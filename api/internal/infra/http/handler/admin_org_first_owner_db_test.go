package handler

// POST /api/v1/admin/tenants/{tenantId}/users is bootstrap only (owner
// decision 2026-10-02): the platform administrator creates the first owner of
// an organization that has none, and nothing else. Exercised through the real
// handler, provisioning service and repositories.
//
// Needs DATABASE_URL (CI's Test job provides one); skipped otherwise.

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/app"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

type firstOwnerTestMailer struct{ deliverable bool }

func (m firstOwnerTestMailer) CanDeliverTo(context.Context, string) bool { return m.deliverable }
func (m firstOwnerTestMailer) SendAccountSetupEmail(context.Context, string, string, string, string, string, time.Duration) error {
	return nil
}

func TestAdminCreateOrgUser_FirstOwnerOnly_DB(t *testing.T) {
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping DB-backed test")
	}
	raw, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer raw.Close()
	if err := raw.Ping(); err != nil {
		t.Skipf("cannot reach test DB: %v", err)
	}
	pg := &postgres.DB{DB: raw}
	log := logger.NewNop()
	tenantRepo := postgres.NewTenantRepository(pg)
	userRepo := postgres.NewUserRepository(pg)
	tenants := app.NewTenantService(tenantRepo, log)

	newHandler := func(smtp bool) *AdminOrganizationHandler {
		prov := app.NewUserProvisioningService(tenantRepo, userRepo, nil, firstOwnerTestMailer{deliverable: smtp}, nil, log)
		return NewAdminOrganizationHandler(postgres.NewAdminOrganizationRepository(pg), tenants, userRepo, validator.New(), log).
			WithUserProvisioning(prov)
	}
	org := func() string {
		id := uuid.NewString()
		if _, err := raw.Exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'Admin first owner IT', $2)`,
			id, "adm-fo-"+strings.ReplaceAll(id[:13], "-", "")); err != nil {
			t.Fatalf("seed org: %v", err)
		}
		t.Cleanup(func() {
			_, _ = raw.Exec(`DELETE FROM users WHERE id IN (SELECT user_id FROM tenant_members WHERE tenant_id = $1)`, id)
			for _, q := range []string{`DELETE FROM audit_log_chain WHERE tenant_id = $1`, `DELETE FROM audit_logs WHERE tenant_id = $1`,
				`DELETE FROM user_roles WHERE tenant_id = $1`, `DELETE FROM tenant_members WHERE tenant_id = $1`, `DELETE FROM tenants WHERE id = $1`} {
				_, _ = raw.Exec(q, id)
			}
		})
		return id
	}
	call := func(h *AdminOrganizationHandler, orgID, body string) (int, map[string]any) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/tenants/"+orgID+"/users", strings.NewReader(body))
		req.SetPathValue(middleware.AdminTenantParam, orgID)
		rec := httptest.NewRecorder()
		h.CreateUser(rec, req)
		out := map[string]any{}
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}
	email := func() string {
		addr := "adm-fo-" + uuid.NewString()[:8] + "@it.test"
		t.Cleanup(func() { _, _ = raw.Exec(`DELETE FROM users WHERE email = $1`, addr) })
		return addr
	}

	t.Run("a role other than owner is refused", func(t *testing.T) {
		for _, r := range []string{"admin", "member", "viewer"} {
			code, _ := call(newHandler(false), org(), `{"email":"`+email()+`","role":"`+r+`"}`)
			if code != http.StatusBadRequest {
				t.Errorf("role %s: status %d, want 400", r, code)
			}
		}
	})

	t.Run("no owner yet, no SMTP: 201 with the link once", func(t *testing.T) {
		code, body := call(newHandler(false), org(), `{"email":"`+email()+`","name":"Owner"}`)
		if code != http.StatusCreated {
			t.Fatalf("status %d (%v)", code, body)
		}
		if body["role"] != "owner" || body["setup_token"] == nil || body["setup_token"] == "" {
			t.Fatalf("body %v, want role owner and a setup_token", body)
		}
	})

	t.Run("SMTP configured: emailed, token never in the response", func(t *testing.T) {
		code, body := call(newHandler(true), org(), `{"email":"`+email()+`","role":"owner"}`)
		if code != http.StatusCreated {
			t.Fatalf("status %d (%v)", code, body)
		}
		if _, has := body["setup_token"]; has || body["email_sent"] != true {
			t.Fatalf("body %v, want email_sent and no setup_token", body)
		}
	})

	t.Run("organization with an owner: 409", func(t *testing.T) {
		id := org()
		h := newHandler(false)
		if code, body := call(h, id, `{"email":"`+email()+`"}`); code != http.StatusCreated {
			t.Fatalf("first owner: %d %v", code, body)
		}
		code, body := call(h, id, `{"email":"`+email()+`"}`)
		if code != http.StatusConflict {
			t.Fatalf("second user: status %d (%v), want 409", code, body)
		}
		if msg, _ := body["message"].(string); !strings.Contains(msg, "already has an owner") {
			t.Fatalf("message %q does not explain the refusal", msg)
		}
	})
}
