package handler

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	_ "github.com/lib/pq"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/scim"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Creating and revoking a SCIM token (a credential that can create, suspend
// and re-role members) leaves an audit row naming the actor; the plaintext
// token never reaches the audit log.
func TestSCIMTokenHandler_CreateAndRevokeAreAudited(t *testing.T) {
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
	db := &postgres.DB{DB: raw}
	tenantID := shared.NewID().String()
	actor := shared.NewID().String()
	if _, err := raw.Exec(`INSERT INTO tenants (id, name, slug) VALUES ($1,'SCIM Org',$2)`, tenantID, "scim-"+tenantID); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	if _, err := raw.Exec(`INSERT INTO users (id, email, name) VALUES ($1,$2,'Admin')`, actor, "admin-"+actor+"@example.com"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	t.Cleanup(func() {
		ctx := context.Background()
		_, _ = raw.ExecContext(ctx, `DELETE FROM audit_log_chain WHERE tenant_id=$1`, tenantID)
		_, _ = raw.ExecContext(ctx, `DELETE FROM audit_logs WHERE tenant_id=$1`, tenantID)
		_, _ = raw.ExecContext(ctx, `DELETE FROM tenants WHERE id=$1`, tenantID)
		_, _ = raw.ExecContext(ctx, `DELETE FROM users WHERE id=$1`, actor)
	})

	h := NewSCIMTokenHandler(scim.NewTokenService(postgres.NewScimTokenRepository(db), "test-pepper", logger.NewNop()), logger.NewNop())
	h.SetAuditService(auditapp.NewAuditService(postgres.NewAuditRepository(db), logger.NewNop()))

	withAuth := func(r *http.Request) *http.Request {
		ctx := context.WithValue(r.Context(), middleware.TenantIDKey, tenantID)
		ctx = context.WithValue(ctx, middleware.UserIDKey, actor)
		return r.WithContext(ctx)
	}

	w := httptest.NewRecorder()
	h.Create(w, withAuth(httptest.NewRequest(http.MethodPost, "/api/v1/scim-tokens", strings.NewReader(`{"name":"okta"}`))))
	if w.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	var created struct {
		ID    string `json:"id"`
		Token string `json:"token"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &created)

	var severity, rowText string
	if err := raw.QueryRow(`SELECT severity, row_to_json(a)::text FROM audit_logs a
		WHERE tenant_id=$1 AND action='scim_token.created' AND resource_id=$2 AND actor_id=$3`,
		tenantID, created.ID, actor).Scan(&severity, &rowText); err != nil {
		t.Fatalf("no scim_token.created row: %v", err)
	}
	if severity != "high" {
		t.Fatalf("scim_token.created severity = %s, want high", severity)
	}
	if strings.Contains(rowText, created.Token) {
		t.Fatalf("audit row contains the plaintext token")
	}

	w = httptest.NewRecorder()
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", created.ID)
	req := withAuth(httptest.NewRequest(http.MethodDelete, "/api/v1/scim-tokens/"+created.ID, nil))
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	h.Revoke(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("revoke: %d %s", w.Code, w.Body.String())
	}
	var n int
	if err := raw.QueryRow(`SELECT count(*) FROM audit_logs WHERE tenant_id=$1 AND action='scim_token.revoked' AND resource_id=$2 AND actor_id=$3`,
		tenantID, created.ID, actor).Scan(&n); err != nil || n != 1 {
		t.Fatalf("scim_token.revoked rows = %d (err %v), want 1", n, err)
	}
}
