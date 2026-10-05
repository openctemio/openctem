package integration

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/integration"
	"github.com/openctemio/openctem/api/internal/app/template"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/secretstore"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

// A member held scans:sources:write and scans:secret_store:write, so they
// could create an HTTP template source pointing at their own server with the
// owner's stored credential, then sync it: the server decrypted the secret and
// sent it there. Against the real repositories, the secret store and the
// audit log: binding someone else's credential is refused for a member, an
// admin (or the credential's creator) can bind it, re-pointing a credentialed
// source drops the credential, and every binding change is audited.
func TestTemplateSourceCredentialBinding(t *testing.T) {
	dsn := testdb.URL()
	if dsn == "" {
		t.Skip("DATABASE_URL not set; skipping template source credential binding DB test")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Skipf("database not available: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()

	tenantID := uuid.NewString()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'Cred binding IT', $2)`,
		tenantID, "cred-binding-"+strings.ReplaceAll(tenantID[:13], "-", ""))
	newUser := func(role string) string {
		id := uuid.NewString()
		exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, 'Cred binding IT')`, id, "cb-"+id[:8]+"@it.test")
		exec(`INSERT INTO tenant_members (user_id, tenant_id, role) VALUES ($1, $2, $3)`, id, tenantID, role)
		return id
	}
	owner, member := newUser("owner"), newUser("member")
	t.Cleanup(func() {
		_, _ = db.ExecContext(ctx, `DELETE FROM template_sources WHERE tenant_id = $1`, tenantID)
		_, _ = db.ExecContext(ctx, `DELETE FROM credentials WHERE tenant_id = $1`, tenantID)
		_, _ = db.ExecContext(ctx, `DELETE FROM audit_logs WHERE tenant_id = $1`, tenantID)
		_, _ = db.ExecContext(ctx, `DELETE FROM user_roles WHERE tenant_id = $1`, tenantID)
		_, _ = db.ExecContext(ctx, `DELETE FROM tenant_members WHERE tenant_id = $1`, tenantID)
		_, _ = db.ExecContext(ctx, `DELETE FROM users WHERE id = ANY($1)`, "{"+owner+","+member+"}")
		_, _ = db.ExecContext(ctx, `DELETE FROM tenants WHERE id = $1`, tenantID)
	})

	pg := &postgres.DB{DB: db}
	log := logger.NewNop()
	auditSvc := audit.NewAuditService(postgres.NewAuditRepository(pg), log)
	secrets, err := integration.NewSecretStoreService(postgres.NewSecretStoreRepository(pg), make([]byte, 32), auditSvc, log)
	if err != nil {
		t.Fatal(err)
	}
	sources := template.NewSourceService(postgres.NewTemplateSourceRepository(pg), log)
	sources.SetCredentialGuard(secrets, auditSvc)
	h := handler.NewTemplateSourceHandler(sources, validator.New(), log)

	tid := shared.MustIDFromString(tenantID)
	storeCred := func(creator, name string) string {
		t.Helper()
		c, err := secrets.CreateCredential(ctx, integration.CreateCredentialInput{
			TenantID: tid, UserID: shared.MustIDFromString(creator), Name: name,
			CredentialType: secretstore.CredentialTypeBearerToken,
			Data:           &secretstore.BearerTokenData{Token: "s3cr3t-" + name},
		})
		if err != nil {
			t.Fatalf("store credential: %v", err)
		}
		return c.ID.String()
	}
	ownerCred := storeCred(owner, "owner-token")
	memberCred := storeCred(member, "member-token")

	router := chi.NewRouter()
	router.Post("/template-sources", h.Create)
	router.Put("/template-sources/{id}", h.Update)
	call := func(method, path, userID string, isAdmin bool, body any) (int, map[string]any) {
		t.Helper()
		raw, _ := json.Marshal(body)
		req := httptest.NewRequest(method, path, bytes.NewReader(raw))
		rctx := context.WithValue(req.Context(), middleware.TenantIDKey, tenantID)
		rctx = context.WithValue(rctx, middleware.UserIDKey, userID)
		rctx = context.WithValue(rctx, middleware.IsAdminKey, isAdmin)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req.WithContext(rctx))
		out := map[string]any{}
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}
	httpSource := func(name, url, credID string) map[string]any {
		return map[string]any{
			"name": name, "source_type": "http", "template_type": "nuclei", "enabled": true,
			"http_config":   map[string]any{"url": url, "auth_type": "bearer"},
			"credential_id": credID,
		}
	}
	storedCred := func(sourceID string) string {
		t.Helper()
		var cred sql.NullString
		if err := db.QueryRowContext(ctx, `SELECT credential_id FROM template_sources WHERE id = $1`, sourceID).Scan(&cred); err != nil {
			t.Fatalf("read source: %v", err)
		}
		return cred.String
	}
	auditCount := func(action, result, sourceID string) int {
		t.Helper()
		var n int
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_logs
			WHERE tenant_id = $1 AND action = $2 AND result = $3 AND resource_id = $4`,
			tenantID, action, result, sourceID).Scan(&n); err != nil {
			t.Fatalf("count audit: %v", err)
		}
		return n
	}
	countSources := func() int {
		var n int
		_ = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM template_sources WHERE tenant_id = $1`, tenantID).Scan(&n)
		return n
	}

	t.Run("member cannot point the owner's credential at their own URL", func(t *testing.T) {
		before := countSources()
		code, body := call(http.MethodPost, "/template-sources", member, false,
			httpSource("exfil", "https://93.184.216.34/t.zip", ownerCred))
		if code != http.StatusForbidden {
			t.Fatalf("member create with owner's credential: got %d %v, want 403", code, body)
		}
		if countSources() != before {
			t.Fatal("a source was stored despite the refusal")
		}
		var denied int
		_ = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_logs WHERE tenant_id = $1
			AND action = 'template_source.credential_attached' AND result = 'denied' AND actor_id = $2`,
			tenantID, member).Scan(&denied)
		if denied != 1 {
			t.Fatalf("denied attempt audit rows = %d, want 1", denied)
		}
	})

	t.Run("member cannot attach the owner's credential to an existing source", func(t *testing.T) {
		code, body := call(http.MethodPost, "/template-sources", member, false,
			httpSource("member-plain", "https://93.184.216.34/plain.zip", ""))
		if code != http.StatusCreated {
			t.Fatalf("member create without credential: %d %v", code, body)
		}
		id := body["id"].(string)
		code, body = call(http.MethodPut, "/template-sources/"+id, member, false,
			map[string]any{"credential_id": ownerCred})
		if code != http.StatusForbidden {
			t.Fatalf("member attach owner's credential: got %d %v, want 403", code, body)
		}
		if got := storedCred(id); got != "" {
			t.Fatalf("credential stored on the source: %q", got)
		}
	})

	t.Run("member can bind a credential they stored themselves", func(t *testing.T) {
		code, body := call(http.MethodPost, "/template-sources", member, false,
			httpSource("member-own", "https://93.184.216.34/own.zip", memberCred))
		if code != http.StatusCreated {
			t.Fatalf("member create with own credential: %d %v", code, body)
		}
		if got := storedCred(body["id"].(string)); got != memberCred {
			t.Fatalf("credential = %q, want %q", got, memberCred)
		}
	})

	var adminSource string
	t.Run("admin binds the owner's credential; it is audited", func(t *testing.T) {
		code, body := call(http.MethodPost, "/template-sources", owner, true,
			httpSource("vendor-feed", "https://93.184.216.34/vendor.zip", ownerCred))
		if code != http.StatusCreated {
			t.Fatalf("admin create: %d %v", code, body)
		}
		adminSource = body["id"].(string)
		if got := storedCred(adminSource); got != ownerCred {
			t.Fatalf("credential = %q, want %q", got, ownerCred)
		}
		if n := auditCount("template_source.credential_attached", "success", adminSource); n != 1 {
			t.Fatalf("attach audit rows = %d, want 1", n)
		}
	})

	t.Run("member edit that keeps the destination keeps the credential", func(t *testing.T) {
		code, body := call(http.MethodPut, "/template-sources/"+adminSource, member, false,
			map[string]any{"description": "renamed by member", "credential_id": ownerCred})
		if code != http.StatusOK {
			t.Fatalf("member benign edit: %d %v", code, body)
		}
		if got := storedCred(adminSource); got != ownerCred {
			t.Fatalf("credential = %q, want it kept", got)
		}
	})

	t.Run("member cannot re-point the credentialed source while keeping the credential", func(t *testing.T) {
		code, body := call(http.MethodPut, "/template-sources/"+adminSource, member, false, map[string]any{
			"http_config":   map[string]any{"url": "https://198.51.100.7/steal", "auth_type": "bearer"},
			"credential_id": ownerCred,
		})
		if code != http.StatusForbidden {
			t.Fatalf("member re-point with credential: got %d %v, want 403", code, body)
		}
		if storedCred(adminSource) != ownerCred {
			t.Fatal("credential changed on a refused update")
		}
	})

	t.Run("re-pointing without re-binding drops the credential", func(t *testing.T) {
		code, body := call(http.MethodPut, "/template-sources/"+adminSource, member, false, map[string]any{
			"http_config": map[string]any{"url": "https://198.51.100.7/steal", "auth_type": "bearer"},
		})
		if code != http.StatusOK {
			t.Fatalf("member re-point: %d %v", code, body)
		}
		if got := storedCred(adminSource); got != "" {
			t.Fatalf("credential = %q after the URL changed, want it dropped", got)
		}
		if _, ok := body["credential_id"]; ok {
			t.Fatalf("response still carries a credential: %v", body)
		}
		if n := auditCount("template_source.credential_detached", "success", adminSource); n != 1 {
			t.Fatalf("detach audit rows = %d, want 1", n)
		}
	})

	t.Run("admin re-binds after re-pointing; audited as attach", func(t *testing.T) {
		code, body := call(http.MethodPut, "/template-sources/"+adminSource, owner, true, map[string]any{
			"http_config":   map[string]any{"url": "https://93.184.216.34/vendor-v2.zip", "auth_type": "bearer"},
			"credential_id": ownerCred,
		})
		if code != http.StatusOK {
			t.Fatalf("admin re-point + bind: %d %v", code, body)
		}
		if got := storedCred(adminSource); got != ownerCred {
			t.Fatalf("credential = %q, want %q", got, ownerCred)
		}
		if n := auditCount("template_source.credential_attached", "success", adminSource); n != 2 {
			t.Fatalf("attach audit rows = %d, want 2", n)
		}
	})

	t.Run("binding a credential that does not exist is a validation error", func(t *testing.T) {
		code, body := call(http.MethodPost, "/template-sources", owner, true,
			httpSource("ghost", "https://93.184.216.34/ghost.zip", uuid.NewString()))
		if code != http.StatusBadRequest {
			t.Fatalf("unknown credential: got %d %v, want 400", code, body)
		}
	})
}
