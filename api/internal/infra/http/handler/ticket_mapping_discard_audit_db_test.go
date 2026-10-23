package handler

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	_ "github.com/lib/pq"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	appticketmap "github.com/openctemio/openctem/api/internal/app/ticketmap"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Discarding a ticket mapping draft throws away unpublished configuration, so
// it leaves an audit row naming the actor, like saving the draft does. Another
// tenant's mapping is 404 and leaves nothing; with no draft nothing is audited.
func TestTicketMappingHandler_DiscardDraftIsAudited(t *testing.T) {
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

	tenantA, tenantB := shared.NewID().String(), shared.NewID().String()
	actor := shared.NewID().String()
	intg, profile := shared.NewID().String(), shared.NewID().String()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := raw.Exec(q, args...); err != nil {
			t.Fatalf("seed: %v\n%s", err, q)
		}
	}
	for _, tid := range []string{tenantA, tenantB} {
		exec(`INSERT INTO tenants (id, name, slug) VALUES ($1,'TM Org',$2)`, tid, "tm-"+tid)
	}
	exec(`INSERT INTO users (id, email, name) VALUES ($1,$2,'Admin')`, actor, "admin-"+actor+"@example.com")
	exec(`INSERT INTO integrations (id, tenant_id, name, category, provider, status)
		VALUES ($1,$2,'Jira','ticketing','jira','connected')`, intg, tenantA)
	exec(`INSERT INTO ticket_mapping_profiles (id, tenant_id, integration_id, object_kind, project_key, issue_type_id, name, draft_version)
		VALUES ($1,$2,$3,'finding','SEC','10001','Security bugs',1)`, profile, tenantA, intg)
	exec(`INSERT INTO ticket_mapping_versions (profile_id, tenant_id, version, state, spec)
		VALUES ($1,$2,1,'draft','{}')`, profile, tenantA)
	t.Cleanup(func() {
		ctx := context.Background()
		for _, tid := range []string{tenantA, tenantB} {
			_, _ = raw.ExecContext(ctx, `DELETE FROM audit_log_chain WHERE tenant_id=$1`, tid)
			_, _ = raw.ExecContext(ctx, `DELETE FROM audit_logs WHERE tenant_id=$1`, tid)
			_, _ = raw.ExecContext(ctx, `DELETE FROM tenants WHERE id=$1`, tid)
		}
		_, _ = raw.ExecContext(ctx, `DELETE FROM users WHERE id=$1`, actor)
	})

	svc := appticketmap.NewService(postgres.NewTicketMappingRepository(db), nil, nil, nil, "", logger.NewNop())
	h := NewTicketMappingHandler(svc, auditapp.NewAuditService(postgres.NewAuditRepository(db), logger.NewNop()), logger.NewNop())

	discard := func(tenant string) int {
		r := httptest.NewRequest(http.MethodDelete, "/api/v1/integrations/ticket-mappings/"+profile+"/draft", nil)
		rc := chi.NewRouteContext()
		rc.URLParams.Add("mapping_id", profile)
		ctx := context.WithValue(r.Context(), chi.RouteCtxKey, rc)
		ctx = context.WithValue(ctx, middleware.TenantIDKey, tenant)
		ctx = context.WithValue(ctx, middleware.UserIDKey, actor)
		w := httptest.NewRecorder()
		h.DiscardDraft(w, r.WithContext(ctx))
		return w.Code
	}
	audited := func(tenant string) int {
		var n int
		if err := raw.QueryRow(`SELECT count(*) FROM audit_logs
			WHERE tenant_id=$1 AND action='ticket_mapping.updated' AND resource_id=$2 AND actor_id=$3`,
			tenant, profile, actor).Scan(&n); err != nil {
			t.Fatalf("count audit: %v", err)
		}
		return n
	}

	// Another tenant cannot discard (or learn about) tenant A's draft.
	if code := discard(tenantB); code != http.StatusNotFound {
		t.Fatalf("cross-tenant discard: want 404, got %d", code)
	}
	if n := audited(tenantB); n != 0 {
		t.Fatalf("cross-tenant discard wrote %d audit rows", n)
	}

	if code := discard(tenantA); code != http.StatusNoContent {
		t.Fatalf("discard: want 204, got %d", code)
	}
	if n := audited(tenantA); n != 1 {
		t.Fatalf("discard: want 1 audit row, got %d", n)
	}
	var drafts int
	_ = raw.QueryRow(`SELECT count(*) FROM ticket_mapping_versions WHERE profile_id=$1 AND state='draft'`, profile).Scan(&drafts)
	if drafts != 0 {
		t.Fatalf("draft still stored")
	}

	// Nothing left to discard: no change, no audit row.
	if code := discard(tenantA); code != http.StatusNoContent {
		t.Fatalf("second discard: want 204, got %d", code)
	}
	if n := audited(tenantA); n != 1 {
		t.Fatalf("second discard: want still 1 audit row, got %d", n)
	}
}
