package handler

// B1 against real Postgres: an assignee must be able to read the finding, and
// GET /findings/{id}/assignable lists only such members (research 215).

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/app/datascope"
	findingapp "github.com/openctemio/openctem/api/internal/app/finding"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

func TestFindingAssign_AssigneeMustReadFinding_DB(t *testing.T) {
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping DB-backed handler test")
	}
	raw, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer raw.Close()
	ctx := context.Background()
	if err := raw.PingContext(ctx); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := raw.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("seed %q: %v", q, err)
		}
	}

	tenantA, tenantB := shared.NewID().String(), shared.NewID().String()
	caller, inScope, otherAsset, noScope, tenantBUser := shared.NewID().String(), shared.NewID().String(),
		shared.NewID().String(), shared.NewID().String(), shared.NewID().String()
	users := []string{caller, inScope, otherAsset, noScope, tenantBUser}
	for _, tn := range []string{tenantA, tenantB} {
		exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'asg', $2)`, tn, "asg-"+tn)
	}
	t.Cleanup(func() {
		bg := context.Background()
		for _, tn := range []string{tenantA, tenantB} {
			_, _ = raw.ExecContext(bg, `DELETE FROM user_accessible_assets WHERE tenant_id = $1`, tn)
			_, _ = raw.ExecContext(bg, `DELETE FROM findings WHERE tenant_id = $1`, tn)
			_, _ = raw.ExecContext(bg, `DELETE FROM assets WHERE tenant_id = $1`, tn)
			_, _ = raw.ExecContext(bg, `DELETE FROM tenants WHERE id = $1`, tn)
		}
		for _, u := range users {
			_, _ = raw.ExecContext(bg, `DELETE FROM users WHERE id = $1`, u)
		}
	})
	for i, u := range users {
		exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, $3)`, u, "asg-"+u+"@asg.test", []string{"Cara", "Ines", "Olga", "Nora", "Bob"}[i])
	}
	for _, u := range []string{caller, inScope, otherAsset, noScope} {
		exec(`INSERT INTO tenant_members (user_id, tenant_id, role) VALUES ($1, $2, 'member')`, u, tenantA)
	}
	exec(`INSERT INTO tenant_members (user_id, tenant_id, role) VALUES ($1, $2, 'member')`, tenantBUser, tenantB)

	assetA, assetB := shared.NewID().String(), shared.NewID().String()
	for _, a := range []string{assetA, assetB} {
		exec(`INSERT INTO assets (id, tenant_id, name, asset_type, exposure, criticality) VALUES ($1, $2, $3, 'domain', 'public', 'high')`, a, tenantA, "asg-"+a+".example.com")
	}
	exec(`INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type) VALUES ($1, $2, $3, 'secondary'), ($4, $2, $5, 'secondary'), ($6, $2, $3, 'secondary')`,
		inScope, tenantA, assetA, otherAsset, assetB, caller)
	finding := shared.NewID().String()
	exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, severity, message, fingerprint)
	      VALUES ($1, $2, $3, 'manual', 'asg', 'high', 'asg', $4)`, finding, tenantA, assetA, "asg-"+finding)

	db := &postgres.DB{DB: raw}
	svc := findingapp.NewVulnerabilityService(nil, postgres.NewFindingRepository(db), logger.NewNop())
	svc.SetDataScope(datascope.New(postgres.NewDataScopeRepository(db), nil, logger.NewNop()))
	svc.SetAssigneeChecker(postgres.NewAccessControlRepository(db))
	svc.SetMemberSearcher(postgres.NewTenantRepository(db))
	h := NewVulnerabilityHandler(svc, validator.New(), logger.NewNop())

	req := func(method, tenant, user, id, target, body string) *http.Request {
		r := httptest.NewRequest(method, "/"+target, strings.NewReader(body))
		r.SetPathValue("id", id)
		c := context.WithValue(r.Context(), middleware.TenantIDKey, tenant)
		c = context.WithValue(c, middleware.UserIDKey, user)
		c = context.WithValue(c, middleware.IsAdminKey, true)
		return r.WithContext(c)
	}
	assign := func(user string) (int, string) {
		t.Helper()
		w := httptest.NewRecorder()
		h.AssignFinding(w, req(http.MethodPost, tenantA, caller, finding, "", `{"user_id":"`+user+`"}`))
		return w.Code, w.Body.String()
	}

	// A member whose scope does not cover the asset, one with no scope row,
	// and a user of another tenant are refused; the refusal names no scope.
	st, body := assign(otherAsset)
	if st != http.StatusBadRequest || !strings.Contains(body, "cannot be assigned") {
		t.Errorf("assign to an out-of-scope member = %d %s, want 400", st, body)
	}
	if st2, body2 := assign(noScope); st2 != st || body2 != body {
		t.Errorf("no-scope member answered %d %q, want the same as out-of-scope %d %q", st2, body2, st, body)
	}
	if st3, _ := assign(tenantBUser); st3 != http.StatusBadRequest {
		t.Errorf("assign to a tenant B user = %d, want 400", st3)
	}
	var assigned sql.NullString
	if err := raw.QueryRowContext(ctx, `SELECT assigned_to::text FROM findings WHERE id = $1`, finding).Scan(&assigned); err != nil {
		t.Fatal(err)
	}
	if assigned.Valid {
		t.Fatalf("finding assigned to %s after refusals", assigned.String)
	}
	if st4, b4 := assign(inScope); st4 != http.StatusOK {
		t.Fatalf("assign to an in-scope member = %d (%s)", st4, b4)
	}

	// Bulk: the out-of-scope target is refused per finding, nothing assigned.
	finding2 := shared.NewID().String()
	exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, severity, message, fingerprint)
	      VALUES ($1, $2, $3, 'manual', 'asg', 'high', 'asg', $4)`, finding2, tenantA, assetA, "asg-"+finding2)
	res, err := svc.BulkAssignFindings(ctx, tenantA, findingapp.BulkAssignInput{FindingIDs: []string{finding2}, UserID: otherAsset, AssignerID: caller})
	if err != nil || res.Updated != 0 || res.Failed != 1 {
		t.Errorf("bulk assign to an out-of-scope member = %+v, %v; want 0 updated, 1 failed", res, err)
	}

	// The picker lists in-scope members only, without emails.
	w := httptest.NewRecorder()
	h.ListAssignableMembers(w, req(http.MethodGet, tenantA, caller, finding, "assignable", ""))
	if w.Code != http.StatusOK {
		t.Fatalf("assignable = %d (%s)", w.Code, w.Body.String())
	}
	var out struct {
		Data []struct {
			UserID string `json:"user_id"`
			Name   string `json:"name"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, m := range out.Data {
		got[m.UserID] = true
	}
	if !got[inScope] || !got[caller] || got[otherAsset] || got[noScope] || got[tenantBUser] {
		t.Errorf("assignable = %v, want in-scope members only", got)
	}
	if strings.Contains(w.Body.String(), "@asg.test") {
		t.Errorf("assignable discloses an email: %s", w.Body.String())
	}

	// A search narrows it.
	r := req(http.MethodGet, tenantA, caller, finding, "assignable?q=ine", "")
	w = httptest.NewRecorder()
	h.ListAssignableMembers(w, r)
	if !strings.Contains(w.Body.String(), "Ines") || strings.Contains(w.Body.String(), "Cara") {
		t.Errorf("search q=ine = %s", w.Body.String())
	}

	// Cross-tenant: tenant B's caller gets 404 for tenant A's finding.
	w = httptest.NewRecorder()
	h.ListAssignableMembers(w, req(http.MethodGet, tenantB, tenantBUser, finding, "assignable", ""))
	if w.Code != http.StatusNotFound {
		t.Errorf("assignable of another tenant's finding = %d, want 404", w.Code)
	}
	// A restricted caller who cannot read the finding gets 404.
	w = httptest.NewRecorder()
	rr := req(http.MethodGet, tenantA, otherAsset, finding, "assignable", "")
	rr = rr.WithContext(context.WithValue(rr.Context(), middleware.IsAdminKey, false))
	h.ListAssignableMembers(w, rr)
	if w.Code != http.StatusNotFound {
		t.Errorf("assignable for a caller without scope = %d, want 404", w.Code)
	}
}
