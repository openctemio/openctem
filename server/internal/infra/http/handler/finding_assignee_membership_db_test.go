package handler

// Finding assignment against real Postgres (research doc 21b C2, research
// doc 15 L-15): the assignee must be an active member of the finding's
// tenant. Before the check, assigning a finding to any platform user's id
// wrote that user's name and email into the tenant's activity log, and
// GET /findings/{id} returned them through the global profile lookup.

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/app/activity"
	"github.com/openctemio/openctem/api/internal/app/datascope"
	findingapp "github.com/openctemio/openctem/api/internal/app/finding"
	"github.com/openctemio/openctem/api/internal/app/tenant"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

func TestFindingAssign_AssigneeMustBeActiveMember_DB(t *testing.T) {
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
	admin, member, suspended, deactivated, outsider := shared.NewID().String(), shared.NewID().String(),
		shared.NewID().String(), shared.NewID().String(), shared.NewID().String()
	users := []string{admin, member, suspended, deactivated, outsider}
	for _, tn := range []string{tenantA, tenantB} {
		exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'fam', $2)`, tn, "fam-"+tn)
	}
	t.Cleanup(func() {
		bg := context.Background()
		for _, tn := range []string{tenantA, tenantB} {
			_, _ = raw.ExecContext(bg, `DELETE FROM findings WHERE tenant_id = $1`, tn)
			_, _ = raw.ExecContext(bg, `DELETE FROM tenants WHERE id = $1`, tn)
		}
		for _, u := range users {
			_, _ = raw.ExecContext(bg, `DELETE FROM users WHERE id = $1`, u)
		}
	})
	for _, u := range users {
		exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, $3)`, u, "secret-"+u+"@fam.test", "Secret Name "+u)
	}
	exec(`UPDATE users SET status = 'inactive' WHERE id = $1`, deactivated)
	for _, u := range []string{admin, member, suspended, deactivated} {
		exec(`INSERT INTO tenant_members (user_id, tenant_id, role) VALUES ($1, $2, 'member')`, u, tenantA)
	}
	exec(`UPDATE tenant_members SET status = 'suspended', suspended_at = now() WHERE user_id = $1 AND tenant_id = $2`, suspended, tenantA)
	exec(`INSERT INTO tenant_members (user_id, tenant_id, role) VALUES ($1, $2, 'member')`, outsider, tenantB)

	asset := shared.NewID().String()
	exec(`INSERT INTO assets (id, tenant_id, name, asset_type, exposure, criticality) VALUES ($1, $2, 'fam.example.com', 'domain', 'public', 'high')`, asset, tenantA)
	// The member can read the asset (an assignee must be able to read the finding).
	exec(`INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type) VALUES ($1, $2, $3, 'secondary')`, member, tenantA, asset)
	finding, legacy := shared.NewID().String(), shared.NewID().String()
	for _, f := range []string{finding, legacy} {
		exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, severity, message, fingerprint)
		      VALUES ($1, $2, $3, 'manual', 'fam', 'high', 'fam', $4)`, f, tenantA, asset, "fam-"+f)
	}
	// An assignment written before the check, to a user of another tenant.
	exec(`UPDATE findings SET assigned_to = $1 WHERE id = $2`, outsider, legacy)

	db := &postgres.DB{DB: raw}
	svc := findingapp.NewVulnerabilityService(nil, postgres.NewFindingRepository(db), logger.NewNop())
	svc.SetDataScope(datascope.New(postgres.NewDataScopeRepository(db), nil, logger.NewNop()))
	userRepo := postgres.NewUserRepository(db)
	svc.SetUserRepository(userRepo)
	svc.SetActivityService(activity.NewFindingActivityService(postgres.NewFindingActivityRepository(db), postgres.NewFindingRepository(db), logger.NewNop()))
	svc.SetAssigneeChecker(postgres.NewAccessControlRepository(db))
	svc.SetAssigneeProfileReader(postgres.NewAccessControlRepository(db))
	h := NewVulnerabilityHandler(svc, validator.New(), logger.NewNop())
	h.SetUserService(tenant.NewUserService(userRepo, logger.NewNop()))

	req := func(method, id, body string) *http.Request {
		r := httptest.NewRequest(method, "/", strings.NewReader(body))
		r.SetPathValue("id", id)
		c := context.WithValue(r.Context(), middleware.TenantIDKey, tenantA)
		c = context.WithValue(c, middleware.UserIDKey, admin)
		c = context.WithValue(c, middleware.IsAdminKey, true)
		return r.WithContext(c)
	}
	assign := func(user string) (int, string) {
		t.Helper()
		w := httptest.NewRecorder()
		h.AssignFinding(w, req(http.MethodPost, finding, `{"user_id":"`+user+`"}`))
		return w.Code, w.Body.String()
	}

	// Refused, all with the same answer: another tenant's user, an unknown
	// id, a suspended member and a deactivated account.
	oStatus, oBody := assign(outsider)
	if oStatus != http.StatusBadRequest {
		t.Errorf("assign to a tenant B user = %d, want 400 (%s)", oStatus, oBody)
	}
	for name, u := range map[string]string{"unknown": shared.NewID().String(), "suspended": suspended, "deactivated": deactivated} {
		if status, body := assign(u); status != oStatus || body != oBody {
			t.Errorf("%s user answered %d %q, outsider %d %q: must be identical", name, status, body, oStatus, oBody)
		}
	}
	for _, leak := range []string{"Secret Name", "secret-"} {
		if strings.Contains(oBody, leak) {
			t.Errorf("refusal body discloses the user: %s", oBody)
		}
	}
	var assigned sql.NullString
	if err := raw.QueryRowContext(ctx, `SELECT assigned_to::text FROM findings WHERE id = $1`, finding).Scan(&assigned); err != nil {
		t.Fatal(err)
	}
	if assigned.Valid {
		t.Fatalf("finding assigned to %s after refusals", assigned.String)
	}
	var leakedRows int
	if err := raw.QueryRowContext(ctx, `SELECT COUNT(*) FROM finding_activities WHERE tenant_id = $1 AND changes::text LIKE '%secret-%'`,
		tenantA).Scan(&leakedRows); err != nil {
		t.Fatal(err)
	}
	if leakedRows != 0 {
		t.Errorf("%d activity row(s) carry a refused user's email", leakedRows)
	}

	// An active member is accepted.
	if status, body := assign(member); status != http.StatusOK {
		t.Fatalf("assign to an active member = %d, want 200 (%s)", status, body)
	}

	// GET shows the member's profile but never a foreign assignee's.
	get := func(id string) string {
		t.Helper()
		w := httptest.NewRecorder()
		h.GetFinding(w, req(http.MethodGet, id, ""))
		if w.Code != http.StatusOK {
			t.Fatalf("get %s = %d (%s)", id, w.Code, w.Body.String())
		}
		return w.Body.String()
	}
	if body := get(finding); !strings.Contains(body, "Secret Name "+member) {
		t.Errorf("GET of a finding assigned to a member lacks their profile: %s", body)
	}
	body := get(legacy)
	if strings.Contains(body, "Secret Name") || strings.Contains(body, "secret-"+outsider) {
		t.Errorf("GET discloses a foreign assignee's profile: %s", body)
	}
	var resp struct {
		AssignedTo     *string         `json:"assigned_to"`
		AssignedToUser json.RawMessage `json:"assigned_to_user"`
	}
	_ = json.Unmarshal([]byte(body), &resp)
	if resp.AssignedToUser != nil {
		t.Errorf("assigned_to_user = %s for a foreign assignee, want absent", resp.AssignedToUser)
	}

	// The findings LIST carries the member's name and email for each row (one
	// batched lookup for the page) but, as the single read does, never a
	// foreign tenant's user, a suspended member or an unknown id.
	exec(`UPDATE findings SET assigned_to = $1 WHERE id = $2`, member, finding)
	suspendedFinding := shared.NewID().String()
	exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, severity, message, fingerprint, assigned_to)
	      VALUES ($1, $2, $3, 'manual', 'fam', 'high', 'fam', $4, $5)`, suspendedFinding, tenantA, asset, "fam-"+suspendedFinding, suspended)
	lr := httptest.NewRequest(http.MethodGet, "/?per_page=50", nil)
	lc := context.WithValue(lr.Context(), middleware.TenantIDKey, tenantA)
	lc = context.WithValue(lc, middleware.UserIDKey, admin)
	lc = context.WithValue(lc, middleware.IsAdminKey, true)
	lw := httptest.NewRecorder()
	h.ListFindings(lw, lr.WithContext(lc))
	if lw.Code != http.StatusOK {
		t.Fatalf("list = %d (%s)", lw.Code, lw.Body.String())
	}
	if strings.Contains(lw.Body.String(), "secret-"+outsider) || strings.Contains(lw.Body.String(), "secret-"+suspended) {
		t.Errorf("list discloses a profile outside the tenant's active members: %s", lw.Body.String())
	}
	var list struct {
		Data []struct {
			ID             string `json:"id"`
			AssignedTo     string `json:"assigned_to"`
			AssignedToUser *struct {
				ID, Name, Email string
			} `json:"assigned_to_user"`
		} `json:"data"`
	}
	if err := json.Unmarshal(lw.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	seen := map[string]bool{}
	for _, row := range list.Data {
		seen[row.ID] = true
		switch row.ID {
		case finding:
			if row.AssignedToUser == nil || row.AssignedToUser.Name != "Secret Name "+member || row.AssignedToUser.ID != member {
				t.Errorf("list row of a member-assigned finding = %+v, want the member's name", row.AssignedToUser)
			}
		case legacy, suspendedFinding:
			if row.AssignedTo == "" || row.AssignedToUser != nil {
				t.Errorf("list row %s: assigned_to=%q user=%+v, want id kept and no profile", row.ID, row.AssignedTo, row.AssignedToUser)
			}
		}
	}
	if !seen[finding] || !seen[legacy] || !seen[suspendedFinding] {
		t.Fatalf("list lacks the seeded findings: %v", seen)
	}
}
