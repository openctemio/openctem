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
	findingsvc "github.com/openctemio/openctem/api/internal/app/finding"
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
	finding, legacy := shared.NewID().String(), shared.NewID().String()
	for _, f := range []string{finding, legacy} {
		exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, severity, message, fingerprint)
		      VALUES ($1, $2, $3, 'manual', 'fam', 'high', 'fam', $4)`, f, tenantA, asset, "fam-"+f)
	}
	// An assignment written before the check, to a user of another tenant.
	exec(`UPDATE findings SET assigned_to = $1 WHERE id = $2`, outsider, legacy)

	db := &postgres.DB{DB: raw}
	svc := findingsvc.NewVulnerabilityService(nil, postgres.NewFindingRepository(db), logger.NewNop())
	svc.SetDataScope(datascope.New(postgres.NewDataScopeRepository(db), nil, logger.NewNop()))
	userRepo := postgres.NewUserRepository(db)
	svc.SetUserRepository(userRepo)
	svc.SetActivityService(activity.NewFindingActivityService(postgres.NewFindingActivityRepository(db), postgres.NewFindingRepository(db), logger.NewNop()))
	svc.SetAssigneeChecker(postgres.NewAccessControlRepository(db))
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
}
