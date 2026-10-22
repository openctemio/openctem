package routes

// The outbound ticket gate and the link permission over the real route
// registration, middleware chain (permission gate + DataScopeGuard), handler,
// service and a migrated database:
//   - create-ticket on a finding outside the caller's data scope is 404 and
//     nothing reaches the tracker; another tenant's finding is 404 too;
//   - a pentest finding on the generic create-ticket route is 403
//     TICKET_EGRESS_REFUSED, and nothing reaches the tracker;
//   - linking an existing issue needs findings:fix_apply in addition to
//     findings:write (403 without it).

import (
	"context"
	"database/sql"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/app/datascope"
	"github.com/openctemio/openctem/api/internal/app/jira"
	infrahttp "github.com/openctemio/openctem/api/internal/infra/http"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

// egressTracker counts the issues the tracker was asked to create.
type egressTracker struct{ creates int32 }

func (c *egressTracker) CreateIssue(_ context.Context, in jira.CreateIssueInput) (*jira.CreateIssueResult, error) {
	atomic.AddInt32(&c.creates, 1)
	return &jira.CreateIssueResult{Key: in.ProjectKey + "-1", BrowseURL: "https://acme.atlassian.net/browse/" + in.ProjectKey + "-1"}, nil
}
func (c *egressTracker) GetIssueStatus(context.Context, string) (string, error)           { return "", nil }
func (c *egressTracker) TransitionToStatus(context.Context, string, string, string) error { return nil }
func (c *egressTracker) AddComment(context.Context, string, string) error                 { return nil }
func (c *egressTracker) ListProjects(context.Context) ([]jira.ProjectRef, error)          { return nil, nil }
func (c *egressTracker) TestConnection(context.Context) error                             { return nil }

type egressHarness struct {
	t       *testing.T
	db      *sql.DB
	srv     *httptest.Server
	tracker *egressTracker

	tenantA, tenantB      shared.ID
	member                shared.ID
	assetA1, assetA2      shared.ID
	assetB                shared.ID
	inScope, outOfScope   shared.ID
	pentestFinding, other shared.ID
}

func newEgressHarness(t *testing.T) *egressHarness {
	t.Helper()
	url := testdb.URL()
	if url == "" {
		t.Skip("DATABASE_URL not set to a test database; skipping ticket egress DB test")
	}
	db, err := sql.Open("postgres", url)
	if err != nil {
		t.Skipf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Ping(); err != nil {
		t.Skipf("cannot reach test DB: %v", err)
	}
	h := &egressHarness{t: t, db: db, tracker: &egressTracker{}}
	h.seed()

	pg := &postgres.DB{DB: db}
	log := logger.NewNop()
	enforcer := datascope.New(postgres.NewDataScopeRepository(pg),
		func(ctx context.Context) datascope.Caller {
			return datascope.Caller{UserID: middleware.GetUserID(ctx), IsAdmin: middleware.IsAdmin(ctx)}
		}, log)
	prevGuard := dataScopeGuardMiddleware
	dataScopeGuardMiddleware = middleware.DataScopeGuard(enforcer)
	t.Cleanup(func() { dataScopeGuardMiddleware = prevGuard })

	svc := jira.NewSyncService(postgres.NewFindingRepository(pg), h.tracker, log)
	jh := handler.NewJiraWebhookHandler(svc, validator.New(), log)
	router := infrahttp.NewChiRouter()
	registerVulnerabilityRoutes(router, nil, nil, jh, nil, Middleware(h.auth), nil)
	h.srv = httptest.NewServer(router.(interface{ Handler() http.Handler }).Handler())
	t.Cleanup(h.srv.Close)
	return h
}

// auth stands in for UnifiedAuth: the caller is always in tenant A.
func (h *egressHarness) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		ctx = context.WithValue(ctx, middleware.UserIDKey, r.Header.Get("X-Test-User"))
		ctx = context.WithValue(ctx, middleware.TenantIDKey, h.tenantA.String())
		ctx = context.WithValue(ctx, middleware.IsAdminKey, false)
		ctx = context.WithValue(ctx, middleware.PermissionsKey, strings.Split(r.Header.Get("X-Test-Perms"), ","))
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (h *egressHarness) exec(q string, args ...any) {
	h.t.Helper()
	if _, err := h.db.ExecContext(context.Background(), q, args...); err != nil {
		h.t.Fatalf("seed %q: %v", q, err)
	}
}

func (h *egressHarness) seed() {
	h.tenantA, h.tenantB = shared.NewID(), shared.NewID()
	h.member = shared.NewID()
	h.assetA1, h.assetA2, h.assetB = shared.NewID(), shared.NewID(), shared.NewID()
	h.inScope, h.outOfScope, h.pentestFinding, h.other = shared.NewID(), shared.NewID(), shared.NewID(), shared.NewID()

	for _, tid := range []shared.ID{h.tenantA, h.tenantB} {
		h.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, tid.String(), "te-"+tid.String())
	}
	h.t.Cleanup(func() {
		ctx := context.Background()
		for _, tid := range []shared.ID{h.tenantA, h.tenantB} {
			_, _ = h.db.ExecContext(ctx, `DELETE FROM tenants WHERE id = $1`, tid.String())
		}
		_, _ = h.db.ExecContext(ctx, `DELETE FROM users WHERE id = $1`, h.member.String())
	})
	h.exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, 'member')`, h.member.String(), h.member.String()+"@te.test")
	h.exec(`INSERT INTO tenant_members (user_id, tenant_id, role) VALUES ($1, $2, 'member')`, h.member.String(), h.tenantA.String())
	assets := []struct {
		id, tenant shared.ID
		name       string
	}{{h.assetA1, h.tenantA, "a1.example.com"}, {h.assetA2, h.tenantA, "a2.example.com"}, {h.assetB, h.tenantB, "b.example.com"}}
	for _, a := range assets {
		h.exec(`INSERT INTO assets (id, tenant_id, name, asset_type, status) VALUES ($1, $2, $3, 'domain', 'active')`,
			a.id.String(), a.tenant.String(), a.name)
	}
	findings := []struct {
		id, tenant, asset shared.ID
		source            string
	}{
		{h.inScope, h.tenantA, h.assetA1, "dast"},
		{h.outOfScope, h.tenantA, h.assetA2, "dast"},
		{h.pentestFinding, h.tenantA, h.assetA1, "pentest"},
		{h.other, h.tenantB, h.assetB, "dast"},
	}
	for _, f := range findings {
		h.exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, rule_id, message, severity, fingerprint, status)
			VALUES ($1::uuid, $2, $3, $4, 'nuclei', 'exposed-panel', 'hit', 'high', $1::text, 'confirmed')`,
			f.id.String(), f.tenant.String(), f.asset.String(), f.source)
	}
	// The member is on the pentest finding's campaign, so the campaign gate
	// admits them and the egress rule itself is what refuses the ticket.
	campaign := shared.NewID()
	h.exec(`INSERT INTO pentest_campaigns (id, tenant_id, name) VALUES ($1, $2, 'engagement')`, campaign.String(), h.tenantA.String())
	h.exec(`INSERT INTO pentest_campaign_members (tenant_id, campaign_id, user_id, role) VALUES ($1, $2, $3, 'lead')`,
		h.tenantA.String(), campaign.String(), h.member.String())
	h.exec(`UPDATE findings SET pentest_campaign_id = $1 WHERE id = $2`, campaign.String(), h.pentestFinding.String())
	// The member's data scope is asset A1 only.
	h.exec(`INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type) VALUES ($1, $2, $3, 'secondary')`,
		h.member.String(), h.tenantA.String(), h.assetA1.String())
}

func (h *egressHarness) post(perms []permission.Permission, path, body string) (int, string) {
	h.t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, h.srv.URL+path, strings.NewReader(body))
	if err != nil {
		h.t.Fatal(err)
	}
	names := make([]string, 0, len(perms))
	for _, p := range perms {
		names = append(names, p.String())
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Test-User", h.member.String())
	req.Header.Set("X-Test-Perms", strings.Join(names, ","))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

var teWritePerms = []permission.Permission{permission.FindingsRead, permission.FindingsWrite} //nolint:gochecknoglobals // fixture

func TestTicketEgress_CreateTicketScopeAndTenant(t *testing.T) {
	h := newEgressHarness(t)
	for name, id := range map[string]shared.ID{"out of scope": h.outOfScope, "other tenant": h.other} {
		status, body := h.post(teWritePerms, "/api/v1/findings/"+id.String()+"/create-ticket", `{"project_key":"SEC"}`)
		if status != http.StatusNotFound {
			t.Fatalf("%s: create-ticket = %d, want 404 (%s)", name, status, body)
		}
		if strings.Contains(body, "b.example.com") || strings.Contains(body, "a2.example.com") {
			t.Fatalf("%s: response leaks the finding: %s", name, body)
		}
	}
	if n := atomic.LoadInt32(&h.tracker.creates); n != 0 {
		t.Fatalf("tracker asked to create %d issues for refused findings", n)
	}
	// The in-scope finding is ticketed (the route works end to end).
	if status, body := h.post(teWritePerms, "/api/v1/findings/"+h.inScope.String()+"/create-ticket", `{"project_key":"SEC"}`); status != http.StatusCreated {
		t.Fatalf("in-scope create-ticket = %d (%s)", status, body)
	}
	if n := atomic.LoadInt32(&h.tracker.creates); n != 1 {
		t.Fatalf("tracker creates = %d, want 1", n)
	}
}

func TestTicketEgress_PentestRefusedOnGenericRoute(t *testing.T) {
	h := newEgressHarness(t)
	status, body := h.post(teWritePerms, "/api/v1/findings/"+h.pentestFinding.String()+"/create-ticket", `{"project_key":"SEC"}`)
	if status != http.StatusForbidden || !strings.Contains(body, "TICKET_EGRESS_REFUSED") || !strings.Contains(body, "pentest_campaign_route_only") {
		t.Fatalf("pentest create-ticket = %d (%s), want 403 TICKET_EGRESS_REFUSED", status, body)
	}
	// GitHub is refused the same way (the gate runs before any provider).
	if n := atomic.LoadInt32(&h.tracker.creates); n != 0 {
		t.Fatalf("tracker asked to create %d issues for a pentest finding", n)
	}
	var uris sql.NullString
	if err := h.db.QueryRow(`SELECT array_to_string(work_item_uris, ',') FROM findings WHERE id = $1`, h.pentestFinding.String()).Scan(&uris); err != nil {
		t.Fatal(err)
	}
	if uris.String != "" {
		t.Fatalf("refused finding got a work item link: %q", uris.String)
	}
}

func TestTicketEgress_LinkNeedsFixApply(t *testing.T) {
	h := newEgressHarness(t)
	path := "/api/v1/findings/" + h.inScope.String() + "/ticket-links"
	status, body := h.post(teWritePerms, path, `{"issue":"SEC-7"}`)
	if status != http.StatusForbidden || !strings.Contains(body, "findings:fix_apply") {
		t.Fatalf("link without findings:fix_apply = %d (%s), want 403 naming the permission", status, body)
	}
	withFix := append([]permission.Permission{permission.FindingsFixApply}, teWritePerms...)
	if status, body := h.post(withFix, path, `{"issue":"SEC-7"}`); status == http.StatusForbidden {
		t.Fatalf("link with findings:fix_apply refused by the gate: %s", body)
	}
	// Another tenant's finding stays 404 with every permission.
	if status, body := h.post(withFix, "/api/v1/findings/"+h.other.String()+"/ticket-links", `{"issue":"SEC-7"}`); status != http.StatusNotFound {
		t.Fatalf("link on another tenant's finding = %d (%s), want 404", status, body)
	}
}
