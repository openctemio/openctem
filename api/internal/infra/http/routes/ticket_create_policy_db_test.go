package routes

// The ticket create policy over the real routes, middleware chain, handler,
// gate, repository and a migrated database:
//   - the policy routes need integrations:manage, and another tenant's
//     integration is 404 (nothing stored for it);
//   - the preview counts only the caller's tenant;
//   - a manual create below the policy is 409 TICKET_BELOW_THRESHOLD until
//     confirmed, and nothing reaches the tracker before that;
//   - a finding's holds follow its data scope (404 out of scope / tenant);
//   - the SQL predicate of the preview agrees with the Go evaluation, the
//     daily cap reserves atomically, and due holds are re-listed after the
//     finding changes.

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

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
	"github.com/openctemio/openctem/api/pkg/domain/ticketpolicy"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

// policyTracker is tenant A's Jira integration; it counts creates.
type policyTracker struct {
	egressTracker
	intg shared.ID
}

func (c *policyTracker) IntegrationID() shared.ID { return c.intg }
func (c *policyTracker) SiteURL() string          { return "https://acme.atlassian.net" }
func (c *policyTracker) IssueIdentity(context.Context, string) (string, string, error) {
	return "", "", jira.ErrIssueNotVisible
}

type policyHarness struct {
	egressHarness
	pt         *policyTracker
	repo       *postgres.TicketCreatePolicyRepository
	intA, intB shared.ID
}

func newPolicyHarness(t *testing.T) *policyHarness {
	t.Helper()
	url := testdb.URL()
	if url == "" {
		t.Skip("DATABASE_URL not set to a test database; skipping ticket create policy DB test")
	}
	db, err := sql.Open("postgres", url)
	if err != nil {
		t.Skipf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Ping(); err != nil {
		t.Skipf("cannot reach test DB: %v", err)
	}
	h := &policyHarness{egressHarness: egressHarness{t: t, db: db, tracker: &egressTracker{}}}
	h.seed()
	// The in-scope finding is low and P3: below the default policy.
	h.exec(`UPDATE findings SET severity = 'low', priority_class = 'P3' WHERE id = $1`, h.inScope.String())
	h.intA, h.intB = shared.NewID(), shared.NewID()
	for _, in := range []struct{ id, tenant shared.ID }{{h.intA, h.tenantA}, {h.intB, h.tenantB}} {
		h.exec(`INSERT INTO integrations (id, tenant_id, name, category, provider, status)
			VALUES ($1, $2, $3, 'ticketing', 'jira', 'connected')`, in.id.String(), in.tenant.String(), "jira-"+in.id.String())
	}

	pg := &postgres.DB{DB: db}
	log := logger.NewNop()
	enforcer := datascope.New(postgres.NewDataScopeRepository(pg),
		func(ctx context.Context) datascope.Caller {
			return datascope.Caller{UserID: middleware.GetUserID(ctx), IsAdmin: middleware.IsAdmin(ctx)}
		}, log)
	prevGuard := dataScopeGuardMiddleware
	dataScopeGuardMiddleware = middleware.DataScopeGuard(enforcer)
	t.Cleanup(func() { dataScopeGuardMiddleware = prevGuard })

	h.pt = &policyTracker{intg: h.intA}
	h.repo = postgres.NewTicketCreatePolicyRepository(pg)
	svc := jira.NewSyncService(postgres.NewFindingRepository(pg), h.pt, log)
	gate := jira.NewPolicyGate(svc, h.repo, postgres.NewIntegrationRepository(pg), log)
	jh := handler.NewJiraWebhookHandler(svc, validator.New(), log)
	jh.SetCreatePolicy(gate)
	tm := handler.NewTicketMappingHandler(nil, nil, log)
	tm.SetCreatePolicy(gate)
	passThrough := Middleware(func(next http.Handler) http.Handler { return next })
	router := infrahttp.NewChiRouter()
	registerVulnerabilityRoutes(router, nil, nil, jh, nil, Middleware(h.auth), nil)
	registerIntegrationRoutes(router, handler.NewIntegrationHandler(nil, validator.New(), log), nil, nil, Middleware(h.auth), nil, passThrough, nil, nil, tm)
	h.srv = httptest.NewServer(router.(interface{ Handler() http.Handler }).Handler())
	t.Cleanup(h.srv.Close)
	return h
}

func (h *policyHarness) do(method string, perms []permission.Permission, path, body string) (int, string) {
	h.t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, h.srv.URL+path, strings.NewReader(body))
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

var tcpManage = []permission.Permission{permission.IntegrationsRead, permission.IntegrationsManage} //nolint:gochecknoglobals // fixture

func TestTicketCreatePolicy_RoutesAuthzAndTenant(t *testing.T) {
	h := newPolicyHarness(t)
	pathA := "/api/v1/integrations/" + h.intA.String() + "/ticket-create-policy"
	pathB := "/api/v1/integrations/" + h.intB.String() + "/ticket-create-policy"

	if status, body := h.do(http.MethodGet, []permission.Permission{permission.IntegrationsRead}, pathA, ""); status != http.StatusForbidden {
		t.Fatalf("GET without integrations:manage = %d (%s), want 403", status, body)
	}
	status, body := h.do(http.MethodGet, tcpManage, pathA, "")
	if status != http.StatusOK || !strings.Contains(body, `"stored":false`) || !strings.Contains(body, `"min_severity":"medium"`) {
		t.Fatalf("GET defaults = %d (%s)", status, body)
	}
	if status, body := h.do(http.MethodGet, tcpManage, pathB, ""); status != http.StatusNotFound {
		t.Fatalf("GET other tenant's integration = %d (%s), want 404", status, body)
	}
	good := `{"min_severity":"high","min_priority_class":"P1","always_kev":true,"daily_cap":50}`
	if status, body := h.do(http.MethodPut, tcpManage, pathB, good); status != http.StatusNotFound {
		t.Fatalf("PUT other tenant's integration = %d (%s), want 404", status, body)
	}
	var n int
	if err := h.db.QueryRow(`SELECT count(*) FROM ticket_create_policies WHERE integration_id = $1`, h.intB.String()).Scan(&n); err != nil || n != 0 {
		t.Fatalf("other tenant's policy rows = %d (%v)", n, err)
	}
	if status, body := h.do(http.MethodPut, tcpManage, pathA, `{"min_severity":"none","daily_cap":5}`); status != http.StatusBadRequest {
		t.Fatalf("PUT invalid = %d (%s), want 400", status, body)
	}
	if status, body := h.do(http.MethodPut, []permission.Permission{permission.IntegrationsRead}, pathA, good); status != http.StatusForbidden {
		t.Fatalf("PUT without integrations:manage = %d (%s), want 403", status, body)
	}
	if status, body := h.do(http.MethodPut, tcpManage, pathA, good); status != http.StatusOK || !strings.Contains(body, `"stored":true`) {
		t.Fatalf("PUT = %d (%s)", status, body)
	}
	if status, body := h.do(http.MethodGet, tcpManage, pathA, ""); !strings.Contains(body, `"min_priority_class":"P1"`) || status != http.StatusOK {
		t.Fatalf("GET after PUT = %d (%s)", status, body)
	}

	// Preview counts tenant A's findings only (3 in tenant A, 1 in B).
	status, body = h.do(http.MethodPost, tcpManage, pathA+"/preview", `{"min_severity":"info"}`)
	var pv ticketpolicy.Preview
	if status != http.StatusOK || json.Unmarshal([]byte(body), &pv) != nil || pv.Last30DaysTotal != 3 || pv.Last30DaysPass != 3 {
		t.Fatalf("preview = %d (%s)", status, body)
	}
	if status, body := h.do(http.MethodPost, tcpManage, pathB+"/preview", `{"min_severity":"info"}`); status != http.StatusNotFound {
		t.Fatalf("preview other tenant = %d (%s), want 404", status, body)
	}
}

func TestTicketCreatePolicy_ManualCreateBelowThreshold(t *testing.T) {
	h := newPolicyHarness(t)
	path := "/api/v1/findings/" + h.inScope.String() + "/create-ticket"
	status, body := h.do(http.MethodPost, teWritePerms, path, `{"project_key":"SEC"}`)
	if status != http.StatusConflict || !strings.Contains(body, "TICKET_BELOW_THRESHOLD") {
		t.Fatalf("below-threshold create = %d (%s), want 409", status, body)
	}
	if n := atomic.LoadInt32(&h.pt.creates); n != 0 {
		t.Fatalf("tracker creates = %d before confirmation", n)
	}
	if status, body := h.do(http.MethodPost, teWritePerms, path, `{"project_key":"SEC","confirm_below_threshold":true}`); status != http.StatusCreated {
		t.Fatalf("confirmed create = %d (%s)", status, body)
	}
	if n := atomic.LoadInt32(&h.pt.creates); n != 1 {
		t.Fatalf("tracker creates = %d, want 1", n)
	}
	// Out of scope stays 404 even with the confirmation.
	if status, body := h.do(http.MethodPost, teWritePerms, "/api/v1/findings/"+h.outOfScope.String()+"/create-ticket",
		`{"project_key":"SEC","confirm_below_threshold":true}`); status != http.StatusNotFound {
		t.Fatalf("out-of-scope create = %d (%s), want 404", status, body)
	}
}

func TestTicketCreatePolicy_FindingHoldsScope(t *testing.T) {
	h := newPolicyHarness(t)
	ctx := context.Background()
	for _, f := range []struct{ tenant, intg, finding shared.ID }{
		{h.tenantA, h.intA, h.inScope}, {h.tenantA, h.intA, h.outOfScope}, {h.tenantB, h.intB, h.other},
	} {
		if err := h.repo.PutHold(ctx, ticketpolicy.Hold{TenantID: f.tenant, IntegrationID: f.intg, FindingID: f.finding,
			Reason: ticketpolicy.ReasonBelowThreshold}); err != nil {
			t.Fatal(err)
		}
	}
	read := []permission.Permission{permission.FindingsRead}
	status, body := h.do(http.MethodGet, read, "/api/v1/findings/"+h.inScope.String()+"/ticket-holds", "")
	if status != http.StatusOK || !strings.Contains(body, ticketpolicy.ReasonBelowThreshold) || !strings.Contains(body, h.intA.String()) {
		t.Fatalf("in-scope holds = %d (%s)", status, body)
	}
	for name, id := range map[string]shared.ID{"out of scope": h.outOfScope, "other tenant": h.other} {
		if status, body := h.do(http.MethodGet, read, "/api/v1/findings/"+id.String()+"/ticket-holds", ""); status != http.StatusNotFound {
			t.Fatalf("%s holds = %d (%s), want 404", name, status, body)
		}
	}
	// A cross-tenant pair cannot be stored (composite foreign keys).
	if err := h.repo.PutHold(ctx, ticketpolicy.Hold{TenantID: h.tenantA, IntegrationID: h.intB, FindingID: h.inScope,
		Reason: ticketpolicy.ReasonBelowThreshold}); err == nil {
		t.Fatal("hold on another tenant's integration was stored")
	}
}

func TestTicketCreatePolicy_RepositorySemantics(t *testing.T) {
	h := newPolicyHarness(t)
	ctx := context.Background()

	// Daily cap: two slots, the third is refused, a release frees one.
	for i, want := range []bool{true, true, false} {
		ok, err := h.repo.Reserve(ctx, h.tenantA, h.intA, 2)
		if err != nil || ok != want {
			t.Fatalf("reserve %d = %v (%v), want %v", i, ok, err, want)
		}
	}
	if err := h.repo.Release(ctx, h.tenantA, h.intA); err != nil {
		t.Fatal(err)
	}
	if ok, _ := h.repo.Reserve(ctx, h.tenantA, h.intA, 2); !ok {
		t.Fatal("reserve after release refused")
	}
	if st, err := h.repo.Stats(ctx, h.tenantA, h.intA); err != nil || st.CreatedToday != 2 {
		t.Fatalf("stats %+v (%v)", st, err)
	}

	// The SQL predicate agrees with Evaluate on tenant A's findings.
	for _, p := range []ticketpolicy.Policy{
		ticketpolicy.Default(), {MinSeverity: "critical"}, {MinSeverity: "critical", MinPriorityClass: "P3"}, {MinSeverity: "info"},
	} {
		pv, err := h.repo.Preview(ctx, h.tenantA, h.intA, p)
		if err != nil {
			t.Fatal(err)
		}
		want := goPassCount(t, h, p)
		if pv.Last30DaysPass != want {
			t.Fatalf("policy %+v: SQL pass %d, Go pass %d", p, pv.Last30DaysPass, want)
		}
	}

	// A hold is due again only after its finding changes.
	if err := h.repo.PutHold(ctx, ticketpolicy.Hold{TenantID: h.tenantA, IntegrationID: h.intA, FindingID: h.inScope,
		Reason: ticketpolicy.ReasonBelowThreshold}); err != nil {
		t.Fatal(err)
	}
	h.exec(`UPDATE ticket_create_holds SET checked_at = (SELECT updated_at FROM findings WHERE id = $1) WHERE finding_id = $1`, h.inScope.String())
	if due := dueFor(t, h, h.inScope); due != nil {
		t.Fatalf("unchanged finding listed as due: %+v", due)
	}
	h.exec(`UPDATE findings SET severity = 'critical', updated_at = clock_timestamp() + interval '1 second' WHERE id = $1`, h.inScope.String())
	due := dueFor(t, h, h.inScope)
	if due == nil || due.Signals.Severity != "critical" || !due.Policy.UpdatedAt.IsZero() || due.TenantID != h.tenantA {
		t.Fatalf("changed finding not due: %+v", due)
	}
}

func dueFor(t *testing.T, h *policyHarness, findingID shared.ID) *ticketpolicy.Candidate {
	t.Helper()
	due, err := h.repo.DueHolds(context.Background(), 1000, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	for i := range due {
		if due[i].FindingID == findingID {
			return &due[i]
		}
	}
	return nil
}

// goPassCount evaluates the policy in Go over tenant A's recent findings.
func goPassCount(t *testing.T, h *policyHarness, p ticketpolicy.Policy) int {
	t.Helper()
	rows, err := h.db.Query(`SELECT severity, COALESCE(priority_class, ''), is_in_kev FROM findings
		WHERE tenant_id = $1 AND created_at >= now() - interval '30 days'`, h.tenantA.String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	n := 0
	for rows.Next() {
		var s ticketpolicy.Signals
		if err := rows.Scan(&s.Severity, &s.PriorityClass, &s.InKEV); err != nil {
			t.Fatal(err)
		}
		s.Open = true
		if p.Evaluate(s).Pass {
			n++
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return n
}
