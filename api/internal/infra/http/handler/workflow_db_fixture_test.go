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
	"github.com/lib/pq"

	automationsvc "github.com/openctemio/openctem/api/internal/app/automation"
	"github.com/openctemio/openctem/api/internal/app/datascope"
	findingapp "github.com/openctemio/openctem/api/internal/app/finding"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	automationdom "github.com/openctemio/openctem/api/pkg/domain/automation"
	"github.com/openctemio/openctem/api/pkg/domain/role"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

// wfDB is a real-Postgres automation fixture: two tenants; in tenant A an
// administrator, an editor (automation permissions, no findings:write) and
// an operator (findings:write, one asset in scope); one finding in the
// operator's scope (fIn), one outside it (fOut) and one in tenant B (fB).
type wfDB struct {
	t                         *testing.T
	ctx                       context.Context
	raw                       *sql.DB
	tenantA, tenantB          string
	admin, editor, operator   string
	editorRole, operatorRole  string
	assetIn, assetOut, assetB string
	fIn, fOut, fB             string
	roles                     *postgres.RoleRepository
	svc                       *automationsvc.WorkflowService
	executor                  *automationsvc.WorkflowExecutor
	versions                  *postgres.AutomationVersionRepository
	deliveries                *postgres.AutomationDeliveryRepository
	h                         *WorkflowHandler
}

func newWFDB(t *testing.T, extraExecutorOpts ...automationsvc.WorkflowExecutorOption) *wfDB {
	t.Helper()
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping DB-backed handler test")
	}
	raw, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	f := &wfDB{t: t, ctx: context.Background(), raw: raw}
	if err := raw.PingContext(f.ctx); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}
	f.tenantA, f.tenantB = shared.NewID().String(), shared.NewID().String()
	f.admin, f.editor, f.operator = shared.NewID().String(), shared.NewID().String(), shared.NewID().String()
	users := []string{f.admin, f.editor, f.operator}
	for _, tn := range []string{f.tenantA, f.tenantB} {
		f.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'wfd', $2)`, tn, "wfd-"+tn)
	}
	t.Cleanup(func() {
		bg := context.Background()
		for _, tn := range []string{f.tenantA, f.tenantB} {
			_, _ = raw.ExecContext(bg, `DELETE FROM automation_runs WHERE tenant_id = $1`, tn)
			_, _ = raw.ExecContext(bg, `UPDATE automations SET published_version_id = NULL WHERE tenant_id = $1`, tn)
			_, _ = raw.ExecContext(bg, `DELETE FROM automations WHERE tenant_id = $1`, tn)
			_, _ = raw.ExecContext(bg, `DELETE FROM finding_status_approvals WHERE tenant_id = $1`, tn)
			_, _ = raw.ExecContext(bg, `DELETE FROM findings WHERE tenant_id = $1`, tn)
			_, _ = raw.ExecContext(bg, `DELETE FROM tenants WHERE id = $1`, tn)
		}
		for _, u := range users {
			_, _ = raw.ExecContext(bg, `DELETE FROM users WHERE id = $1`, u)
		}
	})
	for _, u := range users {
		f.exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, 'wfd')`, u, u+"@wfd.test")
		membership := "viewer"
		if u == f.admin {
			membership = "admin"
		}
		f.exec(`INSERT INTO tenant_members (user_id, tenant_id, role) VALUES ($1, $2, $3)`, u, f.tenantA, membership)
	}
	f.editorRole = f.customRole("wfd-editor", wfReadPerm, wfWritePerm, "findings:read")
	f.exec(`INSERT INTO user_roles (user_id, tenant_id, role_id) VALUES ($1, $2, $3)`, f.editor, f.tenantA, f.editorRole)
	f.operatorRole = f.customRole("wfd-operator", wfReadPerm, wfWritePerm, "findings:read", "findings:write")
	f.exec(`INSERT INTO user_roles (user_id, tenant_id, role_id) VALUES ($1, $2, $3)`, f.operator, f.tenantA, f.operatorRole)

	f.assetIn, f.assetOut, f.assetB = shared.NewID().String(), shared.NewID().String(), shared.NewID().String()
	for id, tn := range map[string]string{f.assetIn: f.tenantA, f.assetOut: f.tenantA, f.assetB: f.tenantB} {
		f.exec(`INSERT INTO assets (id, tenant_id, name, asset_type, exposure, criticality) VALUES ($1, $2, $3, 'domain', 'public', 'high')`,
			id, tn, "wfd-"+id+".example.com")
	}
	for _, u := range []string{f.editor, f.operator} {
		f.exec(`INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type) VALUES ($1, $2, $3, 'secondary')`,
			u, f.tenantA, f.assetIn)
	}
	f.fIn, f.fOut, f.fB = shared.NewID().String(), shared.NewID().String(), shared.NewID().String()
	for id, a := range map[string][2]string{f.fIn: {f.tenantA, f.assetIn}, f.fOut: {f.tenantA, f.assetOut}, f.fB: {f.tenantB, f.assetB}} {
		f.exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, severity, message, fingerprint)
		      VALUES ($1, $2, $3, 'manual', 'wfd', 'high', 'wfd', $4)`, id, a[0], a[1], "wfd-"+id)
	}

	db := &postgres.DB{DB: raw}
	enforcer := datascope.New(postgres.NewDataScopeRepository(db),
		func(ctx context.Context) datascope.Caller {
			return datascope.Caller{UserID: middleware.GetUserID(ctx), IsAdmin: middleware.IsAdmin(ctx)}
		}, logger.NewNop())
	tenants := postgres.NewTenantRepository(db)
	enforcer.SetAdminLookup(datascope.MembershipAdminLookup(tenants))
	f.roles = postgres.NewRoleRepository(db)
	authorizer := automationsvc.NewPrincipalAuthorizer(
		wfAuthzMembers{tenants: tenants, access: postgres.NewAccessControlRepository(db)},
		wfAuthzPerms{roles: f.roles}, enforcer,
		func(ctx context.Context, p automationsvc.Principal) context.Context {
			ctx = context.WithValue(ctx, middleware.UserIDKey, p.UserID.String())
			return context.WithValue(ctx, middleware.IsAdminKey, p.IsAdmin)
		})
	vuln := findingapp.NewVulnerabilityService(nil, postgres.NewFindingRepository(db), logger.NewNop())
	vuln.SetDataScope(enforcer)

	wfRepo, nodeRepo := postgres.NewAutomationRepository(db), postgres.NewAutomationNodeRepository(db)
	runRepo, nodeRunRepo := postgres.NewAutomationRunRepository(db), postgres.NewAutomationRunStepRepository(db)
	f.versions = postgres.NewAutomationVersionRepository(db)
	f.deliveries = postgres.NewAutomationDeliveryRepository(db)
	opts := append([]automationsvc.WorkflowExecutorOption{
		automationsvc.WithExecutorStepAuthorizer(authorizer), automationsvc.WithExecutorVersions(f.versions),
		automationsvc.WithExecutorDeliveries(f.deliveries),
		automationsvc.WithExecutorEvaluator(automationsvc.NewSimulateEvaluator(postgres.NewFindingRepository(db))),
	}, extraExecutorOpts...)
	f.executor = automationsvc.NewWorkflowExecutor(wfRepo, runRepo, nodeRunRepo, logger.NewNop(), opts...)
	f.executor.RegisterActionHandler(automationdom.ActionTypeAddTags, automationsvc.NewFindingActionHandler(vuln, logger.NewNop()))
	// No executor on the service: each run executes synchronously in the test.
	f.svc = automationsvc.NewWorkflowService(wfRepo, nodeRepo, postgres.NewAutomationEdgeRepository(db), runRepo, nodeRunRepo,
		logger.NewNop(),
		automationsvc.WithWorkflowStepAuthorizer(authorizer),
		automationsvc.WithWorkflowSubjectReaders(postgres.NewFindingRepository(db), postgres.NewAssetRepository(db)),
		automationsvc.WithWorkflowVersions(f.versions),
		automationsvc.WithWorkflowRunReaders(enforcer, f.deliveries))
	f.h = NewWorkflowHandler(f.svc, validator.New(), logger.NewNop())
	return f
}

// Permission ids of the automation routes, as the fixture's roles hold them.
const (
	wfReadPerm  = "findings:workflows:read"
	wfWritePerm = "findings:workflows:write"
)

func (f *wfDB) exec(q string, args ...any) {
	f.t.Helper()
	if _, err := f.raw.ExecContext(f.ctx, q, args...); err != nil {
		f.t.Fatalf("seed %q: %v", q, err)
	}
}

func (f *wfDB) customRole(slug string, perms ...string) string {
	f.t.Helper()
	id := shared.NewID().String()
	f.exec(`INSERT INTO roles (id, tenant_id, slug, name, is_system, hierarchy_level) VALUES ($1, $2, $3, $3, FALSE, 10)`, id, f.tenantA, slug)
	for _, p := range perms {
		f.exec(`INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2)`, id, p)
	}
	return id
}

// as builds a request from user in tenant (tenant A unless given), with the
// user's current permissions.
func (f *wfDB) as(user, method, body string, params map[string]string, tenant ...string) *http.Request {
	f.t.Helper()
	tn := f.tenantA
	if len(tenant) > 0 {
		tn = tenant[0]
	}
	r := httptest.NewRequest(method, "/", strings.NewReader(body))
	rc := chi.NewRouteContext()
	for k, v := range params {
		rc.URLParams.Add(k, v)
	}
	perms, err := f.roles.GetUserPermissions(f.ctx, role.MustParseID(tn), role.MustParseID(user))
	if err != nil {
		f.t.Fatal(err)
	}
	c := context.WithValue(r.Context(), chi.RouteCtxKey, rc)
	c = context.WithValue(c, middleware.TenantIDKey, tn)
	c = context.WithValue(c, middleware.UserIDKey, user)
	c = context.WithValue(c, middleware.IsAdminKey, user == f.admin)
	c = context.WithValue(c, middleware.FetchedPermissionsKey, append([]string{}, perms...))
	return r.WithContext(c)
}

func (f *wfDB) call(fn http.HandlerFunc, r *http.Request) (int, string) {
	w := httptest.NewRecorder()
	fn(w, r)
	return w.Code, w.Body.String()
}

// create makes an automation from the admin with the given nodes and edges
// JSON and returns its id.
func (f *wfDB) create(nodes, edges string) string {
	f.t.Helper()
	status, body := f.call(f.h.CreateWorkflow, f.as(f.admin, http.MethodPost,
		`{"name":"wfd `+shared.NewID().String()[24:]+`","nodes":`+nodes+`,"edges":`+edges+`}`, nil))
	if status != http.StatusCreated {
		f.t.Fatalf("create = %d %s", status, body)
	}
	var created WorkflowResponse
	_ = json.Unmarshal([]byte(body), &created)
	return created.ID
}

func (f *wfDB) tagsOf(finding string) []string {
	f.t.Helper()
	var tags pq.StringArray
	if err := f.raw.QueryRowContext(f.ctx, `SELECT COALESCE(tags, '{}') FROM findings WHERE id = $1`, finding).Scan(&tags); err != nil {
		f.t.Fatal(err)
	}
	return tags
}

// eventRun starts a finding_created run of wf for the finding.
func (f *wfDB) eventRun(wf, finding string) *automationdom.Run {
	f.t.Helper()
	run, err := f.svc.TriggerWorkflow(f.ctx, automationsvc.TriggerWorkflowInput{
		TenantID: shared.MustIDFromString(f.tenantA), WorkflowID: shared.MustIDFromString(wf),
		TriggerType: automationdom.TriggerTypeFindingCreated,
		TriggerData: map[string]any{"finding": map[string]any{"id": finding}},
	})
	if err != nil {
		f.t.Fatalf("event run: %v", err)
	}
	return run
}

// execute runs a run synchronously and returns its status.
func (f *wfDB) execute(runID shared.ID) string {
	f.t.Helper()
	if err := f.executor.ExecuteWithTenant(f.ctx, runID, shared.MustIDFromString(f.tenantA)); err != nil {
		f.t.Fatalf("execute: %v", err)
	}
	var status string
	if err := f.raw.QueryRowContext(f.ctx, `SELECT status FROM automation_runs WHERE id = $1`, runID.String()).Scan(&status); err != nil {
		f.t.Fatal(err)
	}
	return status
}

// tagFlow is trigger finding_created -> add_tags(tag).
func tagFlow(tag string) (nodes, edges string) {
	return `[{"node_key":"t","node_type":"trigger","name":"t","config":{"trigger_type":"finding_created"}},
		{"node_key":"a","node_type":"action","name":"a","config":{"action_type":"add_tags","action_config":{"tags":["` + tag + `"]}}}]`,
		`[{"source_node_key":"t","target_node_key":"a"}]`
}
