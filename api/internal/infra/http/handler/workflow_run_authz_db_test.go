package handler

// Automation runs against real Postgres (research/61 §1.6, P0-3): a run acts
// as one person, checked live before every step.
//
//   - A manual run acts as the caller: it needs the permission of every
//     step and the subject inside the caller's data scope. The caller names
//     the subject by id; forged trigger data and other trigger types are
//     refused (the confused deputy: before, any holder of workflows:write
//     could point an admin's automation at any finding).
//   - Rewiring (edges, deleting a node, trigger edits) needs the
//     permission of every step, like adding one; the editor becomes owner.
//   - An event run acts as the owner, re-checked on every run: out of their
//     scope, a lost permission or a suspended membership refuses the step
//     and nothing changes.

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/app/datascope"
	findingapp "github.com/openctemio/openctem/api/internal/app/finding"
	workflowsvc "github.com/openctemio/openctem/api/internal/app/workflow"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/role"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	workflowdom "github.com/openctemio/openctem/api/pkg/domain/workflow"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

type wfAuthzMembers struct {
	tenants *postgres.TenantRepository
	access  *postgres.AccessControlRepository
}

func (m wfAuthzMembers) GetMembership(ctx context.Context, userID, tenantID shared.ID) (*tenant.Membership, error) {
	return m.tenants.GetMembership(ctx, userID, tenantID)
}

func (m wfAuthzMembers) IsActiveTenantMember(ctx context.Context, tenantID, userID shared.ID) (bool, error) {
	return m.access.IsActiveTenantMember(ctx, tenantID, userID)
}

type wfAuthzPerms struct{ roles *postgres.RoleRepository }

func (p wfAuthzPerms) GetUserPermissions(ctx context.Context, tenantID, userID string) ([]string, error) {
	return p.roles.GetUserPermissions(ctx, role.MustParseID(tenantID), role.MustParseID(userID))
}

func TestWorkflowRunAuthz_DB(t *testing.T) {
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
	admin, editor, operator := shared.NewID().String(), shared.NewID().String(), shared.NewID().String()
	users := []string{admin, editor, operator}
	for _, tn := range []string{tenantA, tenantB} {
		exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'wfa', $2)`, tn, "wfa-"+tn)
	}
	t.Cleanup(func() {
		bg := context.Background()
		for _, tn := range []string{tenantA, tenantB} {
			_, _ = raw.ExecContext(bg, `DELETE FROM workflow_runs WHERE tenant_id = $1`, tn)
			_, _ = raw.ExecContext(bg, `DELETE FROM workflows WHERE tenant_id = $1`, tn)
			_, _ = raw.ExecContext(bg, `DELETE FROM findings WHERE tenant_id = $1`, tn)
			_, _ = raw.ExecContext(bg, `DELETE FROM tenants WHERE id = $1`, tn)
		}
		for _, u := range users {
			_, _ = raw.ExecContext(bg, `DELETE FROM users WHERE id = $1`, u)
		}
	})
	// The membership role is synced to a system role: the admin is an
	// administrator; the others are viewers whose only write access comes
	// from the custom roles below.
	for _, u := range users {
		exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, 'wfa')`, u, u+"@wfa.test")
		membership := "viewer"
		if u == admin {
			membership = "admin"
		}
		exec(`INSERT INTO tenant_members (user_id, tenant_id, role) VALUES ($1, $2, $3)`, u, tenantA, membership)
	}
	customRole := func(slug string, perms ...string) string {
		id := shared.NewID().String()
		exec(`INSERT INTO roles (id, tenant_id, slug, name, is_system, hierarchy_level) VALUES ($1, $2, $3, $3, FALSE, 10)`, id, tenantA, slug)
		for _, p := range perms {
			exec(`INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2)`, id, p)
		}
		return id
	}
	// editor: may edit automations but not change findings.
	editorRole := customRole("wfa-editor", "findings:workflows:read", "findings:workflows:write", "findings:read")
	exec(`INSERT INTO user_roles (user_id, tenant_id, role_id) VALUES ($1, $2, $3)`, editor, tenantA, editorRole)
	// operator: may change findings, scoped to one asset.
	operatorRole := customRole("wfa-operator", "findings:workflows:read", "findings:workflows:write", "findings:read", "findings:write")
	exec(`INSERT INTO user_roles (user_id, tenant_id, role_id) VALUES ($1, $2, $3)`, operator, tenantA, operatorRole)

	assetIn, assetOut, assetB := shared.NewID().String(), shared.NewID().String(), shared.NewID().String()
	for id, tn := range map[string]string{assetIn: tenantA, assetOut: tenantA, assetB: tenantB} {
		exec(`INSERT INTO assets (id, tenant_id, name, asset_type, exposure, criticality) VALUES ($1, $2, $3, 'domain', 'public', 'high')`,
			id, tn, "wfa-"+id+".example.com")
	}
	for _, u := range []string{editor, operator} {
		exec(`INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type) VALUES ($1, $2, $3, 'secondary')`,
			u, tenantA, assetIn)
	}
	fIn, fOut, fB := shared.NewID().String(), shared.NewID().String(), shared.NewID().String()
	for f, a := range map[string][2]string{fIn: {tenantA, assetIn}, fOut: {tenantA, assetOut}, fB: {tenantB, assetB}} {
		exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, severity, message, fingerprint)
		      VALUES ($1, $2, $3, 'manual', 'wfa', 'high', 'wfa', $4)`, f, a[0], a[1], "wfa-"+f)
	}

	db := &postgres.DB{DB: raw}
	enforcer := datascope.New(postgres.NewDataScopeRepository(db),
		func(ctx context.Context) datascope.Caller {
			return datascope.Caller{UserID: middleware.GetUserID(ctx), IsAdmin: middleware.IsAdmin(ctx)}
		}, logger.NewNop())
	tenants := postgres.NewTenantRepository(db)
	enforcer.SetAdminLookup(datascope.MembershipAdminLookup(tenants))
	roles := postgres.NewRoleRepository(db)
	authorizer := workflowsvc.NewPrincipalAuthorizer(
		wfAuthzMembers{tenants: tenants, access: postgres.NewAccessControlRepository(db)},
		wfAuthzPerms{roles: roles}, enforcer,
		func(ctx context.Context, p workflowsvc.Principal) context.Context {
			ctx = context.WithValue(ctx, middleware.UserIDKey, p.UserID.String())
			return context.WithValue(ctx, middleware.IsAdminKey, p.IsAdmin)
		})
	vuln := findingapp.NewVulnerabilityService(nil, postgres.NewFindingRepository(db), logger.NewNop())
	vuln.SetDataScope(enforcer)

	wfRepo, nodeRepo := postgres.NewWorkflowRepository(db), postgres.NewWorkflowNodeRepository(db)
	runRepo, nodeRunRepo := postgres.NewWorkflowRunRepository(db), postgres.NewWorkflowNodeRunRepository(db)
	executor := workflowsvc.NewWorkflowExecutor(wfRepo, runRepo, nodeRunRepo, logger.NewNop(),
		workflowsvc.WithExecutorStepAuthorizer(authorizer))
	executor.RegisterActionHandler(workflowdom.ActionTypeAddTags, workflowsvc.NewFindingActionHandler(vuln, logger.NewNop()))
	// No executor on the service: the test runs each run synchronously.
	svc := workflowsvc.NewWorkflowService(wfRepo, nodeRepo, postgres.NewWorkflowEdgeRepository(db), runRepo, nodeRunRepo,
		logger.NewNop(),
		workflowsvc.WithWorkflowStepAuthorizer(authorizer),
		workflowsvc.WithWorkflowSubjectReaders(postgres.NewFindingRepository(db), postgres.NewAssetRepository(db)))
	h := NewWorkflowHandler(svc, validator.New(), logger.NewNop())

	as := func(user, method, body string, params map[string]string) *http.Request {
		t.Helper()
		r := httptest.NewRequest(method, "/", strings.NewReader(body))
		rc := chi.NewRouteContext()
		for k, v := range params {
			rc.URLParams.Add(k, v)
		}
		perms, err := roles.GetUserPermissions(ctx, role.MustParseID(tenantA), role.MustParseID(user))
		if err != nil {
			t.Fatal(err)
		}
		c := context.WithValue(r.Context(), chi.RouteCtxKey, rc)
		c = context.WithValue(c, middleware.TenantIDKey, tenantA)
		c = context.WithValue(c, middleware.UserIDKey, user)
		c = context.WithValue(c, middleware.IsAdminKey, user == admin)
		c = context.WithValue(c, middleware.FetchedPermissionsKey, append([]string{}, perms...))
		return r.WithContext(c)
	}
	call := func(fn http.HandlerFunc, r *http.Request) (int, string) {
		w := httptest.NewRecorder()
		fn(w, r)
		return w.Code, w.Body.String()
	}
	tagsOf := func(f string) []string {
		t.Helper()
		var tags pq.StringArray
		if err := raw.QueryRowContext(ctx, `SELECT COALESCE(tags, '{}') FROM findings WHERE id = $1`, f).Scan(&tags); err != nil {
			t.Fatal(err)
		}
		return tags
	}
	runCount := func(wf string) int {
		var n int
		if err := raw.QueryRowContext(ctx, `SELECT COUNT(*) FROM workflow_runs WHERE workflow_id = $1`, wf).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	ownerOf := func(wf string) string {
		var o sql.NullString
		if err := raw.QueryRowContext(ctx, `SELECT created_by::text FROM workflows WHERE id = $1`, wf).Scan(&o); err != nil {
			t.Fatal(err)
		}
		return o.String
	}
	execRun := func(runID string) (string, string) {
		t.Helper()
		id := shared.MustIDFromString(runID)
		if err := executor.ExecuteWithTenant(ctx, id, shared.MustIDFromString(tenantA)); err != nil {
			t.Fatalf("execute: %v", err)
		}
		var status string
		var code sql.NullString
		if err := raw.QueryRowContext(ctx, `SELECT r.status, (SELECT error_code FROM workflow_node_runs WHERE workflow_run_id = r.id AND node_type = 'action')
			FROM workflow_runs r WHERE r.id = $1`, runID).Scan(&status, &code); err != nil {
			t.Fatal(err)
		}
		return status, code.String
	}

	// The admin builds: manual trigger -> add tag "auto".
	status, body := call(h.CreateWorkflow, as(admin, http.MethodPost, `{"name":"tag it","nodes":[
		{"node_key":"t","node_type":"trigger","name":"t","config":{"trigger_type":"manual"}},
		{"node_key":"a","node_type":"action","name":"a","config":{"action_type":"add_tags","action_config":{"tags":["auto"]}}}],
		"edges":[{"source_node_key":"t","target_node_key":"a"}]}`, nil))
	if status != http.StatusCreated {
		t.Fatalf("create = %d %s", status, body)
	}
	var created WorkflowResponse
	_ = json.Unmarshal([]byte(body), &created)
	wf := created.ID
	var triggerNode string
	for _, n := range created.Nodes {
		if n.NodeKey == "t" {
			triggerNode = n.ID
		}
	}
	wfParam := map[string]string{"id": wf}

	t.Run("manual run needs every step's permission", func(t *testing.T) {
		status, body := call(h.TriggerWorkflow, as(editor, http.MethodPost, `{"finding_id":"`+fIn+`"}`, wfParam))
		if status != http.StatusForbidden {
			t.Fatalf("editor without findings:write = %d %s, want 403", status, body)
		}
		if runCount(wf) != 0 {
			t.Fatal("a refused manual run left a run row")
		}
	})

	t.Run("forged trigger data and other trigger types are refused", func(t *testing.T) {
		for _, b := range []string{
			`{"trigger_data":{"finding":{"id":"` + fOut + `"}}}`,
			`{"trigger_type":"finding_created","finding_id":"` + fIn + `"}`,
		} {
			if status, body := call(h.TriggerWorkflow, as(operator, http.MethodPost, b, wfParam)); status != http.StatusBadRequest && status != http.StatusUnprocessableEntity {
				t.Errorf("%s = %d %s, want 400/422", b, status, body)
			}
		}
		if runCount(wf) != 0 {
			t.Fatal("a refused manual run left a run row")
		}
	})

	t.Run("manual run only on a subject in the caller's scope", func(t *testing.T) {
		outStatus, outBody := call(h.TriggerWorkflow, as(operator, http.MethodPost, `{"finding_id":"`+fOut+`"}`, wfParam))
		if outStatus != http.StatusNotFound {
			t.Fatalf("out-of-scope finding = %d %s, want 404", outStatus, outBody)
		}
		// Another tenant's finding (even for the admin) and an unknown id
		// get the same answer.
		for _, f := range []string{fB, shared.NewID().String()} {
			if s, b := call(h.TriggerWorkflow, as(admin, http.MethodPost, `{"finding_id":"`+f+`"}`, wfParam)); s != outStatus || b != outBody {
				t.Errorf("finding %s = %d %s, want the out-of-scope answer", f, s, b)
			}
		}
		if runCount(wf) != 0 {
			t.Fatal("a refused manual run left a run row")
		}

		status, body := call(h.TriggerWorkflow, as(operator, http.MethodPost, `{"finding_id":"`+fIn+`"}`, wfParam))
		if status != http.StatusCreated {
			t.Fatalf("in-scope manual run = %d %s", status, body)
		}
		var run WorkflowRunResponse
		_ = json.Unmarshal([]byte(body), &run)
		if run.TriggeredBy == nil || *run.TriggeredBy != operator {
			t.Fatalf("manual run triggered_by = %v, want the caller", run.TriggeredBy)
		}
		var subject sql.NullString
		if err := raw.QueryRowContext(ctx, `SELECT subject_id::text FROM workflow_runs WHERE id = $1`, run.ID).Scan(&subject); err != nil {
			t.Fatal(err)
		}
		if subject.String != fIn {
			t.Fatalf("manual run subject = %q, want the named finding", subject.String)
		}
		if st, code := execRun(run.ID); st != "completed" {
			t.Fatalf("run = %s (%s), want completed", st, code)
		}
		if !slices.Contains(tagsOf(fIn), "auto") {
			t.Fatalf("tags of the run's finding = %v", tagsOf(fIn))
		}
		if len(tagsOf(fOut)) != 0 {
			t.Fatal("the run touched another finding")
		}
	})

	t.Run("rewiring needs every step's permission", func(t *testing.T) {
		edge := `{"source_node_key":"t","target_node_key":"a"}`
		if s, b := call(h.AddEdge, as(editor, http.MethodPost, edge, wfParam)); s != http.StatusForbidden {
			t.Errorf("editor add edge = %d %s, want 403", s, b)
		}
		if s, b := call(h.DeleteNode, as(editor, http.MethodDelete, "", map[string]string{"id": wf, "nodeId": triggerNode})); s != http.StatusForbidden {
			t.Errorf("editor delete node = %d %s, want 403", s, b)
		}
		if s, b := call(h.UpdateNode, as(editor, http.MethodPut,
			`{"config":{"trigger_type":"manual","trigger_config":{}}}`, map[string]string{"id": wf, "nodeId": triggerNode})); s != http.StatusForbidden {
			t.Errorf("editor trigger edit = %d %s, want 403", s, b)
		}
		if s, b := call(h.UpdateWorkflow, as(editor, http.MethodPut, `{"is_active":true}`, wfParam)); s != http.StatusForbidden {
			t.Errorf("editor activate = %d %s, want 403", s, b)
		}
		if ownerOf(wf) != admin {
			t.Fatalf("owner = %s after refused edits, want the admin", ownerOf(wf))
		}
		// The operator may: and becomes the owner the event runs act as.
		if s, b := call(h.UpdateNode, as(operator, http.MethodPut,
			`{"config":{"trigger_type":"manual","trigger_config":{}}}`, map[string]string{"id": wf, "nodeId": triggerNode})); s != http.StatusOK {
			t.Fatalf("operator trigger edit = %d %s", s, b)
		}
		if ownerOf(wf) != operator {
			t.Fatalf("owner = %s after the operator's edit, want the operator", ownerOf(wf))
		}
	})

	eventRun := func(f string) string {
		t.Helper()
		run, err := svc.TriggerWorkflow(ctx, workflowsvc.TriggerWorkflowInput{
			TenantID: shared.MustIDFromString(tenantA), WorkflowID: shared.MustIDFromString(wf),
			TriggerType: workflowdom.TriggerTypeFindingCreated,
			TriggerData: map[string]any{"finding": map[string]any{"id": f}},
		})
		if err != nil {
			t.Fatalf("event run: %v", err)
		}
		return run.ID.String()
	}
	clearTags := func() { exec(`UPDATE findings SET tags = '{}' WHERE tenant_id = $1`, tenantA) }

	t.Run("event run acts as the owner, checked on every run", func(t *testing.T) {
		clearTags()
		if st, code := execRun(eventRun(fOut)); st != "failed" || code != workflowsvc.ErrCodeRunNotAuthorized {
			t.Errorf("event on a finding outside the owner's scope = %s/%s, want failed/%s", st, code, workflowsvc.ErrCodeRunNotAuthorized)
		}
		if len(tagsOf(fOut)) != 0 {
			t.Fatal("an out-of-scope event changed the finding")
		}
		if st, code := execRun(eventRun(fIn)); st != "completed" {
			t.Fatalf("event in scope = %s/%s, want completed", st, code)
		}

		// The owner loses findings:write: the next run is refused.
		clearTags()
		exec(`DELETE FROM role_permissions WHERE role_id = $1 AND permission_id = 'findings:write'`, operatorRole)
		if st, code := execRun(eventRun(fIn)); st != "failed" || code != workflowsvc.ErrCodeRunNotAuthorized {
			t.Errorf("after losing findings:write = %s/%s, want failed/%s", st, code, workflowsvc.ErrCodeRunNotAuthorized)
		}
		if len(tagsOf(fIn)) != 0 {
			t.Fatal("a run of an owner without findings:write changed the finding")
		}

		// Back, but suspended: refused too.
		exec(`INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, 'findings:write')`, operatorRole)
		exec(`UPDATE tenant_members SET status = 'suspended', suspended_at = now() WHERE user_id = $1 AND tenant_id = $2`, operator, tenantA)
		if st, code := execRun(eventRun(fIn)); st != "failed" || code != workflowsvc.ErrCodeRunNotAuthorized {
			t.Errorf("suspended owner = %s/%s, want failed/%s", st, code, workflowsvc.ErrCodeRunNotAuthorized)
		}
		if len(tagsOf(fIn)) != 0 {
			t.Fatal("a run of a suspended owner changed the finding")
		}
	})
}
