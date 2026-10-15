package integration

// Repositories go to code scanning only (docs/architecture/active-probe-gate.md,
// "Repositories and path targets"): a repository asset, or a target in the
// form of one ("github.com/acme/app"), never reaches a network tool, which
// would probe the code host itself. On a migrated database: a network scan
// leaves the repository out and records why on the run; a workflow's
// network step never gets it; the coverage planner never plans a network
// capability for a repository.

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"

	coverageapp "github.com/openctemio/openctem/api/internal/app/coverage"
	scansvc "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/internal/app/scanrun"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/scangov"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
	"github.com/openctemio/openctem/api/pkg/logger"
)

const (
	repoTarget = "github.com/acme/app"
	webTarget  = "app.repo-route.test"
)

// newRepoRouteService is the trigger service with the asset-group
// repository, so group members are resolved.
func newRepoRouteService(t *testing.T) (*scansvc.Service, func(q string, args ...any)) {
	db := openLifecycleDB(t)
	pg := &postgres.DB{DB: db}
	svc := scansvc.NewService(
		postgres.NewScanRepository(pg), postgres.NewScanWorkflowRepository(pg), postgres.NewAssetGroupRepository(pg),
		postgres.NewScanRunRepository(pg), postgres.NewScanWorkflowStepRepository(pg), postgres.NewStepRunRepository(pg),
		postgres.NewCommandRepository(pg), nil, nil, postgres.NewToolRepository(pg), nil, availableSensors{}, nil,
		logger.New(logger.Config{Level: "error"}), allowAllTargetChecks()...,
	)
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(context.Background(), q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	return svc, exec
}

// A network scan (nuclei) of a direct repository-form target and of an
// asset group holding a repository asset scans the web name only; the run
// records each skipped repository and the reason.
func TestRepositoryTargets_NetworkScanSkipsRepositories(t *testing.T) {
	ctx := context.Background()
	svc, exec := newRepoRouteService(t)
	db := openLifecycleDB(t)
	tenant := seedLifecycleTenant(ctx, t, db)
	other := seedLifecycleTenant(ctx, t, db)

	group := shared.NewID()
	exec(`INSERT INTO asset_groups (id, tenant_id, name) VALUES ($1, $2, 'repos and web')`, group.String(), tenant.String())
	for _, a := range []struct{ name, typ string }{{"gitlab.com/acme/api", "repository"}, {webTarget, "subdomain"}} {
		id := seedOwnedAsset(t, db, tenant, a.name, a.typ)
		exec(`INSERT INTO asset_group_members (asset_group_id, asset_id) VALUES ($1, $2)`, group.String(), id.String())
	}
	// Another tenant's same-named assets change nothing for this tenant.
	seedOwnedAsset(t, db, other, repoTarget, "repository")

	// The direct target is stored as an older scan could have saved it
	// (scan create refuses it today); the trigger must still refuse it.
	scanID := shared.NewID()
	exec(`INSERT INTO scans (id, tenant_id, name, scan_type, scanner_name, targets, asset_group_id,
	                         status, schedule_type, sensor_preference, timeout_seconds)
	      VALUES ($1, $2, 'network scan with a repository', 'single', 'nuclei', ARRAY[$3], $4,
	              'active', 'manual', 'tenant', 3600)`, scanID.String(), tenant.String(), repoTarget, group.String())

	run, err := svc.TriggerScan(ctx, scansvc.TriggerScanExecInput{TenantID: tenant.String(), ScanID: scanID.String()})
	if err != nil {
		t.Fatalf("trigger: %v", err)
	}
	if got := lastCommandTargets(t, db, tenant); !slices.Equal(got, []string{webTarget}) {
		t.Fatalf("nuclei targets = %v, want only %s", got, webTarget)
	}
	for _, n := range []string{repoTarget, "gitlab.com/acme/api", "github.com", "gitlab.com"} {
		if commandsNaming(t, db, tenant, n) != 0 {
			t.Fatalf("a command names %s", n)
		}
	}

	// Recorded on the run, with the reason.
	var raw []byte
	if err := db.QueryRowContext(ctx, `SELECT context FROM scan_runs WHERE tenant_id = $1 AND id = $2`,
		tenant.String(), run.ID.String()).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var rc struct {
		Incompatible int      `json:"incompatible_target_count"`
		Warnings     []string `json:"dispatch_warnings"`
	}
	if err := json.Unmarshal(raw, &rc); err != nil {
		t.Fatal(err)
	}
	if rc.Incompatible != 2 {
		t.Fatalf("incompatible_target_count = %d, want 2 (the direct target and the group member)", rc.Incompatible)
	}
	if !slices.ContainsFunc(rc.Warnings, func(w string) bool { return strings.Contains(w, stage.ReasonPathTarget) }) {
		t.Fatalf("dispatch_warnings %v do not say why the repositories were skipped", rc.Warnings)
	}

	// A network scan of repositories alone is refused, nothing dispatched.
	only := shared.NewID()
	exec(`INSERT INTO scans (id, tenant_id, name, scan_type, scanner_name, targets,
	                         status, schedule_type, sensor_preference, timeout_seconds)
	      VALUES ($1, $2, 'repositories only', 'single', 'httpx', ARRAY[$3, 'git@github.com:acme/app'],
	              'active', 'manual', 'tenant', 3600)`, only.String(), tenant.String(), repoTarget)
	before := countCommands(t, db, tenant)
	_, err = svc.TriggerScan(ctx, scansvc.TriggerScanExecInput{TenantID: tenant.String(), ScanID: only.String()})
	var de *shared.DomainError
	if !errors.As(err, &de) || de.Code != "NO_COMPATIBLE_TARGETS" || !strings.Contains(err.Error(), stage.ReasonPathTarget) {
		t.Fatalf("repositories-only network scan: %v, want NO_COMPATIBLE_TARGETS with the reason", err)
	}
	if countCommands(t, db, tenant) != before {
		t.Fatal("a refused scan dispatched a command")
	}
	if countCommands(t, db, other) != 0 {
		t.Fatal("another tenant got a command")
	}
}

// A workflow's network step never gets the run's repositories: alone they
// refuse the step, beside a web name only the name is dispatched. Nothing
// derived from a repository points the step at the code host.
func TestRepositoryTargets_WorkflowNetworkStepYieldsNothing(t *testing.T) {
	ctx := context.Background()
	svc, exec := newRepoRouteService(t)
	db := openLifecycleDB(t)
	tenant := seedLifecycleTenant(ctx, t, db)

	templateID := shared.NewID()
	exec(`INSERT INTO scan_workflows (id, tenant_id, name, description, is_active) VALUES ($1, $2, 'repo route', '', TRUE)`,
		templateID.String(), tenant.String())
	exec(`INSERT INTO scan_workflow_steps (id, scan_workflow_id, step_key, name, description, step_order, tool) VALUES ($1, $2, 'probe', 'Probe', '', 1, 'httpx')`,
		shared.NewID().String(), templateID.String())
	pg := &postgres.DB{DB: db}
	runs := scanrun.NewService(
		postgres.NewScanWorkflowRepository(pg), postgres.NewScanWorkflowStepRepository(pg),
		postgres.NewScanRunRepository(pg), postgres.NewStepRunRepository(pg),
		postgres.NewSensorRepository(pg), postgres.NewCommandRepository(pg), nil, logger.New(logger.Config{Level: "error"}),
		scanrun.WithTargetGate(svc),
	)
	svc.SetStepQueuer(runs)

	before := countCommands(t, db, tenant)
	if _, err := runs.TriggerPipeline(ctx, scanrun.TriggerRunInput{TenantID: tenant.String(), TemplateID: templateID.String(),
		TriggerType: "api", Context: map[string]any{"targets": []any{repoTarget, "git@github.com:acme/app"}}}); err == nil {
		t.Fatal("a network step was started on repositories alone")
	}
	if countCommands(t, db, tenant) != before {
		t.Fatal("the refused step dispatched a command")
	}

	// A workflow scan of an asset group: the repository member is a typed
	// target of the run, and the network step does not get it.
	group := shared.NewID()
	exec(`INSERT INTO asset_groups (id, tenant_id, name) VALUES ($1, $2, 'repos and web')`, group.String(), tenant.String())
	for _, a := range []struct{ name, typ string }{{repoTarget, "repository"}, {webTarget, "subdomain"}} {
		id := seedOwnedAsset(t, db, tenant, a.name, a.typ)
		exec(`INSERT INTO asset_group_members (asset_group_id, asset_id) VALUES ($1, $2)`, group.String(), id.String())
	}
	scanID := shared.NewID()
	exec(`INSERT INTO scans (id, tenant_id, name, scan_type, scan_workflow_id, targets, asset_group_id,
	                         status, schedule_type, sensor_preference, timeout_seconds)
	      VALUES ($1, $2, 'workflow with a repository', 'workflow', $3, ARRAY[]::text[], $4,
	              'active', 'manual', 'tenant', 3600)`, scanID.String(), tenant.String(), templateID.String(), group.String())
	if _, err := svc.TriggerScan(ctx, scansvc.TriggerScanExecInput{TenantID: tenant.String(), ScanID: scanID.String()}); err != nil {
		t.Fatalf("trigger: %v", err)
	}
	if got := lastCommandTargets(t, db, tenant); !slices.Equal(got, []string{webTarget}) {
		t.Fatalf("httpx targets = %v, want only %s", got, webTarget)
	}
	if n := commandsNaming(t, db, tenant, "github.com"); n != 0 {
		t.Fatalf("%d command(s) name the code host", n)
	}
}

// recordingStarter records every batch the planner starts.
type recordingStarter struct {
	mu    sync.Mutex
	calls map[string][]string
}

func (r *recordingStarter) StartCoverage(_ context.Context, in scansvc.CoverageInput) (*scansvc.CoverageResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls[in.Capability] = append(r.calls[in.Capability], in.Targets...)
	return &scansvc.CoverageResult{}, nil
}

// The coverage policy plans no network capability for a repository, and a
// stray ledger row of one is never started: it is blocked with the reason.
func TestRepositoryTargets_CoverageNeverPlansNetworkForRepositories(t *testing.T) {
	g := newCovRig(t)
	ctx := context.Background()
	a := g.r.newTenant()
	repo := g.asset(a, repoTarget, "repository", "", "")
	web := g.asset(a, webTarget, "subdomain", "", "")

	if _, err := g.svc.RunTenant(ctx, a.tenant); err != nil {
		t.Fatal(err)
	}
	for capability := range g.states(a, repo) {
		if st, ok := stage.Lookup(stage.Key(capability)); ok && st.TakesNetworkKinds() {
			t.Fatalf("the policy planned %s for a repository", capability)
		}
	}
	if len(g.states(a, web)) == 0 {
		t.Fatal("the web name got no coverage rows; the rig plans nothing")
	}

	// A row the policy would never write (an older policy, a manual edit).
	g.exec(`INSERT INTO asset_coverage (tenant_id, asset_id, capability, vantage, state, reason, next_due_at)
	        VALUES ($1, $2, 'probe.http', '', 'due', '', now())`, a.tenant, repo)
	f := &recordingStarter{calls: map[string][]string{}}
	g.svc.EnablePlanning(g.repo, f, coverageapp.GovernanceSwitch{Modes: &fixedMode{m: scangov.ModeOff}}, coverageapp.Config{})
	if _, err := g.svc.RunTenant(ctx, a.tenant); err != nil {
		t.Fatal(err)
	}
	for capability, targets := range f.calls {
		if slices.Contains(targets, repoTarget) {
			t.Fatalf("%s was started on the repository", capability)
		}
	}
	if got := g.states(a, repo)["probe.http"]; got != "blocked:"+coverageapp.ReasonRepositoryCodeOnly {
		t.Fatalf("repository probe.http = %q, want blocked with the reason", got)
	}
}
