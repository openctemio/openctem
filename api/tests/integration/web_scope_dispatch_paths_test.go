package integration

// Every path that creates a web job attaches the web scope of the tenant's
// path exclusions, or refuses the job (docs/rfcs/RFC-056-web-attack-surface.md
// §5, RFC-055 §6.1). A quick nuclei scan of a host with /admin excluded used
// to carry no web scope at all, and nuclei requested paths under /admin.
// These tests run the real services and the real command repository, with
// its create guard, on a migrated database.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"slices"
	"testing"

	commandapp "github.com/openctemio/openctem/api/internal/app/command"
	scansvc "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/internal/app/scanrun"
	scopesvc "github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/internal/app/validation"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	scanrundom "github.com/openctemio/openctem/api/pkg/domain/scanrun"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

const webHost = "app.webscope.example.com"

// seedPathExclusion inserts an approved path exclusion in effect: every
// method under prefix on hosts matching host.
func seedPathExclusion(t *testing.T, db *sql.DB, tenant shared.ID, host, prefix string) {
	t.Helper()
	if _, err := db.ExecContext(context.Background(),
		`INSERT INTO scope_exclusions (tenant_id, exclusion_type, pattern, path_prefix, reason, status, approved_by, approved_at, created_by)
		 VALUES ($1, 'path', $2, $3, 'test', 'active', 'approver', NOW(), 'requester')`,
		tenant.String(), host+prefix, prefix); err != nil {
		t.Fatalf("seed path exclusion %s%s: %v", host, prefix, err)
	}
}

// guardedCommands is the command repository as production wires it: every
// command passes the web job guard.
func guardedCommands(db *sql.DB, b scopesvc.WebScopeBuilder) *postgres.CommandRepository {
	repo := postgres.NewCommandRepository(&postgres.DB{DB: db})
	repo.SetCreateGuard(integrationGuard(scopesvc.NewWebJobGuard(b, nil)))
	return repo
}

// scanServiceOver is newTriggerServiceWith over the given command repository.
func scanServiceOver(db *sql.DB, cmds commanddom.Repository) *scansvc.Service {
	pg := &postgres.DB{DB: db}
	svc := scansvc.NewService(
		postgres.NewScanRepository(pg), postgres.NewScanWorkflowRepository(pg), nil,
		postgres.NewScanRunRepository(pg), postgres.NewScanWorkflowStepRepository(pg),
		postgres.NewStepRunRepository(pg), cmds, nil, nil,
		postgres.NewToolRepository(pg), nil, tenantSensors{}, nil,
		logger.New(logger.Config{Level: "error"}), allowAllTargetChecks()...,
	)
	svc.SetStepQueuer(scanrun.NewService(
		postgres.NewScanWorkflowRepository(pg), postgres.NewScanWorkflowStepRepository(pg),
		postgres.NewScanRunRepository(pg), postgres.NewStepRunRepository(pg),
		postgres.NewSensorRepository(pg), cmds, nil, logger.New(logger.Config{Level: "error"}),
		scanrun.WithTargetGate(svc), scanrun.WithToolFacts(integrationTools),
	))
	return svc
}

// tenantSensors routes every job to the tenant's own sensors.
type tenantSensors struct{ availableSensors }

func (tenantSensors) SelectSensor(context.Context, scansvc.SelectSensorRequest) (*scansvc.SelectSensorResult, error) {
	return &scansvc.SelectSensorResult{}, nil
}

// commandPayloads are the payloads of a tenant's commands of a type.
func commandPayloads(t *testing.T, db *sql.DB, tenant shared.ID, typ string) []map[string]any {
	t.Helper()
	rows, err := db.QueryContext(context.Background(),
		`SELECT payload FROM commands WHERE tenant_id = $1 AND type = $2 ORDER BY created_at`, tenant.String(), typ)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			t.Fatal(err)
		}
		var p map[string]any
		if err := json.Unmarshal(raw, &p); err != nil {
			t.Fatal(err)
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func webDenyPaths(p map[string]any) []string {
	ws, _ := p[commanddom.PayloadKeyWebScope].(map[string]any)
	list, _ := ws["deny_paths"].([]any)
	out := make([]string, 0, len(list))
	for _, v := range list {
		s, _ := v.(string)
		out = append(out, s)
	}
	return out
}

// onlyCommand is the one command of a type a tenant has, and its deny paths.
func onlyCommand(t *testing.T, db *sql.DB, tenant shared.ID, typ string) []string {
	t.Helper()
	ps := commandPayloads(t, db, tenant, typ)
	if len(ps) != 1 {
		t.Fatalf("%d %s command(s), want 1", len(ps), typ)
	}
	return webDenyPaths(ps[0])
}

// SECURITY: a quick scan with a web tool carries the deny paths (the
// reported bypass), and so does a saved single-scanner scan when it is
// triggered (schedules and retries trigger it the same way).
func TestWebScope_QuickAndSingleScans(t *testing.T) {
	db := openLifecycleDB(t)
	ctx := context.Background()
	for _, tool := range []string{"nuclei", "katana"} {
		t.Run(tool, func(t *testing.T) {
			tenant := seedLifecycleTenant(ctx, t, db)
			seedPathExclusion(t, db, tenant, webHost, "/admin")
			svc := scanServiceOver(db, guardedCommands(db, scopeService(db)))

			if _, err := svc.QuickScan(ctx, scansvc.QuickScanInput{TenantID: tenant.String(), ScannerName: tool,
				Targets: []string{"https://" + webHost}}); err != nil {
				t.Fatalf("quick scan: %v", err)
			}
			if got := onlyCommand(t, db, tenant, "scan"); !slices.Equal(got, []string{"/admin"}) {
				t.Fatalf("quick scan job deny_paths = %v, want [/admin]", got)
			}

			sc, err := svc.CreateScan(ctx, scansvc.CreateScanInput{TenantID: tenant.String(), Name: "saved " + tool,
				ScanType: "single", ScannerName: tool, Targets: []string{"https://" + webHost}, TenantRunner: true})
			if err != nil {
				t.Fatalf("create scan: %v", err)
			}
			if _, err := svc.TriggerScan(ctx, scansvc.TriggerScanExecInput{TenantID: tenant.String(), ScanID: sc.ID.String()}); err != nil {
				t.Fatalf("trigger: %v", err)
			}
			ps := commandPayloads(t, db, tenant, "scan")
			if len(ps) != 2 || !slices.Equal(webDenyPaths(ps[1]), []string{"/admin"}) {
				t.Fatalf("triggered scan job: %d command(s), deny_paths %v", len(ps), webDenyPaths(ps[len(ps)-1]))
			}
		})
	}
}

// A workflow step with a web tool keeps its scope (one dispatcher, the same
// guard).
func TestWebScope_WorkflowStep(t *testing.T) {
	db := openLifecycleDB(t)
	ctx := context.Background()
	tenant := seedLifecycleTenant(ctx, t, db)
	seedPathExclusion(t, db, tenant, webHost, "/admin")
	templateID := shared.NewID()
	if _, err := db.ExecContext(ctx,
		`INSERT INTO scan_workflows (id, tenant_id, name, description, is_active) VALUES ($1, $2, 'web scope', '', TRUE)`,
		templateID.String(), tenant.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx,
		`INSERT INTO scan_workflow_steps (id, scan_workflow_id, step_key, name, description, step_order, tool) VALUES ($1, $2, 'templates', 'Templates', '', 1, 'nuclei')`,
		shared.NewID().String(), templateID.String()); err != nil {
		t.Fatal(err)
	}
	seedScopeTarget(t, db, tenant, "domain", "*.webscope.example.com")
	pg := &postgres.DB{DB: db}
	cmds := guardedCommands(db, scopeService(db))
	svc := scanrun.NewService(
		postgres.NewScanWorkflowRepository(pg), postgres.NewScanWorkflowStepRepository(pg),
		postgres.NewScanRunRepository(pg), postgres.NewStepRunRepository(pg),
		postgres.NewSensorRepository(pg), cmds, nil, logger.New(logger.Config{Level: "error"}),
		scanrun.WithTargetGate(newTriggerServiceWith(db, scansvc.WithActScope(actScopeChecker(db)))), scanrun.WithToolFacts(integrationTools),
	)
	if _, err := svc.TriggerPipeline(ctx, scanrun.TriggerRunInput{TenantID: tenant.String(), TemplateID: templateID.String(),
		TriggerType: "api", Context: map[string]any{"targets": []any{"https://" + webHost}}}); err != nil {
		t.Fatalf("trigger: %v", err)
	}
	if got := onlyCommand(t, db, tenant, "scan"); !slices.Equal(got, []string{"/admin"}) {
		t.Fatalf("workflow step deny_paths = %v, want [/admin]", got)
	}
}

// SECURITY: a command created through the API (POST /api/v1/commands) gets
// the platform's web scope; a caller's own web_scope does not survive.
func TestWebScope_CommandAPI(t *testing.T) {
	db := openLifecycleDB(t)
	ctx := context.Background()
	tenant := seedLifecycleTenant(ctx, t, db)
	seedPathExclusion(t, db, tenant, webHost, "/admin")
	svc := commandapp.NewService(guardedCommands(db, scopeService(db)), logger.New(logger.Config{Level: "error"}))
	payload := json.RawMessage(`{"scanner":"nuclei","targets":["https://` + webHost + `"],"web_scope":{"deny_paths":["/elsewhere"]}}`)
	if _, err := svc.Create(ctx, commandapp.CreateInput{TenantID: tenant.String(), Type: "scan", Payload: payload}); err != nil {
		t.Fatalf("create: %v", err)
	}
	if got := onlyCommand(t, db, tenant, "scan"); !slices.Equal(got, []string{"/admin"}) {
		t.Fatalf("API command deny_paths = %v, want [/admin] only", got)
	}
}

// allowProbe is an active-probe gate that allows every target.
type allowProbe struct{}

func (allowProbe) ResolveDispatchTargets(_ context.Context, in scansvc.DispatchTargetsInput) (*scansvc.DispatchTargets, error) {
	return &scansvc.DispatchTargets{Allowed: in.Targets}, nil
}

// seedConfinedSensor inserts an active sensor of tenant whose own report
// lists net.confined@1 (sensor v0.19.0 or later, network-confined).
func seedConfinedSensor(t *testing.T, db *sql.DB, tenant shared.ID) {
	t.Helper()
	id := shared.NewID()
	if _, err := db.ExecContext(context.Background(),
		`INSERT INTO sensors (id, tenant_id, name, api_key_hash, api_key_prefix, status, reported_capabilities)
		 VALUES ($1, $2, $3, $4, 'pfx', 'active', $5)`,
		id.String(), tenant.String(), "confined-"+id.String()[:8], "hash-"+id.String(),
		"{"+sensordom.CapabilityNetConfined+"}"); err != nil {
		t.Fatalf("seed confined sensor: %v", err)
	}
}

// SECURITY: a nuclei validation or retest on a host with a path exclusion
// carries its own organization's web scope and requires net.confined@1. It
// is refused (nothing queued) while the organization has no sensor that
// reports the feature, including when only another organization has one;
// once it has one, the job is queued with the scope. On a host without a
// rule it is dispatched unchanged.
func TestWebScope_ValidationAndRetest(t *testing.T) {
	db := openLifecycleDB(t)
	ctx := context.Background()
	tenant := seedLifecycleTenant(ctx, t, db)
	other := seedLifecycleTenant(ctx, t, db)
	seedPathExclusion(t, db, tenant, webHost, "/admin")
	seedConfinedSensor(t, db, other)
	pg := &postgres.DB{DB: db}
	cmds := postgres.NewCommandRepository(pg)
	cmds.SetCreateGuard(integrationGuard(scopesvc.NewWebJobGuard(scopeService(db), postgres.NewSensorRepository(pg))))
	d := validation.NewCommandDispatcher(cmds, allowProbe{}, logger.New(logger.Config{Level: "error"}))

	validate := func(address string) error {
		_, err := d.Dispatch(ctx, validation.ValidationJob{JobID: shared.NewID(), TenantID: tenant, FindingID: shared.NewID(),
			ExecutorKind: validation.KindNuclei, Target: validation.Target{Address: address}, TemplateID: "some-template"})
		return err
	}
	retest := func(address string) error {
		_, err := d.DispatchToolRetest(ctx, validation.ToolRetestJob{TenantID: tenant, FindingID: shared.NewID(), RetestID: shared.NewID(),
			Tool: "nuclei", Target: validation.Target{Address: address}, RuleID: "some-template"})
		return err
	}
	jobs := map[string]func(string) error{"validate": validate, "retest": retest}
	for name, run := range jobs {
		var de *shared.DomainError
		if err := run("https://" + webHost + "/login"); !errors.As(err, &de) || de.Code != scanrundom.FailureNoConfinedSensor {
			t.Fatalf("%s without a capable sensor: err = %v, want %s", name, err, scanrundom.FailureNoConfinedSensor)
		}
		if n := len(commandPayloads(t, db, tenant, name)); n != 0 {
			t.Fatalf("%s: %d command(s) queued for a refused job", name, n)
		}
	}

	seedConfinedSensor(t, db, tenant)
	for name, run := range jobs {
		if err := run("https://" + webHost + "/login"); err != nil {
			t.Fatalf("%s on an excluded-path host with a capable sensor: %v", name, err)
		}
		got := commandPayloads(t, db, tenant, name)
		if len(got) != 1 {
			t.Fatalf("%s: %d command(s) queued, want 1", name, len(got))
		}
		ws, _ := got[0][commanddom.PayloadKeyWebScope].(map[string]any)
		if deny, _ := ws["deny_paths"].([]any); len(deny) != 1 || deny[0] != "/admin" {
			t.Fatalf("%s: web_scope = %v, want deny_paths [/admin]", name, got[0][commanddom.PayloadKeyWebScope])
		}
		if f, _ := got[0][commanddom.PayloadKeyRequiredFeatures].([]any); len(f) != 1 || f[0] != sensordom.CapabilityNetConfined {
			t.Fatalf("%s: required_features = %v, want [%s]", name, f, sensordom.CapabilityNetConfined)
		}

		if err := run("https://other.webscope.example.com/login"); err != nil {
			t.Fatalf("%s on a host without path exclusions: %v", name, err)
		}
		got = commandPayloads(t, db, tenant, name)
		if _, has := got[1][commanddom.PayloadKeyWebScope]; has || got[1][commanddom.PayloadKeyRequiredFeatures] != nil {
			t.Fatalf("%s on a host without a rule carries %v", name, got[1])
		}
	}
}

// SECURITY: tenant isolation. Two organizations exclude different paths on
// the same host: each job carries only its own organization's paths, and an
// organization without a rule gets no web scope.
func TestWebScope_CrossTenant(t *testing.T) {
	db := openLifecycleDB(t)
	ctx := context.Background()
	a := seedLifecycleTenant(ctx, t, db)
	b := seedLifecycleTenant(ctx, t, db)
	c := seedLifecycleTenant(ctx, t, db)
	seedPathExclusion(t, db, a, webHost, "/admin")
	seedPathExclusion(t, db, b, webHost, "/b-private")
	svc := scanServiceOver(db, guardedCommands(db, scopeService(db)))
	for _, tenant := range []shared.ID{a, b, c} {
		if _, err := svc.QuickScan(ctx, scansvc.QuickScanInput{TenantID: tenant.String(), ScannerName: "nuclei",
			Targets: []string{"https://" + webHost}}); err != nil {
			t.Fatalf("quick scan: %v", err)
		}
	}
	if got := onlyCommand(t, db, a, "scan"); !slices.Equal(got, []string{"/admin"}) {
		t.Fatalf("tenant A deny_paths = %v, want [/admin] (B's rule leaked in, or A's is missing)", got)
	}
	if got := onlyCommand(t, db, b, "scan"); !slices.Equal(got, []string{"/b-private"}) {
		t.Fatalf("tenant B deny_paths = %v, want [/b-private]", got)
	}
	if p := commandPayloads(t, db, c, "scan"); len(p) != 1 || p[0][commanddom.PayloadKeyWebScope] != nil {
		t.Fatalf("tenant C (no rule) job = %v, want no web_scope", p)
	}
}

// failingScope is a web scope builder whose lookup fails.
type failingScope struct{}

func (failingScope) BuildWebScope(context.Context, shared.ID, []string) (*scopesvc.WebScope, error) {
	return nil, errors.New("exclusions unavailable")
}

// SECURITY: fail closed. When the exclusions cannot be read, or the guard is
// not wired while the tenant has a path exclusion, a web job is refused and
// nothing is queued; a job without web requests is not affected while the
// guard is wired (unwired, every tool job is refused).
func TestWebScope_FailsClosed(t *testing.T) {
	db := openLifecycleDB(t)
	ctx := context.Background()
	for name, repo := range map[string]*postgres.CommandRepository{
		"lookup error": guardedCommands(db, failingScope{}),
		"unwired":      postgres.NewCommandRepository(&postgres.DB{DB: db}),
	} {
		t.Run(name, func(t *testing.T) {
			tenant := seedLifecycleTenant(ctx, t, db)
			seedPathExclusion(t, db, tenant, webHost, "/admin")
			svc := scanServiceOver(db, repo)
			if _, err := svc.QuickScan(ctx, scansvc.QuickScanInput{TenantID: tenant.String(), ScannerName: "nuclei",
				Targets: []string{"https://" + webHost}}); err == nil {
				t.Fatal("a web job was queued without its web scope")
			}
			if n := len(commandPayloads(t, db, tenant, "scan")); n != 0 {
				t.Fatalf("%d command(s) queued", n)
			}
			// Wired, the organization's catalog says httpx requests no web
			// paths. Unwired, the tool facts are not at hand and any tool
			// job may be a web job: it is refused too (fail closed).
			_, err := svc.QuickScan(ctx, scansvc.QuickScanInput{TenantID: tenant.String(), ScannerName: "httpx",
				Targets: []string{webHost}})
			if name == "unwired" {
				if err == nil {
					t.Fatal("an unguarded tool job was queued for a tenant with a path exclusion")
				}
			} else if err != nil {
				t.Fatalf("a job without web requests was refused: %v", err)
			}
		})
	}
}
