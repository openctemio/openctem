package integration

// Inventory first, scope later (research/124, RFC-054 §15): a discovered
// asset is in the inventory, and that grants nothing. Every path that
// dispatches active work (an API-created scan, a quick scan, a triggered
// scan as automation and schedules trigger it, a workflow step, the hop
// gate) refuses a discovered asset no scope entry covers and an excluded
// one, and lets a covered one through. Another tenant's entries never
// authorize anything.

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"testing"

	scansvc "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/internal/app/scanrun"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func TestScanGate_InventoryFirst(t *testing.T) {
	db := openLifecycleDB(t)
	ctx := context.Background()
	tenantA := seedLifecycleTenant(ctx, t, db)
	tenantB := seedLifecycleTenant(ctx, t, db)

	seedScopeTarget(t, db, tenantA, "domain", "*.inscope.example.com")
	seedApprovedExclusion(t, db, tenantA, "domain", "skip.inscope.example.com")
	// Tenant B's entry covers the name tenant A only discovered.
	seedScopeTarget(t, db, tenantB, "domain", "*.thirdparty.example.net")

	discovered := func(tenant shared.ID, name, typ string) shared.ID {
		id := seedOwnedAsset(t, db, tenant, name, typ)
		automatic(t, db, tenant, id, attribution.StateDiscovered)
		return id
	}
	const (
		uncovered = "cname-target.thirdparty.example.net"
		covered   = "api.inscope.example.com"
		excluded  = "skip.inscope.example.com"
	)
	discovered(tenantA, uncovered, "domain")
	discovered(tenantA, covered, "subdomain")
	discovered(tenantA, excluded, "subdomain")

	svc := newTriggerServiceWith(db, scansvc.WithScopeExclusionFilter(scopeService(db)),
		scansvc.WithAttributionGate(ownershipGate(db)))
	create := func(target string) error {
		_, err := svc.CreateScan(ctx, scansvc.CreateScanInput{
			TenantID: tenantA.String(), Name: "inv " + shared.NewID().String(), ScanType: "single",
			ScannerName: "nuclei", Targets: []string{target}, TenantRunner: true,
		})
		return err
	}
	refusalCode := func(err error) string {
		var de *shared.DomainError
		if !errors.As(err, &de) {
			return ""
		}
		details, _ := de.Details.(map[string]any)
		list, _ := details["refused"].([]scopedom.Refusal)
		if len(list) == 0 {
			return de.Code
		}
		return list[0].Code
	}

	t.Run("api-created scan", func(t *testing.T) {
		if err := create(covered); err != nil {
			t.Fatalf("covered discovered refused: %v", err)
		}
		if code := refusalCode(create(uncovered)); code != scopedom.RefusalNoEntry {
			t.Fatalf("uncovered discovered: code %q, want no_entry", code)
		}
	})

	t.Run("quick scan", func(t *testing.T) {
		before := countCommands(t, db, tenantA)
		_, err := svc.QuickScan(ctx, scansvc.QuickScanInput{TenantID: tenantA.String(), ScannerName: "nuclei", Targets: []string{uncovered}})
		if err == nil {
			t.Fatal("quick scan of an uncovered discovered asset accepted")
		}
		if countCommands(t, db, tenantA) != before || commandsNaming(t, db, tenantA, uncovered) != 0 {
			t.Fatal("quick scan dispatched a command")
		}
	})

	t.Run("triggered scan (automation, schedule)", func(t *testing.T) {
		// Saved while an entry covered it; the entry then went away.
		seedScopeTarget(t, db, tenantA, "domain", "later.example.org")
		discovered(tenantA, "later.example.org", "domain")
		sc, err := svc.CreateScan(ctx, scansvc.CreateScanInput{TenantID: tenantA.String(), Name: "saved inv",
			ScanType: "single", ScannerName: "nuclei", Targets: []string{"later.example.org"}, TenantRunner: true})
		if err != nil {
			t.Fatalf("create: %v", err)
		}
		if _, err := db.ExecContext(ctx, `UPDATE scope_targets SET status = 'inactive' WHERE tenant_id = $1 AND pattern = 'later.example.org'`, tenantA.String()); err != nil {
			t.Fatal(err)
		}
		_, _ = svc.TriggerScan(ctx, scansvc.TriggerScanExecInput{TenantID: tenantA.String(), ScanID: sc.ID.String(), TriggerType: "automation"})
		if n := commandsNaming(t, db, tenantA, "later.example.org"); n != 0 {
			t.Fatalf("triggered scan dispatched an uncovered discovered asset (%d commands)", n)
		}
	})

	t.Run("workflow step", func(t *testing.T) {
		templateID := shared.NewID()
		if _, err := db.ExecContext(ctx,
			`INSERT INTO scan_workflows (id, tenant_id, name, description, is_active) VALUES ($1, $2, 'inv first', '', TRUE)`,
			templateID.String(), tenantA.String()); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx,
			`INSERT INTO scan_workflow_steps (id, scan_workflow_id, step_key, name, description, step_order, tool) VALUES ($1, $2, 'templates', 'Templates', '', 1, 'nuclei')`,
			shared.NewID().String(), templateID.String()); err != nil {
			t.Fatal(err)
		}
		pg := &postgres.DB{DB: db}
		runs := scanrun.NewService(
			postgres.NewScanWorkflowRepository(pg), postgres.NewScanWorkflowStepRepository(pg),
			postgres.NewScanRunRepository(pg), postgres.NewStepRunRepository(pg),
			postgres.NewSensorRepository(pg), postgres.NewCommandRepository(pg), nil, logger.New(logger.Config{Level: "error"}),
			scanrun.WithTargetGate(svc), scanrun.WithToolFacts(integrationTools),
		)
		// Typed targets an active step may not take refuse the request.
		before := countCommands(t, db, tenantA)
		for _, target := range []string{uncovered} {
			if _, err := runs.TriggerPipeline(ctx, scanrun.TriggerRunInput{TenantID: tenantA.String(), TemplateID: templateID.String(),
				TriggerType: "api", Context: map[string]any{"targets": []any{target, covered}}}); err == nil {
				t.Fatalf("workflow with %s accepted", target)
			}
		}
		if countCommands(t, db, tenantA) != before {
			t.Fatal("a refused workflow dispatched a command")
		}
		// An excluded target is dropped; the covered one runs.
		if _, err := runs.TriggerPipeline(ctx, scanrun.TriggerRunInput{TenantID: tenantA.String(), TemplateID: templateID.String(),
			TriggerType: "api", Context: map[string]any{"targets": []any{excluded, covered}}}); err != nil {
			t.Fatalf("trigger: %v", err)
		}
		if got := lastCommandTargets(t, db, tenantA); !slices.Equal(got, []string{covered}) {
			t.Fatalf("workflow step targets = %v, want only %s", got, covered)
		}
		for _, n := range []string{uncovered, excluded} {
			if commandsNaming(t, db, tenantA, n) != 0 {
				t.Fatalf("workflow dispatched %s", n)
			}
		}
	})

	t.Run("hop gate", func(t *testing.T) {
		in := scansvc.DispatchTargetsInput{TenantID: tenantA, Targets: []string{uncovered, covered, excluded}}
		active, err := svc.ResolveDispatchTargets(ctx, in)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(active.Allowed, []string{covered}) {
			t.Fatalf("active hop allowed %v, want only %s", active.Allowed, covered)
		}
		if !slices.Contains(active.Excluded, excluded) {
			t.Fatalf("exclusion did not win: %+v", active)
		}
		in.PassiveOnly = true
		passive, err := svc.ResolveDispatchTargets(ctx, in)
		if err != nil {
			t.Fatal(err)
		}
		// A passive step of a chain sends no traffic to a name no entry
		// covers either; an excluded name never passes.
		if slices.Contains(passive.Allowed, uncovered) || slices.Contains(passive.Allowed, excluded) {
			t.Fatalf("passive hop: %+v", passive)
		}
	})

	t.Run("cross-tenant", func(t *testing.T) {
		// Tenant B's entry covers the name for B only.
		b, err := ownershipGate(db).BlockedTargets(ctx, tenantA, []string{uncovered})
		if err != nil {
			t.Fatal(err)
		}
		if b[uncovered] != attribution.StateDiscovered {
			t.Fatalf("tenant B's entry reached tenant A: %v", b)
		}
		// Tenant A's entries authorize nothing for B.
		b, err = ownershipGate(db).BlockedTargets(ctx, tenantB, []string{covered})
		if err != nil {
			t.Fatal(err)
		}
		if b[covered] != attribution.StateUnattributed {
			t.Fatalf("tenant A's entry reached tenant B: %v", b)
		}
	})
}

func countCommands(t *testing.T, db *sql.DB, tenant shared.ID) int {
	t.Helper()
	var n int
	if err := db.QueryRowContext(context.Background(), `SELECT count(*) FROM commands WHERE tenant_id = $1`, tenant.String()).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// commandsNaming counts the tenant's commands whose payload names target.
func commandsNaming(t *testing.T, db *sql.DB, tenant shared.ID, target string) int {
	t.Helper()
	var n int
	if err := db.QueryRowContext(context.Background(),
		`SELECT count(*) FROM commands WHERE tenant_id = $1 AND strpos(payload::text, $2) > 0`, tenant.String(), target).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}
