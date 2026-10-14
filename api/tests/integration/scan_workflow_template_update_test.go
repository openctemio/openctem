package integration

// Template updates for tenant copies of system scan workflows, on a real
// database: a copy keeps its lineage, a later template change is offered
// (never applied on its own), applying it is audited and changes only the
// tenant's own copy, and another tenant can neither see nor apply it.

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/scanrun"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type tplUpdateAudit struct {
	mu     sync.Mutex
	events []scanrun.AuditEvent
	actx   []scanrun.AuditContext
}

func (r *tplUpdateAudit) LogEvent(_ context.Context, actx scanrun.AuditContext, e scanrun.AuditEvent) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
	r.actx = append(r.actx, actx)
	return nil
}

func TestScanWorkflowTemplateUpdate(t *testing.T) {
	db := setupTestDB(t)
	t.Cleanup(func() { db.Close() })
	ctx := context.Background()
	tenantA := createTestTenant(t, db, "tpl-update-a")
	tenantB := createTestTenant(t, db, "tpl-update-b")
	tpl := shared.NewID()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		for _, tn := range []shared.ID{tenantA, tenantB} {
			_, _ = db.Exec(`DELETE FROM scan_workflows WHERE tenant_id=$1`, tn.String())
			_, _ = db.Exec(`DELETE FROM tenants WHERE id=$1`, tn.String())
		}
		_, _ = db.Exec(`DELETE FROM scan_workflows WHERE id=$1`, tpl.String())
	})

	// A system template like Network before it gained Host discovery.
	exec(`INSERT INTO scan_workflows (id, tenant_id, name, description, is_system_template) VALUES ($1, '00000000-0000-0000-0000-000000000000', $2, 'test template', true)`,
		tpl.String(), "tpl-update-"+tpl.String()[:8])
	exec(`INSERT INTO scan_workflow_steps (scan_workflow_id, step_key, name, step_order, capabilities, depends_on, condition_type)
	      VALUES ($1, 'ports', 'Port scan', 1, '{scan.ports}', '{}', 'always'),
	             ($1, 'http', 'HTTP probe', 2, '{probe.http}', '{ports}', 'always')`, tpl.String())

	pg := &postgres.DB{DB: db}
	repo := postgres.NewScanWorkflowRepository(pg)
	audit := &tplUpdateAudit{}
	svc := scanrun.NewService(repo, postgres.NewScanWorkflowStepRepository(pg), postgres.NewScanRunRepository(pg),
		postgres.NewStepRunRepository(pg), nil, postgres.NewCommandRepository(pg), acceptingStepValidator{},
		logger.New(logger.Config{Level: "error"}),
		scanrun.WithDraftStore(repo), scanrun.WithVersionStore(repo), scanrun.WithAuditService(audit), scanrun.WithToolFacts(integrationTools))
	svc.SetTemplateLineage(repo)

	clone := func(tenant shared.ID, name string) *scanworkflow.Workflow {
		t.Helper()
		w, err := svc.CloneTemplate(ctx, scanrun.CloneTemplateInput{TenantID: tenant.String(), TemplateID: tpl.String(), NewName: name})
		if err != nil {
			t.Fatal(err)
		}
		return w
	}
	copyA := clone(tenantA, "net-a")
	dismissA := clone(tenantA, "net-a-keep")
	copyB := clone(tenantB, "net-b")

	// Nothing changed yet: nothing offered.
	if v, err := svc.GetTemplateUpdate(ctx, tenantA.String(), copyA.ID.String()); err != nil || v != nil {
		t.Fatalf("before the change: %+v %v", v, err)
	}

	// The template gains Host discovery and the port scan depends on it.
	exec(`INSERT INTO scan_workflow_steps (scan_workflow_id, step_key, name, step_order, capabilities, depends_on, condition_type)
	      VALUES ($1, 'hosts', 'Host discovery', 0, '{discover.hosts}', '{}', 'always')`, tpl.String())
	exec(`UPDATE scan_workflow_steps SET depends_on = '{hosts}' WHERE scan_workflow_id = $1 AND step_key = 'ports'`, tpl.String())

	keys := func(id shared.ID) map[string][]string {
		t.Helper()
		w, err := repo.GetWithSteps(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string][]string{}
		for _, s := range w.Steps {
			out[s.StepKey] = s.DependsOn
		}
		return out
	}
	// Never modified on its own.
	if k := keys(copyA.ID); len(k) != 2 {
		t.Fatalf("copy changed without a person: %v", k)
	}

	v, err := svc.GetTemplateUpdate(ctx, tenantA.String(), copyA.ID.String())
	if err != nil || v == nil {
		t.Fatalf("update: %+v %v", v, err)
	}
	var got []string
	for _, c := range v.Changes {
		got = append(got, c.Kind+":"+c.StepKey)
	}
	if !slices.Equal(got, []string{"add_step:hosts", "depends_on:ports"}) {
		t.Fatalf("changes = %v", got)
	}

	// Another tenant can neither see nor apply tenant A's update.
	if _, err := svc.GetTemplateUpdate(ctx, tenantB.String(), copyA.ID.String()); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("tenant B read tenant A's update: %v", err)
	}
	if _, err := svc.ApplyTemplateUpdate(ctx, tenantB.String(), copyA.ID.String(), v.TemplateDigest); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("tenant B applied tenant A's update: %v", err)
	}
	if err := svc.DismissTemplateUpdate(ctx, tenantB.String(), copyA.ID.String(), v.TemplateDigest); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("tenant B dismissed tenant A's update: %v", err)
	}
	// The system template itself is not a copy.
	if _, err := svc.ApplyTemplateUpdate(ctx, tenantA.String(), tpl.String(), v.TemplateDigest); err == nil {
		t.Fatal("applied to the system template")
	}
	// A stale preview is refused.
	if _, err := svc.ApplyTemplateUpdate(ctx, tenantA.String(), copyA.ID.String(), "stale"); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale digest: %v", err)
	}
	if k := keys(copyA.ID); len(k) != 2 {
		t.Fatalf("a refused apply changed the copy: %v", k)
	}

	applied, err := svc.ApplyTemplateUpdate(ctx, tenantA.String(), copyA.ID.String(), v.TemplateDigest)
	if err != nil {
		t.Fatal(err)
	}
	if applied.Version != copyA.Version+1 {
		t.Errorf("version = %d, want %d", applied.Version, copyA.Version+1)
	}
	k := keys(copyA.ID)
	if _, ok := k["hosts"]; !ok || !slices.Equal(k["ports"], []string{"hosts"}) || !slices.Equal(k["http"], []string{"ports"}) {
		t.Fatalf("applied steps = %v", k)
	}
	if v2, err := svc.GetTemplateUpdate(ctx, tenantA.String(), copyA.ID.String()); err != nil || v2 != nil {
		t.Fatalf("after apply: %+v %v", v2, err)
	}
	// Tenant B's copy and tenant A's other copy are untouched.
	if k := keys(copyB.ID); len(k) != 2 {
		t.Fatalf("tenant B's copy changed: %v", k)
	}
	if k := keys(dismissA.ID); len(k) != 2 {
		t.Fatalf("the other copy changed: %v", k)
	}

	// Audited, in tenant A, with what changed.
	var found bool
	for i, e := range audit.events {
		if e.Metadata["template_update"] == "applied" {
			found = true
			if audit.actx[i].TenantID != tenantA.String() || e.ResourceID != copyA.ID.String() {
				t.Errorf("audit = %+v %+v", audit.actx[i], e)
			}
		}
	}
	if !found {
		t.Fatal("apply not audited")
	}

	// Dismissing keeps the copy and stops the offer.
	v3, err := svc.GetTemplateUpdate(ctx, tenantA.String(), dismissA.ID.String())
	if err != nil || v3 == nil {
		t.Fatalf("dismiss copy update: %+v %v", v3, err)
	}
	if err := svc.DismissTemplateUpdate(ctx, tenantA.String(), dismissA.ID.String(), v3.TemplateDigest); err != nil {
		t.Fatal(err)
	}
	if k := keys(dismissA.ID); len(k) != 2 {
		t.Fatalf("dismiss changed the copy: %v", k)
	}
	if v4, err := svc.GetTemplateUpdate(ctx, tenantA.String(), dismissA.ID.String()); err != nil || v4 != nil {
		t.Fatalf("after dismiss: %+v %v", v4, err)
	}
}
