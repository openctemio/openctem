package integration

// A pipeline run's asset_id against a migrated database (research doc 21b,
// C4): it is stored on the run and copied into every step command, and
// pipeline_runs.asset_id references assets(id) without the tenant. It must be
// a live asset of the run's tenant that the caller may see; a foreign,
// unknown, deleted or out-of-scope id is refused identically and nothing is
// created.

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/datascope"
	pipelinesvc "github.com/openctemio/openctem/api/internal/app/pipeline"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func TestPipelineRun_AssetMustBeTheCallersInTheTenant(t *testing.T) {
	db := openLifecycleDB(t)
	ctx := context.Background()
	tenant := seedLifecycleTenant(ctx, t, db)
	other := seedLifecycleTenant(ctx, t, db)
	pg := &postgres.DB{DB: db}

	templateID := shared.NewID()
	if _, err := db.ExecContext(ctx,
		`INSERT INTO pipeline_templates (id, tenant_id, name, description, is_active) VALUES ($1, $2, 'asset ref test', '', TRUE)`,
		templateID.String(), tenant.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx,
		`INSERT INTO pipeline_steps (id, pipeline_id, step_key, name, description, step_order, tool) VALUES ($1, $2, 'scan', 'Scan', '', 1, 'nuclei')`,
		shared.NewID().String(), templateID.String()); err != nil {
		t.Fatal(err)
	}

	inScope := seedActAsset(t, db, tenant, "in.pra.example.com")
	outScope := seedActAsset(t, db, tenant, "out.pra.example.com")
	deleted := seedActAsset(t, db, tenant, "gone.pra.example.com")
	foreign := seedActAsset(t, db, other, "foreign.pra.example.com")
	if _, err := db.ExecContext(ctx, `UPDATE assets SET deleted_at = now() WHERE id = $1`, deleted.String()); err != nil {
		t.Fatal(err)
	}
	member := seedActUser(t, db)
	grantScope(t, db, tenant, member, inScope)

	enf := datascope.New(postgres.NewDataScopeRepository(pg), nil, func(ctx context.Context) datascope.Caller {
		c, _ := ctx.Value(actCallerKey{}).(datascope.Caller)
		return c
	}, logger.NewNop())
	svc := pipelinesvc.NewService(
		postgres.NewPipelineTemplateRepository(pg), postgres.NewPipelineStepRepository(pg),
		postgres.NewPipelineRunRepository(pg), postgres.NewStepRunRepository(pg),
		postgres.NewSensorRepository(pg), postgres.NewCommandRepository(pg),
		nil, logger.New(logger.Config{Level: "error"}),
		pipelinesvc.WithAssetRefChecker(enf),
	)
	admin := datascope.Caller{UserID: shared.NewID().String(), IsAdmin: true}
	restricted := datascope.Caller{UserID: member.String()}
	trigger := func(c datascope.Caller, assetID string) error {
		_, err := svc.TriggerPipeline(asCaller(ctx, c), pipelinesvc.TriggerPipelineInput{
			TenantID: tenant.String(), TemplateID: templateID.String(), AssetID: assetID,
			TriggerType: "manual", TriggeredBy: c.UserID,
		})
		return err
	}

	// Refused: identical error for foreign (even for an admin and for a
	// workflow trigger with no user), unknown, deleted and out-of-scope ids.
	refused := map[string]struct {
		caller datascope.Caller
		asset  shared.ID
	}{
		"admin, tenant B asset":      {admin, foreign},
		"workflow, tenant B asset":   {datascope.Caller{}, foreign},
		"admin, unknown asset":       {admin, shared.NewID()},
		"admin, deleted asset":       {admin, deleted},
		"restricted, out of scope":   {restricted, outScope},
		"restricted, tenant B asset": {restricted, foreign},
	}
	var first string
	for name, tc := range refused {
		err := trigger(tc.caller, tc.asset.String())
		if !errors.Is(err, pipelinesvc.ErrRunAssetNotFound) {
			t.Errorf("%s: err = %v, want ErrRunAssetNotFound", name, err)
			continue
		}
		if first == "" {
			first = err.Error()
		} else if err.Error() != first {
			t.Errorf("%s: error %q differs from %q (no existence oracle)", name, err, first)
		}
	}
	if err := trigger(admin, "not-a-uuid"); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("malformed asset id: err = %v, want a validation error (it used to be dropped silently)", err)
	}
	if n := countRows(t, db, `SELECT COUNT(*) FROM pipeline_runs WHERE tenant_id = $1`, tenant); n != 0 {
		t.Fatalf("%d run(s) created for refused triggers", n)
	}
	if n := countRows(t, db, `SELECT COUNT(*) FROM commands WHERE tenant_id = $1`, tenant); n != 0 {
		t.Fatalf("%d command(s) created for refused triggers", n)
	}

	// Allowed: an in-scope asset for the restricted member, any own asset
	// for an admin.
	if err := trigger(restricted, inScope.String()); err != nil {
		t.Errorf("restricted, in scope: %v", err)
	}
	if err := trigger(admin, outScope.String()); err != nil {
		t.Errorf("admin, own tenant: %v", err)
	}
	if n := countRows(t, db, `SELECT COUNT(*) FROM pipeline_runs WHERE tenant_id = $1`, tenant); n != 2 {
		t.Errorf("%d run(s), want 2", n)
	}
	var stray int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM pipeline_runs WHERE asset_id = ANY($1::uuid[])`,
		"{"+foreign.String()+","+deleted.String()+"}").Scan(&stray); err != nil {
		t.Fatal(err)
	}
	if stray != 0 {
		t.Errorf("%d run(s) on a foreign or deleted asset", stray)
	}

	// Unwired: a run with an asset id is refused (fail closed).
	bare := pipelinesvc.NewService(
		postgres.NewPipelineTemplateRepository(pg), postgres.NewPipelineStepRepository(pg),
		postgres.NewPipelineRunRepository(pg), postgres.NewStepRunRepository(pg),
		postgres.NewSensorRepository(pg), postgres.NewCommandRepository(pg),
		nil, logger.New(logger.Config{Level: "error"}),
	)
	if _, err := bare.TriggerPipeline(asCaller(ctx, admin), pipelinesvc.TriggerPipelineInput{
		TenantID: tenant.String(), TemplateID: templateID.String(), AssetID: inScope.String(), TriggerType: "manual",
	}); !errors.Is(err, pipelinesvc.ErrRunAssetNotFound) {
		t.Errorf("unwired checker: err = %v, want ErrRunAssetNotFound", err)
	}
}
