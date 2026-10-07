package handler

// Attack simulations against real Postgres: a simulation's target assets
// follow the scan act-scope rule at create, update and run (research doc 21b
// H4, RFC-050 W3). Before, any member with validation:write could point a
// simulation (a live safe-check probe) at an asset outside their data scope,
// or at another tenant's asset.

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/app/actscope"
	"github.com/openctemio/openctem/api/internal/app/compliance"
	"github.com/openctemio/openctem/api/internal/app/datascope"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type noScopeTargets struct{}

func (noScopeTargets) ListActiveTargets(context.Context, string) ([]*scopedom.Target, error) {
	return nil, nil
}

func TestSimulationTargets_ActScope_DB(t *testing.T) {
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping DB-backed test")
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
	admin, scoped := shared.NewID().String(), shared.NewID().String()
	inScope, outScope, foreign := shared.NewID().String(), shared.NewID().String(), shared.NewID().String()
	for _, tn := range []string{tenantA, tenantB} {
		exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'sim', $2)`, tn, "sim-"+tn)
	}
	t.Cleanup(func() {
		bg := context.Background()
		for _, tn := range []string{tenantA, tenantB} {
			_, _ = raw.ExecContext(bg, `DELETE FROM attack_simulations WHERE tenant_id = $1`, tn)
			_, _ = raw.ExecContext(bg, `DELETE FROM tenants WHERE id = $1`, tn)
		}
		for _, u := range []string{admin, scoped} {
			_, _ = raw.ExecContext(bg, `DELETE FROM users WHERE id = $1`, u)
		}
	})
	for _, u := range []string{admin, scoped} {
		exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, 'sim')`, u, u+"@sim.test")
	}
	for id, tn := range map[string]string{inScope: tenantA, outScope: tenantA, foreign: tenantB} {
		exec(`INSERT INTO assets (id, tenant_id, name, asset_type, exposure, criticality) VALUES ($1, $2, $3, 'domain', 'public', 'high')`,
			id, tn, "sim-"+id+".example.com")
	}
	exec(`INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type) VALUES ($1, $2, $3, 'secondary')`,
		scoped, tenantA, inScope)

	db := &postgres.DB{DB: raw}
	enforcer := datascope.New(postgres.NewDataScopeRepository(db),
		func(ctx context.Context) datascope.Caller {
			return datascope.Caller{UserID: middleware.GetUserID(ctx), IsAdmin: middleware.IsAdmin(ctx)}
		}, logger.NewNop())
	svc := compliance.NewSimulationService(postgres.NewSimulationRepository(db), postgres.NewControlTestRepository(db), logger.NewNop())
	svc.SetActScope(actscope.New(enforcer, postgres.NewAssetRepository(db), noScopeTargets{}, postgres.NewEASMSeedRepository(db)), enforcer)

	as := func(user string, isAdmin bool) context.Context {
		c := context.WithValue(ctx, middleware.UserIDKey, user)
		return context.WithValue(c, middleware.IsAdminKey, isAdmin)
	}
	create := func(user string, isAdmin bool, target string) (string, error) {
		sim, err := svc.CreateSimulation(as(user, isAdmin), compliance.CreateSimulationInput{
			TenantID: tenantA, Name: "sim " + shared.NewID().String(), SimulationType: "atomic",
			MitreTechniqueID: "T1046", TargetAssets: []string{target}, ActorID: user,
		})
		if err != nil {
			return "", err
		}
		return sim.ID().String(), nil
	}
	notFound := func(name string, err error) {
		t.Helper()
		if !errors.Is(err, compliance.ErrSimulationTargetNotFound) {
			t.Errorf("%s: err = %v, want ErrSimulationTargetNotFound", name, err)
		}
	}

	_, err = create(scoped, false, outScope)
	notFound("restricted member, out-of-scope asset", err)
	_, err = create(admin, true, foreign)
	notFound("admin, another tenant's asset", err)
	_, err = create(admin, true, shared.NewID().String())
	notFound("admin, unknown asset id", err)

	simID, err := create(scoped, false, inScope)
	if err != nil {
		t.Fatalf("restricted member, in-scope asset: %v", err)
	}
	if _, err := svc.UpdateSimulation(as(scoped, false), compliance.UpdateSimulationInput{
		TenantID: tenantA, SimulationID: simID, Name: "moved", TargetAssets: []string{outScope}, ActorID: scoped,
	}); !errors.Is(err, compliance.ErrSimulationTargetNotFound) {
		t.Errorf("update to an out-of-scope target: err = %v, want refused", err)
	}

	exec(`UPDATE attack_simulations SET status = 'active' WHERE id = $1 AND tenant_id = $2`, simID, tenantA)
	if _, err := svc.RunSimulation(as(scoped, false), tenantA, simID, scoped); err != nil {
		t.Fatalf("run while in scope: %v", err)
	}
	// The member loses the asset: the saved simulation no longer runs for them.
	exec(`DELETE FROM user_accessible_assets WHERE user_id = $1 AND tenant_id = $2`, scoped, tenantA)
	_, err = svc.RunSimulation(as(scoped, false), tenantA, simID, scoped)
	notFound("run after the scope shrank", err)
}
