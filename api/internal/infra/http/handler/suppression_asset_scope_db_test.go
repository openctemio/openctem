package handler

// Suppression rules against real Postgres: an asset-bound rule (which
// auto-closes that asset's findings) must name a live asset of the caller's
// tenant that the caller may see. suppression_rules.asset_id references
// assets(id) without the tenant. Research doc 21b M-10, RFC-050 W8.

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/app/datascope"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/suppression"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func TestSuppressionRule_AssetTenantAndScope_DB(t *testing.T) {
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
		exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'sup', $2)`, tn, "sup-"+tn)
	}
	t.Cleanup(func() {
		bg := context.Background()
		for _, tn := range []string{tenantA, tenantB} {
			_, _ = raw.ExecContext(bg, `DELETE FROM suppression_rules WHERE tenant_id = $1`, tn)
			_, _ = raw.ExecContext(bg, `DELETE FROM tenants WHERE id = $1`, tn)
		}
		for _, u := range []string{admin, scoped} {
			_, _ = raw.ExecContext(bg, `DELETE FROM users WHERE id = $1`, u)
		}
	})
	for _, u := range []string{admin, scoped} {
		exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, 'sup')`, u, u+"@sup.test")
	}
	for id, tn := range map[string]string{inScope: tenantA, outScope: tenantA, foreign: tenantB} {
		exec(`INSERT INTO assets (id, tenant_id, name, asset_type, exposure, criticality) VALUES ($1, $2, $3, 'domain', 'public', 'high')`,
			id, tn, "sup-"+id+".example.com")
	}
	exec(`INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type) VALUES ($1, $2, $3, 'secondary')`,
		scoped, tenantA, inScope)

	db := &postgres.DB{DB: raw}
	enforcer := datascope.New(postgres.NewDataScopeRepository(db),
		func(ctx context.Context) datascope.Caller {
			return datascope.Caller{UserID: middleware.GetUserID(ctx), IsAdmin: middleware.IsAdmin(ctx)}
		}, logger.NewNop())
	svc := suppression.NewService(postgres.NewSuppressionRepository(db), logger.NewNop())
	svc.SetAssetRefChecker(enforcer)

	tid := shared.MustIDFromString(tenantA)
	create := func(user string, isAdmin bool, asset string) error {
		c := context.WithValue(ctx, middleware.UserIDKey, user)
		c = context.WithValue(c, middleware.IsAdminKey, isAdmin)
		aid := shared.MustIDFromString(asset)
		_, err := svc.CreateRule(c, suppression.CreateRuleInput{
			TenantID: tid, Name: "sup " + shared.NewID().String(), SuppressionType: suppression.SuppressionTypeFalsePositive,
			ToolName: "semgrep", AssetID: &aid, RequestedBy: shared.MustIDFromString(user),
		})
		return err
	}
	for name, err := range map[string]error{
		"admin, another tenant's asset":       create(admin, true, foreign),
		"admin, unknown asset":                create(admin, true, shared.NewID().String()),
		"restricted member, out-of-scope one": create(scoped, false, outScope),
	} {
		if !errors.Is(err, suppression.ErrRuleAssetNotFound) {
			t.Errorf("%s: err = %v, want ErrRuleAssetNotFound", name, err)
		}
	}
	if err := create(scoped, false, inScope); err != nil {
		t.Errorf("restricted member, in-scope asset: %v", err)
	}
	if err := create(admin, true, outScope); err != nil {
		t.Errorf("admin, own-tenant asset: %v", err)
	}
	var stray int
	_ = raw.QueryRowContext(ctx, `SELECT COUNT(*) FROM suppression_rules WHERE asset_id = $1`, foreign).Scan(&stray)
	if stray != 0 {
		t.Errorf("%d rule(s) stored on another tenant's asset", stray)
	}
}
