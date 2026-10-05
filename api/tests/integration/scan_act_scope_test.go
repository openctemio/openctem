package integration

// Scan targets limited to the actor (research/15 L-06, owner decision D9),
// on a migrated database with the production checker: a restricted member
// scans only assets in their data scope; an administrator's free-text
// targets must match one of the tenant's own scope targets; a run started
// with nobody in the request acts as the scan owner. Architecture:
// docs/architecture/active-probe-gate.md.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"slices"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/actscope"
	"github.com/openctemio/openctem/api/internal/app/datascope"
	scansvc "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type actCallerKey struct{}

func asCaller(ctx context.Context, c datascope.Caller) context.Context {
	return context.WithValue(ctx, actCallerKey{}, c)
}

// actScopeChecker is the production checker with the caller read from the
// context and the given administrators.
func actScopeChecker(db *sql.DB, admins ...shared.ID) *actscope.Checker {
	pg := &postgres.DB{DB: db}
	enf := datascope.New(postgres.NewDataScopeRepository(pg), func(ctx context.Context) datascope.Caller {
		c, _ := ctx.Value(actCallerKey{}).(datascope.Caller)
		return c
	}, logger.NewNop())
	enf.SetAdminLookup(func(_ context.Context, _, user shared.ID) (bool, error) {
		return slices.ContainsFunc(admins, user.Equals), nil
	})
	return actscope.New(enf, postgres.NewAssetRepository(pg), scopeService(db))
}

func seedScopeTarget(t *testing.T, db *sql.DB, tenant shared.ID, typ, pattern string) {
	t.Helper()
	if _, err := db.ExecContext(context.Background(),
		`INSERT INTO scope_targets (tenant_id, target_type, pattern, status) VALUES ($1, $2, $3, 'active')`,
		tenant.String(), typ, pattern); err != nil {
		t.Fatalf("seed scope target %s: %v", pattern, err)
	}
}

func seedActAsset(t *testing.T, db *sql.DB, tenant shared.ID, name string) shared.ID {
	t.Helper()
	id := shared.NewID()
	if _, err := db.ExecContext(context.Background(),
		`INSERT INTO assets (id, tenant_id, name, asset_type, status) VALUES ($1, $2, $3, 'domain', 'active')`,
		id.String(), tenant.String(), name); err != nil {
		t.Fatalf("seed asset %s: %v", name, err)
	}
	return id
}

func seedActUser(t *testing.T, db *sql.DB) shared.ID {
	t.Helper()
	id := shared.NewID()
	if _, err := db.ExecContext(context.Background(),
		`INSERT INTO users (id, email, name) VALUES ($1, $2, 'act scope')`, id.String(), id.String()+"@act.test"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	t.Cleanup(func() { _, _ = db.ExecContext(context.Background(), `DELETE FROM users WHERE id = $1`, id.String()) })
	return id
}

func grantScope(t *testing.T, db *sql.DB, tenant, user, asset shared.ID) {
	t.Helper()
	if _, err := db.ExecContext(context.Background(),
		`INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type) VALUES ($1, $2, $3, 'secondary')`,
		user.String(), tenant.String(), asset.String()); err != nil {
		t.Fatalf("grant scope: %v", err)
	}
}

func TestScanActScope(t *testing.T) {
	db := openLifecycleDB(t)
	ctx := context.Background()
	tenantA := seedLifecycleTenant(ctx, t, db)
	tenantB := seedLifecycleTenant(ctx, t, db)
	member, admin := seedActUser(t, db), seedActUser(t, db)

	mine := seedActAsset(t, db, tenantA, "mine.example.com")
	seedActAsset(t, db, tenantA, "theirs.example.com")
	seedActAsset(t, db, tenantB, "b-asset.example.com")
	grantScope(t, db, tenantA, member, mine)
	seedScopeTarget(t, db, tenantA, "domain", "*.allowed.example.com")
	seedScopeTarget(t, db, tenantB, "domain", "*.example.org")

	svc := newTriggerServiceWith(db, scansvc.WithScopeExclusionFilter(scopeService(db)),
		scansvc.WithActScope(actScopeChecker(db, admin)))
	asMember := asCaller(ctx, datascope.Caller{UserID: member.String()})
	asAdmin := asCaller(ctx, datascope.Caller{UserID: admin.String(), IsAdmin: true})

	create := func(ctx context.Context, by shared.ID, targets ...string) (*shared.ID, error) {
		sc, err := svc.CreateScan(ctx, scansvc.CreateScanInput{
			TenantID: tenantA.String(), Name: "act scope " + shared.NewID().String(), ScanType: "single",
			ScannerName: "nuclei", Targets: targets, CreatedBy: by.String(), TenantRunner: true,
		})
		if err != nil {
			return nil, err
		}
		return &sc.ID, nil
	}
	refused := func(t *testing.T, err error) {
		t.Helper()
		var de *shared.DomainError
		if !errors.As(err, &de) || de.Code != "TARGET_OUT_OF_SCOPE" {
			t.Fatalf("err = %v, want TARGET_OUT_OF_SCOPE", err)
		}
	}

	t.Run("restricted member", func(t *testing.T) {
		if _, err := create(asMember, member, "mine.example.com"); err != nil {
			t.Fatalf("own asset refused: %v", err)
		}
		for _, target := range []string{"theirs.example.com", "app.allowed.example.com", "b-asset.example.com", "203.0.113.9"} {
			_, err := create(asMember, member, target)
			refused(t, err)
		}
	})

	t.Run("administrator: inventory or own scope targets only", func(t *testing.T) {
		for _, target := range []string{"theirs.example.com", "app.allowed.example.com"} {
			if _, err := create(asAdmin, admin, target); err != nil {
				t.Fatalf("%s refused: %v", target, err)
			}
		}
		// Not an asset and no scope target of tenant A (tenant B's scope
		// target and asset do not count).
		for _, target := range []string{"evil.example.org", "b-asset.example.com", "203.0.113.9"} {
			_, err := create(asAdmin, admin, target)
			refused(t, err)
		}
	})

	t.Run("quick scan", func(t *testing.T) {
		_, err := svc.QuickScan(asMember, scansvc.QuickScanInput{
			TenantID: tenantA.String(), ScannerName: "nuclei", Targets: []string{"theirs.example.com"}, CreatedBy: member.String(),
		})
		refused(t, err)
	})

	t.Run("a scheduled run acts as the scan owner", func(t *testing.T) {
		// An administrator saved a scan of two assets, owned by the member.
		id, err := create(asAdmin, member, "mine.example.com", "theirs.example.com")
		if err != nil {
			t.Fatalf("create: %v", err)
		}
		if _, err := svc.TriggerScan(ctx, scansvc.TriggerScanExecInput{TenantID: tenantA.String(), ScanID: id.String()}); err != nil {
			t.Fatalf("trigger: %v", err)
		}
		var payload []byte
		if err := db.QueryRowContext(ctx, `SELECT payload FROM commands WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT 1`,
			tenantA.String()).Scan(&payload); err != nil {
			t.Fatalf("read command: %v", err)
		}
		var p struct {
			Targets []string `json:"targets"`
		}
		_ = json.Unmarshal(payload, &p)
		if !slices.Equal(p.Targets, []string{"mine.example.com"}) {
			t.Fatalf("command targets = %v, want only the owner's asset", p.Targets)
		}

		// The owner losing the asset: the next run has nothing to scan.
		if _, err := db.ExecContext(ctx, `DELETE FROM user_accessible_assets WHERE user_id = $1`, member.String()); err != nil {
			t.Fatal(err)
		}
		grantScope(t, db, tenantA, member, seedActAsset(t, db, tenantA, "other.example.com"))
		if _, err := svc.TriggerScan(ctx, scansvc.TriggerScanExecInput{TenantID: tenantA.String(), ScanID: id.String()}); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("run with nothing in the owner's scope: err = %v, want a refusal", err)
		}
	})
}
