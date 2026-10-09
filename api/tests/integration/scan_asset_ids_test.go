package integration

// POST /scans asset_ids on a migrated database with the production act-scope
// checker and asset naming: a restricted member scans their own asset by id
// (the server names it); an asset outside their data scope, another
// tenant's asset or an unknown id refuses the whole create with one answer.

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/datascope"
	scansvc "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ownedWithNames lets every target through the ownership gate (as
// allowAllTargetChecks does) but names assets with the production gate.
type ownedWithNames struct {
	allOwned
	names scansvc.AssetTargetResolver
}

func (g ownedWithNames) AssetTargets(ctx context.Context, tenantID shared.ID, ids []shared.ID) (map[shared.ID][]string, error) {
	return g.names.AssetTargets(ctx, tenantID, ids)
}

func TestScanCreate_AssetIDs(t *testing.T) {
	db := openLifecycleDB(t)
	ctx := context.Background()
	tenantA := seedLifecycleTenant(ctx, t, db)
	tenantB := seedLifecycleTenant(ctx, t, db)
	member, admin := seedActUser(t, db), seedActUser(t, db)

	mine := seedActAsset(t, db, tenantA, "mine-ids.example.com")
	theirs := seedActAsset(t, db, tenantA, "theirs-ids.example.com")
	foreign := seedActAsset(t, db, tenantB, "b-ids.example.com")
	grantScope(t, db, tenantA, member, mine)

	svc := newTriggerServiceWith(db,
		scansvc.WithActScope(actScopeChecker(db, admin)),
		scansvc.WithAttributionGate(ownedWithNames{names: ownershipGate(db)}))
	asMember := asCaller(ctx, datascope.Caller{UserID: member.String()})
	asAdmin := asCaller(ctx, datascope.Caller{UserID: admin.String(), IsAdmin: true})

	create := func(ctx context.Context, by shared.ID, typed []string, ids ...shared.ID) ([]string, error) {
		raw := make([]string, 0, len(ids))
		for _, id := range ids {
			raw = append(raw, id.String())
		}
		sc, err := svc.CreateScan(ctx, scansvc.CreateScanInput{
			TenantID: tenantA.String(), Name: "asset ids " + shared.NewID().String(), ScanType: "single",
			ScannerName: "nuclei", Targets: typed, AssetIDs: raw, CreatedBy: by.String(), TenantRunner: true,
		})
		if err != nil {
			return nil, err
		}
		stored, err := postgres.NewScanRepository(&postgres.DB{DB: db}).GetByTenantAndID(ctx, tenantA, sc.ID)
		if err != nil {
			t.Fatal(err)
		}
		return stored.Targets, nil
	}
	unavailable := func(t *testing.T, err error) {
		t.Helper()
		if !errors.Is(err, shared.ErrValidation) || err == nil {
			t.Fatalf("err = %v, want the validation refusal", err)
		}
	}

	t.Run("member scans their asset by id, named by the server", func(t *testing.T) {
		got, err := create(asMember, member, nil, mine)
		if err != nil {
			t.Fatalf("own asset refused: %v", err)
		}
		if len(got) != 1 || got[0] != "mine-ids.example.com" {
			t.Fatalf("stored targets %v, want the asset name", got)
		}
		// Typed and by id, the same name is stored once.
		got, err = create(asMember, member, []string{"MINE-ids.example.com"}, mine)
		if err != nil || len(got) != 1 {
			t.Fatalf("typed + id: %v %v", got, err)
		}
	})

	t.Run("member: an asset outside their scope, another tenant's or unknown refuses", func(t *testing.T) {
		for name, id := range map[string]shared.ID{"outside scope": theirs, "other tenant": foreign, "unknown": shared.NewID()} {
			_, err := create(asMember, member, nil, mine, id)
			unavailable(t, err)
			if err != nil && (strings.Contains(err.Error(), "theirs-ids") || strings.Contains(err.Error(), "b-ids")) {
				t.Fatalf("%s: the refusal names a hidden asset: %v", name, err)
			}
		}
	})

	t.Run("administrator: any asset of the tenant, never another tenant's", func(t *testing.T) {
		if _, err := create(asAdmin, admin, nil, theirs); err != nil {
			t.Fatalf("admin refused a tenant asset: %v", err)
		}
		_, err := create(asAdmin, admin, nil, foreign)
		unavailable(t, err)
	})
}
