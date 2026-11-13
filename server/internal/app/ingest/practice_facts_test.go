package ingest

import (
	"testing"

	"github.com/openctemio/openctem/server/pkg/domain/asset"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/vulnerability"
)

func practiceTestAsset(t *testing.T, tenant shared.ID, name string, typ asset.AssetType) *asset.Asset {
	t.Helper()
	a, err := asset.NewAssetWithTenant(tenant, name, typ, asset.CriticalityMedium)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// Only the stored rows of the batch tenant that a report asset landed on
// give facts: another tenant's entity, a create that lost the name race, a
// row the database refused and an unmapped entity give none.
func TestNotePracticeFacts_OnlyStoredRowsOfTheTenant(t *testing.T) {
	tenant, other := shared.NewID(), shared.NewID()
	stored := practiceTestAsset(t, tenant, "app.example.com", asset.AssetTypeApplication)
	stored.SetExposure(asset.ExposurePublic)
	existing := practiceTestAsset(t, tenant, "db01", asset.AssetTypeHost)
	foreign := practiceTestAsset(t, other, "foreign.example.com", asset.AssetTypeDomain)
	lostRace := practiceTestAsset(t, tenant, "race.example.com", asset.AssetTypeDomain)
	refused := practiceTestAsset(t, tenant, "refused.example.com", asset.AssetTypeDomain)
	unmapped := practiceTestAsset(t, tenant, "unmapped", asset.AssetTypeHost)

	held := []*asset.Asset{stored, existing, foreign, lostRace, refused, unmapped}
	isNew := map[string]bool{stored.ID().String(): true, lostRace.ID().String(): true, refused.ID().String(): true}
	persisted := map[string]shared.ID{
		stored.Name():   stored.ID(),
		existing.Name(): existing.ID(),
		foreign.Name():  foreign.ID(),
		lostRace.Name(): shared.NewID(), // the concurrent create's row
		unmapped.Name(): unmapped.ID(),
	}
	assetMap := map[string]shared.ID{
		"a1": stored.ID(), "a2": existing.ID(), "a3": foreign.ID(), "a4": persisted[lostRace.Name()], "a5": refused.ID(),
	}
	out := &Output{}
	notePracticeFacts(out, tenant, held, persisted, isNew, assetMap)

	want := map[shared.ID]vulnerability.PracticeAssetFacts{
		stored.ID():   {AssetType: "application", AssetInternetFacing: true},
		existing.ID(): {AssetType: "host"},
	}
	if len(out.practiceFacts) != len(want) {
		t.Fatalf("facts = %v, want %v", out.practiceFacts, want)
	}
	for id, w := range want {
		if out.practiceFacts[id] != w {
			t.Fatalf("facts of %s = %v, want %v", id, out.practiceFacts[id], w)
		}
	}
}

// Facts attach only to the batch tenant's findings on an asset with facts.
func TestAttachPracticeFacts_TenantPinned(t *testing.T) {
	tenant, other := shared.NewID(), shared.NewID()
	assetID := shared.NewID()
	out := &Output{practiceFacts: map[shared.ID]vulnerability.PracticeAssetFacts{
		assetID: {AssetType: "repository"},
	}}
	mk := func(tid, aid shared.ID) *vulnerability.Finding {
		f, err := vulnerability.NewFinding(tid, aid, vulnerability.FindingSourceSecret, "betterleaks", vulnerability.SeverityHigh, "probe")
		if err != nil {
			t.Fatal(err)
		}
		return f
	}
	own, foreign, elsewhere := mk(tenant, assetID), mk(other, assetID), mk(tenant, shared.NewID())
	attachPracticeFacts([]*vulnerability.Finding{own, foreign, elsewhere, nil}, tenant, out)

	if got, ok := own.AttachedPracticeAssetFacts(); !ok || got.AssetType != "repository" {
		t.Fatalf("own finding facts = %v, %v", got, ok)
	}
	if _, ok := foreign.AttachedPracticeAssetFacts(); ok {
		t.Fatal("another tenant's finding took the batch tenant's asset facts")
	}
	if _, ok := elsewhere.AttachedPracticeAssetFacts(); ok {
		t.Fatal("a finding on an asset without facts has facts attached")
	}
}
