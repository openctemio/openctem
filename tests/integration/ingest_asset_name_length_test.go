package integration

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/ctis"

	"github.com/openctemio/api/internal/app/ingest"
	"github.com/openctemio/api/internal/infra/postgres"
	"github.com/openctemio/api/pkg/domain/asset"
	"github.com/openctemio/api/pkg/domain/sensor"
	"github.com/openctemio/api/pkg/logger"
	protov2 "github.com/openctemio/api/pkg/sensorproto/v2"
)

// assets.name is varchar(255) while ingest accepted names up to 1024 bytes:
// one over-long name failed the report's single asset upsert, and every
// asset of the report (and the findings on new ones) was lost. Now that
// asset alone is refused, with an item-level error.

// longNameReport has three host assets, the middle one with a 300-character
// name, and one finding on each.
func longNameReport(tool string) (*ctis.Report, string) {
	long := "host-" + strings.Repeat("x", 295) + ".example.com"
	r := &ctis.Report{
		Version:  "1.0",
		Metadata: ctis.ReportMetadata{Timestamp: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)},
		Tool:     &ctis.Tool{Name: tool},
		Assets: []ctis.Asset{
			{ID: "a", Type: ctis.AssetTypeHost, Value: "web-1.example.com"},
			{ID: "b", Type: ctis.AssetTypeHost, Value: long},
			{ID: "c", Type: ctis.AssetTypeHost, Value: "web-2.example.com"},
		},
	}
	for _, ref := range []string{"a", "b", "c"} {
		r.Findings = append(r.Findings, ctis.Finding{Type: ctis.FindingTypeVulnerability, Title: "finding on " + ref,
			Severity: ctis.SeverityHigh, RuleID: "rule-" + ref, AssetRef: ref})
	}
	return r, long
}

func TestIngestV1_OverlongAssetNameRefusedAlone(t *testing.T) {
	r := newV2Rig(t, ingest.DefaultBlindingGuard())
	tn := r.newTenant("nmap")
	db := &postgres.DB{DB: r.db}
	svc := ingest.NewService(
		postgres.NewAssetRepository(db), postgres.NewFindingRepository(db),
		postgres.NewVulnerabilityRepository(db), postgres.NewComponentRepository(db),
		postgres.NewSensorRepository(db), postgres.NewBranchRepository(db), postgres.NewTenantRepository(db),
		postgres.NewAuditRepository(db), logger.NewNop())

	report, long := longNameReport("nmap")
	tid := tn.tenant
	out, err := svc.Ingest(context.Background(),
		&sensor.Sensor{ID: tn.sensor, TenantID: &tid, Type: sensor.SensorTypeWorker, Status: sensor.SensorStatusActive},
		ingest.Input{Report: report})
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if out.AssetsCreated != 2 {
		t.Errorf("assets created = %d, want 2 (errors: %v)", out.AssetsCreated, out.Errors)
	}
	if _, ok := out.AssetMap["b"]; ok {
		t.Errorf("the refused asset is in the asset map")
	}
	found := false
	for _, e := range out.Errors {
		if strings.Contains(e, "asset b") && strings.Contains(e, "maximum is 255") {
			found = true
		}
		if strings.Contains(e, long) {
			t.Errorf("error message carries the whole name: %.120s...", e)
		}
	}
	if !found {
		t.Errorf("no item-level error for asset b: %v", out.Errors)
	}
	if got := r.countAssets(tn); got != 2 {
		t.Errorf("assets in DB = %d, want 2", got)
	}
	if got := r.countFindings(tn, ""); got < 2 {
		t.Errorf("findings in DB = %d, want the findings of the two stored assets", got)
	}
}

func TestIngestV2_OverlongAssetNameRefusedAlone(t *testing.T) {
	r := newV2Rig(t, ingest.DefaultBlindingGuard())
	tn := r.newTenant("nmap")
	seg, _ := longNameReport("nmap")
	rep := r.open(tn, "0192a3b4-0000-7000-8000-0000000000a1", seg)
	r.put(tn, rep, 0, seg)
	r.process(rep, 0)
	r.commit(tn, rep, 1)

	st := r.status(rep)
	if st.Accepted.Assets != 2 || st.Rejected.Assets != 1 {
		t.Fatalf("assets accepted/rejected = %d/%d, want 2/1 (%+v)", st.Accepted.Assets, st.Rejected.Assets, st)
	}
	if st.Accepted.Findings != 2 || st.Rejected.Findings != 1 {
		t.Fatalf("findings accepted/rejected = %d/%d, want 2/1 (%+v)", st.Accepted.Findings, st.Rejected.Findings, st)
	}
	var assetErr, findingErr bool
	for _, e := range st.Errors {
		switch {
		case e.Pointer == "/assets/1" && e.Code == protov2.CodeAssetInvalid:
			assetErr = true
		case e.Pointer == "/findings/1/asset_ref" && e.Code == protov2.CodeAssetUnresolved:
			findingErr = true
		}
	}
	if !assetErr || !findingErr {
		t.Fatalf("item errors %+v, want /assets/1 asset_invalid and /findings/1/asset_ref", st.Errors)
	}
	if got := r.countAssets(tn); got != 2 {
		t.Fatalf("assets in DB = %d, want 2", got)
	}
}

// The repository's per-row fallback skips a row the database refuses for its
// own values (here sub_type, varchar(50)) and keeps the rest of the batch.
func TestAssetUpsertBatch_RefusedRowSkippedAlone(t *testing.T) {
	r := newV2Rig(t, ingest.DefaultBlindingGuard())
	tn := r.newTenant("nmap")
	repo := postgres.NewAssetRepository(&postgres.DB{DB: r.db})

	mk := func(name, subType string) *asset.Asset {
		a, err := asset.NewAssetWithTenant(tn.tenant, name, asset.AssetTypeHost, asset.CriticalityMedium)
		if err != nil {
			t.Fatal(err)
		}
		if subType != "" {
			a.SetSubType(subType)
		}
		return a
	}
	good1, bad, good2 := mk("ok-1.example.com", ""), mk("bad.example.com", strings.Repeat("s", 60)), mk("ok-2.example.com", "")
	created, _, persisted, err := repo.UpsertBatch(context.Background(), []*asset.Asset{good1, bad, good2})
	if err != nil {
		t.Fatalf("UpsertBatch: %v", err)
	}
	if created != 2 {
		t.Errorf("created = %d, want 2", created)
	}
	if _, ok := persisted[bad.Name()]; ok {
		t.Errorf("refused row reported as persisted")
	}
	if _, ok := persisted[good1.Name()]; !ok {
		t.Errorf("good row missing from persisted ids")
	}
	if got := r.countAssets(tn); got != 2 {
		t.Errorf("assets in DB = %d, want 2", got)
	}
}
