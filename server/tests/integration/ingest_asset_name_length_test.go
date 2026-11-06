package integration

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/ctis/v2"

	"github.com/openctemio/openctem/server/internal/app/ingest"
	"github.com/openctemio/openctem/server/internal/infra/postgres"
	"github.com/openctemio/openctem/server/pkg/domain/sensor"
	"github.com/openctemio/openctem/server/pkg/logger"
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
		Version:  ctis.SchemaVersion,
		Metadata: ctis.ReportMetadata{ID: ctis.NewReportID(), GeneratedAt: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)},
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

// A name no valid canonical form can have (a label over 63 bytes, a name over
// 255) makes the whole document invalid in CTIS 2.0: nothing of it is
// stored, not even the well-formed assets and findings beside it.
func TestIngest_OverlongAssetNameRefusesTheReport(t *testing.T) {
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
	_, err := svc.Ingest(context.Background(),
		&sensor.Sensor{ID: tn.sensor, TenantID: &tid, Type: sensor.SensorTypeWorker, Status: sensor.SensorStatusActive},
		ingest.Input{Report: report})
	if err == nil {
		t.Fatal("a report with an overlong asset name was accepted")
	}
	if strings.Contains(err.Error(), long) {
		t.Errorf("error carries the whole name: %.120s...", err.Error())
	}
	if got := r.countAssets(tn); got != 0 {
		t.Errorf("assets in DB = %d, want 0", got)
	}
	if got := r.countFindings(tn, ""); got != 0 {
		t.Errorf("findings in DB = %d, want 0", got)
	}
}
