package integration

// RFC-043 P0 (B10): every sighting of an existing finding counts one, also
// when ingests run concurrently. The enrich path used to write back the
// value it had loaded, so occurrence_count stayed at 1 for ever.

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func newOccurrenceRig(t *testing.T) (*v2Rig, v2Tenant, *ingest.Service, *sensor.Sensor) {
	t.Helper()
	r := newV2Rig(t, ingest.DefaultBlindingGuard())
	tn := r.newTenant("nessus")
	db := &postgres.DB{DB: r.db}
	svc := ingest.NewService(
		postgres.NewAssetRepository(db), postgres.NewFindingRepository(db),
		postgres.NewVulnerabilityRepository(db), postgres.NewComponentRepository(db),
		postgres.NewSensorRepository(db), postgres.NewBranchRepository(db), postgres.NewTenantRepository(db),
		postgres.NewAuditRepository(db), logger.NewNop())
	tid := tn.tenant
	return r, tn, svc, &sensor.Sensor{ID: tn.sensor, TenantID: &tid, Type: sensor.SensorTypeWorker, Status: sensor.SensorStatusActive}
}

func occurrenceReport(tn v2Tenant) *ctis.Report {
	return &ctis.Report{Version: "1.0", Tool: &ctis.Tool{Name: "nessus"},
		Metadata: ctis.ReportMetadata{ID: shared.NewID().String(), Timestamp: time.Now().UTC()},
		Assets:   []ctis.Asset{{ID: "h", Type: ctis.AssetTypeHost, Value: "occ-" + tn.tenant.String()[:8] + ".example.com"}},
		Findings: []ctis.Finding{{Type: ctis.FindingTypeVulnerability, Title: "OpenSSH regreSSHion", Severity: ctis.SeverityHigh,
			RuleID: "201194", AssetRef: "h", Vulnerability: &ctis.VulnerabilityDetails{CVEID: "CVE-2024-6387"},
			Network: &ctis.NetworkLocation{Port: 22}}}}
}

func occurrenceCount(t *testing.T, r *v2Rig, tn v2Tenant) (rows, count int) {
	t.Helper()
	if err := r.db.QueryRow(`SELECT count(*), COALESCE(max(occurrence_count), 0) FROM findings WHERE tenant_id = $1`,
		tn.tenant.String()).Scan(&rows, &count); err != nil {
		t.Fatal(err)
	}
	return rows, count
}

func TestFindingOccurrenceCount_EachSightingCounts(t *testing.T) {
	r, tn, svc, agt := newOccurrenceRig(t)
	for i := 0; i < 3; i++ {
		if _, err := svc.Ingest(context.Background(), agt, ingest.Input{Report: occurrenceReport(tn)}); err != nil {
			t.Fatal(err)
		}
	}
	if rows, count := occurrenceCount(t, r, tn); rows != 1 || count != 3 {
		t.Errorf("after 3 sightings: rows=%d occurrence_count=%d, want 1 and 3", rows, count)
	}
}

func TestFindingOccurrenceCount_ConcurrentSightingsAreNotLost(t *testing.T) {
	r, tn, svc, agt := newOccurrenceRig(t)
	if _, err := svc.Ingest(context.Background(), agt, ingest.Input{Report: occurrenceReport(tn)}); err != nil {
		t.Fatal(err)
	}
	const n = 8
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if _, err := svc.Ingest(context.Background(), agt, ingest.Input{Report: occurrenceReport(tn)}); err != nil {
				t.Errorf("ingest: %v", err)
			}
		}()
	}
	close(start)
	wg.Wait()
	if rows, count := occurrenceCount(t, r, tn); rows != 1 || count != n+1 {
		t.Errorf("after 1 + %d concurrent sightings: rows=%d occurrence_count=%d, want 1 and %d", n, rows, count, n+1)
	}
}
