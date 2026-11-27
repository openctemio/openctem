package integration

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/ctis/v2"

	"github.com/openctemio/openctem/server/internal/app/ingest"
	"github.com/openctemio/openctem/server/pkg/domain/sensor"
)

// A finding is first detected when its producer says it first saw it
// (first_seen_at), bounded: a time in the future counts as now, a time before
// 2000 is not a time and is ignored. The platform's own receipt stays in
// created_at, and the producer's claim is kept as producer-supplied
// (first_detected_reported_at). A later report never moves first detection
// later; an earlier claim moves it earlier. Another tenant's finding with the
// same rule is untouched.
func TestIngest_FindingFirstSeenFromProducer(t *testing.T) {
	r := newV2Rig(t, ingest.DefaultBlindingGuard())
	ctx := context.Background()
	now := time.Now().UTC()
	days := func(n int) *time.Time { v := now.Add(-time.Duration(n) * 24 * time.Hour); return &v }

	send := func(tn v2Tenant, rule string, firstSeen *time.Time) {
		t.Helper()
		tid := tn.tenant
		agt := &sensor.Sensor{ID: tn.sensor, TenantID: &tid, Type: sensor.SensorTypeWorker, Status: sensor.SensorStatusActive}
		rep := &ctis.Report{Version: ctis.SchemaVersion, Tool: &ctis.Tool{Name: "nessus"},
			Metadata: ctis.ReportMetadata{ID: ctis.NewReportID(), GeneratedAt: now},
			Assets:   []ctis.Asset{{ID: "h", Type: ctis.AssetTypeHost, Value: "srv-db-01.corp.example.net"}},
			Findings: []ctis.Finding{{Type: ctis.FindingTypeVulnerability, Title: "finding " + rule, Severity: ctis.SeverityHigh,
				RuleID: rule, AssetRef: "h", FirstSeenAt: firstSeen}}}
		out, err := r.svc.Ingest(ctx, agt, ingest.Input{Report: rep})
		if err != nil {
			t.Fatal(err)
		}
		if len(out.Errors) > 0 {
			t.Fatal(out.Errors)
		}
	}
	type seen struct {
		firstDays, createdDays float64
		reportedDays           *float64
	}
	read := func(tn v2Tenant, rule string) seen {
		t.Helper()
		var s seen
		if err := r.db.QueryRowContext(ctx, `SELECT extract(epoch FROM now() - first_detected_at) / 86400,
			extract(epoch FROM now() - created_at) / 86400,
			extract(epoch FROM now() - first_detected_reported_at) / 86400
			FROM findings WHERE tenant_id = $1 AND rule_id = $2`, tn.tenant.String(), rule).Scan(&s.firstDays, &s.createdDays, &s.reportedDays); err != nil {
			t.Fatal(err)
		}
		return s
	}
	near := func(got float64, want int) bool { return got > float64(want)-0.1 && got < float64(want)+0.1 }

	a, b := r.newTenant(), r.newTenant()

	send(a, "r-old", days(30))
	if s := read(a, "r-old"); !near(s.firstDays, 30) || !near(s.createdDays, 0) || s.reportedDays == nil || !near(*s.reportedDays, 30) {
		t.Fatalf("producer first seen 30 days ago: first %.2f, created %.2f, reported %v", s.firstDays, s.createdDays, s.reportedDays)
	}
	// A later claim never moves first detection later.
	send(a, "r-old", days(10))
	if s := read(a, "r-old"); !near(s.firstDays, 30) || !near(*s.reportedDays, 30) {
		t.Fatalf("a later claim moved first detection: first %.2f, reported %.2f", s.firstDays, *s.reportedDays)
	}
	// Neither does a report without a claim.
	send(a, "r-old", nil)
	if s := read(a, "r-old"); !near(s.firstDays, 30) {
		t.Fatalf("a report without first_seen_at moved first detection: %.2f", s.firstDays)
	}
	// An earlier claim moves it earlier.
	send(a, "r-old", days(60))
	if s := read(a, "r-old"); !near(s.firstDays, 60) || !near(*s.reportedDays, 60) {
		t.Fatalf("an earlier claim was ignored: first %.2f, reported %.2f", s.firstDays, *s.reportedDays)
	}

	// The future counts as now.
	future := now.Add(48 * time.Hour)
	send(a, "r-future", &future)
	if s := read(a, "r-future"); !near(s.firstDays, 0) || s.reportedDays == nil || !near(*s.reportedDays, 0) {
		t.Fatalf("a future first seen: first %.2f, reported %v", s.firstDays, s.reportedDays)
	}
	// Before the floor: not a time, ignored.
	epoch := time.Unix(0, 0).UTC()
	send(a, "r-epoch", &epoch)
	if s := read(a, "r-epoch"); !near(s.firstDays, 0) || s.reportedDays != nil {
		t.Fatalf("an epoch first seen: first %.2f, reported %v", s.firstDays, s.reportedDays)
	}
	// No claim: first detected on receipt, nothing reported.
	send(a, "r-none", nil)
	if s := read(a, "r-none"); !near(s.firstDays, 0) || s.reportedDays != nil {
		t.Fatalf("no first seen: first %.2f, reported %v", s.firstDays, s.reportedDays)
	}

	// Tenant B: its own finding, its own times.
	send(b, "r-old", nil)
	if s := read(b, "r-old"); !near(s.firstDays, 0) || s.reportedDays != nil {
		t.Fatalf("tenant B's finding took tenant A's time: first %.2f, reported %v", s.firstDays, s.reportedDays)
	}
	if s := read(a, "r-old"); !near(s.firstDays, 60) {
		t.Fatalf("tenant B's report changed tenant A's finding: %.2f", s.firstDays)
	}
}
