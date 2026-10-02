package postgres

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/ingestjob"
	"github.com/openctemio/openctem/api/pkg/domain/ingestreport"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
)

// ingestReportFixture creates a tenant and a sensor of that tenant and removes
// everything (reports and jobs cascade) when the test ends.
func ingestReportFixture(t *testing.T) (*sql.DB, shared.ID, shared.ID) {
	t.Helper()
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping ingest_reports DB test")
	}
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.PingContext(context.Background()); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}
	tenantID, sensorID := shared.NewID(), shared.NewID()
	ctx := context.Background()
	if _, err := db.ExecContext(ctx, `INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`,
		tenantID.String(), "ir-"+tenantID.String()); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO sensors (id, tenant_id, name, api_key_hash, api_key_prefix, status)
		VALUES ($1, $2, 'ir-sensor', $3, 'p', 'active')`, sensorID.String(), tenantID.String(), "h-"+sensorID.String()); err != nil {
		t.Fatalf("insert sensor: %v", err)
	}
	t.Cleanup(func() {
		// Reports first (their jobs cascade), so no queue row outlives the
		// test even if the tenant delete fails.
		_, _ = db.ExecContext(context.Background(), "DELETE FROM ingest_reports WHERE tenant_id = $1", tenantID.String())
		_, _ = db.ExecContext(context.Background(), "DELETE FROM tenants WHERE id = $1", tenantID.String())
	})
	return db, tenantID, sensorID
}

func newTestReport(tenantID, sensorID shared.ID, reportID string, now time.Time) *ingestreport.Report {
	return &ingestreport.Report{
		ID: shared.NewID(), TenantID: tenantID, SensorID: sensorID, ReportID: reportID,
		State: protov2.StateReceiving, MediaType: protov2.MediaTypeCTIS, SensorType: "scanner",
		HeaderDigest: "sha-256=:AAAA:", Header: []byte(`{"tool":{"name":"semgrep"}}`), ToolName: "semgrep",
		ExpiresAt: now.Add(time.Hour), ReceivedAt: now,
	}
}

func TestIngestReportRepository_Lifecycle(t *testing.T) {
	db, tenantID, sensorID := ingestReportFixture(t)
	ctx := context.Background()
	repo := NewIngestReportRepository(&DB{DB: db})
	jobs := NewIngestJobRepository(&DB{DB: db})
	now := time.Now().UTC().Truncate(time.Microsecond)
	reportID := "0192a3b4-5c6d-7e8f-9a0b-1c2d3e4f5a6b"

	rep := newTestReport(tenantID, sensorID, reportID, now)
	if err := repo.Create(ctx, rep); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := repo.Create(ctx, newTestReport(tenantID, sensorID, reportID, now)); !errors.Is(err, ingestreport.ErrExists) {
		t.Fatalf("duplicate create: %v", err)
	}

	// Another tenant cannot see it, even with the same sensor id and report id.
	if _, err := repo.Get(ctx, shared.NewID(), sensorID, reportID); !errors.Is(err, ingestreport.ErrNotFound) {
		t.Fatalf("cross-tenant get: %v", err)
	}
	// A report of this tenant's sensor cannot be filed under another tenant:
	// the sensor key is the composite (tenant_id, sensor_id). Checked in the
	// catalog rather than by provoking a violation, so the run leaves no
	// errors in the server log.
	var fkCols string
	if err := db.QueryRowContext(ctx, `
		SELECT string_agg(a.attname, ',' ORDER BY k.ord)
		FROM pg_constraint c
		CROSS JOIN LATERAL unnest(c.conkey) WITH ORDINALITY AS k(attnum, ord)
		JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = k.attnum
		WHERE c.conname = 'fk_ingest_reports_sensor' AND c.contype = 'f'`).Scan(&fkCols); err != nil || fkCols != "tenant_id,sensor_id" {
		t.Fatalf("composite same-tenant FK: %q %v", fkCols, err)
	}

	if n, err := repo.CountOpen(ctx, sensorID, now); err != nil || n != 1 {
		t.Fatalf("count open: %d %v", n, err)
	}

	// Two segments arrive and are queued.
	for seq := 0; seq < 2; seq++ {
		s := seq
		job := ingestjob.NewV2Job(tenantID, &sensorID, reportID, ingestjob.V2Segment{
			ReportRef: rep.ID, Seq: &s, ContentDigest: "sha-256=:seg" + string(rune('0'+s)) + ":", MediaType: protov2.MediaTypeCTIS,
		}, []byte(`{"version":"1.0"}`))
		job.DelayUntil(now.Add(24 * time.Hour)) // never claimable by a parallel test
		stored, created, err := jobs.EnqueueV2(ctx, job)
		if err != nil || !created || stored.V2() == nil || *stored.V2().Seq != s {
			t.Fatalf("enqueue segment %d: %v %v", s, created, err)
		}
		if ok, err := repo.ReserveSegment(ctx, rep.ID, 1, 10, 100, 25, now.Add(2*time.Hour)); err != nil || !ok {
			t.Fatalf("reserve %d: %v %v", s, ok, err)
		}
	}
	// A third segment would pass the report's finding limit (25).
	if ok, _ := repo.ReserveSegment(ctx, rep.ID, 1, 10, 100, 25, now.Add(2*time.Hour)); ok {
		t.Fatal("reserved past the per-report finding limit")
	}
	if got, _ := repo.GetByID(ctx, rep.ID); got.SegmentsReceived != 2 || got.FindingsReceived != 20 || got.AssetsReceived != 2 {
		t.Fatalf("received %d/%d/%d", got.SegmentsReceived, got.AssetsReceived, got.FindingsReceived)
	}
	if err := repo.ReleaseSegment(ctx, rep.ID, 1, 10); err != nil {
		t.Fatal(err)
	}
	if ok, _ := repo.ReserveSegment(ctx, rep.ID, 1, 10, 100, 25, now.Add(2*time.Hour)); !ok {
		t.Fatal("release did not free the reservation")
	}

	// Replay of segment 0: the existing job comes back.
	zero := 0
	again, created, err := jobs.EnqueueV2(ctx, ingestjob.NewV2Job(tenantID, &sensorID, reportID,
		ingestjob.V2Segment{ReportRef: rep.ID, Seq: &zero, ContentDigest: "sha-256=:other:"}, []byte("x")))
	if err != nil || created || again.V2().ContentDigest != "sha-256=:seg0:" {
		t.Fatalf("replay: created=%v err=%v", created, err)
	}
	digests, err := jobs.V2SegmentDigests(ctx, rep.ID)
	if err != nil || len(digests) != 2 || digests[1] != "sha-256=:seg1:" {
		t.Fatalf("digests: %v %v", digests, err)
	}

	// Not committed: finalize cannot be claimed.
	if _, ok, err := repo.ClaimFinalize(ctx, rep.ID); ok || err != nil {
		t.Fatalf("claim before commit: %v %v", ok, err)
	}
	ok, err := repo.Commit(ctx, rep.ID, 2, false, now)
	if err != nil || !ok {
		t.Fatalf("commit: %v %v", ok, err)
	}
	if ok, _ := repo.Commit(ctx, rep.ID, 2, false, now); ok {
		t.Fatal("second commit succeeded")
	}

	a, b := shared.NewID(), shared.NewID()
	seg := 1
	outcome := ingestreport.SegmentOutcome{AcceptedAssets: 1, AcceptedFindings: 3, RejectedFindings: 1,
		Errors: []protov2.ItemError{{Pointer: "/findings/2/asset_ref", Code: protov2.CodeAssetUnresolved, Detail: protov2.DetailAssetUnresolved}}}
	if err := repo.RecordSegmentOutcome(ctx, rep.ID, 0, outcome, []shared.ID{a}); err != nil {
		t.Fatal(err)
	}
	// One of two segments processed: still not claimable.
	if _, ok, _ := repo.ClaimFinalize(ctx, rep.ID); ok {
		t.Fatal("claimed with a segment outstanding")
	}
	// A retried segment replaces its own outcome rather than adding to it.
	for i := 0; i < 2; i++ {
		if err := repo.RecordSegmentOutcome(ctx, rep.ID, seg, ingestreport.SegmentOutcome{AcceptedFindings: 2}, []shared.ID{a, b}); err != nil {
			t.Fatal(err)
		}
	}
	claimed, ok, err := repo.ClaimFinalize(ctx, rep.ID)
	if err != nil || !ok {
		t.Fatalf("claim: %v %v", ok, err)
	}
	if _, ok, _ := repo.ClaimFinalize(ctx, rep.ID); ok {
		t.Fatal("claimed twice")
	}
	if len(claimed.TouchedAssetIDs) != 2 {
		t.Fatalf("touched %v", claimed.TouchedAssetIDs)
	}
	st := claimed.Status(now)
	if st.Accepted.Findings != 5 || st.Rejected.Findings != 1 || len(st.Errors) != 1 || *st.Errors[0].Segment != 0 {
		t.Fatalf("status %+v", st)
	}
	if err := repo.Finish(ctx, rep.ID, protov2.StateCompleted, 7, protov2.AutoResolveApplied); err != nil {
		t.Fatal(err)
	}
	got, err := repo.Get(ctx, tenantID, sensorID, reportID)
	if err != nil || got.State != protov2.StateCompleted || got.AutoResolved != 7 || got.AutoResolve != protov2.AutoResolveApplied {
		t.Fatalf("finished: %+v %v", got, err)
	}
	if err := jobs.ClearV2Payloads(ctx, rep.ID); err != nil {
		t.Fatal(err)
	}
}

func TestIngestReportRepository_ExpireAndReopen(t *testing.T) {
	db, tenantID, sensorID := ingestReportFixture(t)
	ctx := context.Background()
	repo := NewIngestReportRepository(&DB{DB: db})
	now := time.Now().UTC()

	stale := newTestReport(tenantID, sensorID, "0192a3b4-0000-7e8f-9a0b-1c2d3e4f5a6b", now.Add(-2*time.Hour))
	stale.ExpiresAt = now.Add(-time.Minute)
	if err := repo.Create(ctx, stale); err != nil {
		t.Fatal(err)
	}
	if n, _ := repo.CountOpen(ctx, sensorID, now); n != 0 {
		t.Fatalf("an expired report counts as open: %d", n)
	}
	if got, _ := repo.Get(ctx, tenantID, sensorID, stale.ReportID); got.Status(now).State != protov2.StateExpired {
		t.Fatal("status of a lapsed report is not expired")
	}
	n, err := repo.ExpireStale(ctx, now)
	if err != nil || n < 1 {
		t.Fatalf("expire: %d %v", n, err)
	}
	if ok, _ := repo.Commit(ctx, stale.ID, 1, false, now); ok {
		t.Fatal("committed an expired report")
	}

	abandoned := newTestReport(tenantID, sensorID, "0192a3b4-2222-7e8f-9a0b-1c2d3e4f5a6b", now)
	if err := repo.Create(ctx, abandoned); err != nil {
		t.Fatal(err)
	}
	if ok, err := repo.Abandon(ctx, abandoned.ID); err != nil || !ok {
		t.Fatalf("abandon: %v %v", ok, err)
	}
	if ok, _ := repo.Abandon(ctx, abandoned.ID); ok {
		t.Fatal("abandoned twice")
	}

	failed := newTestReport(tenantID, sensorID, "0192a3b4-1111-7e8f-9a0b-1c2d3e4f5a6b", now)
	if err := repo.Create(ctx, failed); err != nil {
		t.Fatal(err)
	}
	if err := repo.MarkFailed(ctx, failed.ID); err != nil {
		t.Fatal(err)
	}
	if err := repo.Reopen(ctx, failed.ID, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if got, _ := repo.GetByID(ctx, failed.ID); got.State != protov2.StateReceiving {
		t.Fatalf("reopened state %s", got.State)
	}
}
