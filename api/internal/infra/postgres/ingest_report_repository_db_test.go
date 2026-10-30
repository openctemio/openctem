package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
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
	// A report of this tenant's sensor cannot be filed under another tenant,
	// and a shared sensor's report only under the tenant of a shared job it
	// holds: trigger_ingest_reports_sensor_binding (migration
	// ingest_reports_shared_sensor) with the plain FK on sensor_id. Checked
	// in the catalog rather than by provoking a violation, so the run leaves
	// no errors in the server log (the behavior is covered by
	// TestSharedResults_DatabaseRefusesUnboundReport).
	var fkCols string
	var triggers int
	if err := db.QueryRowContext(ctx, `
		SELECT COALESCE(string_agg(a.attname, ',' ORDER BY k.ord), ''),
		       (SELECT count(*) FROM pg_trigger WHERE tgname = 'trigger_ingest_reports_sensor_binding' AND NOT tgisinternal)
		FROM pg_constraint c
		CROSS JOIN LATERAL unnest(c.conkey) WITH ORDINALITY AS k(attnum, ord)
		JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = k.attnum
		WHERE c.conname = 'fk_ingest_reports_sensor_id' AND c.contype = 'f'`).Scan(&fkCols, &triggers); err != nil ||
		fkCols != "sensor_id" || triggers != 1 {
		t.Fatalf("sensor FK %q, binding triggers %d: %v", fkCols, triggers, err)
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
	ok, err := repo.Commit(ctx, rep.ID, ingestreport.CommitFacts{SegmentCount: 2, Integrity: protov2.IntegrityManifest}, now)
	if err != nil || !ok {
		t.Fatalf("commit: %v %v", ok, err)
	}
	if ok, _ := repo.Commit(ctx, rep.ID, ingestreport.CommitFacts{SegmentCount: 2, Integrity: protov2.IntegrityManifest}, now); ok {
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
	if ok, _ := repo.Commit(ctx, stale.ID, ingestreport.CommitFacts{SegmentCount: 1, Integrity: protov2.IntegritySingle}, now); ok {
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

// TouchedAssetsByCommand: the live assets the completed reports of one
// command wrote, each once; never another command's, an unfinished report's,
// a deleted asset or another tenant's.
func TestIngestReportRepository_TouchedAssetsByCommand(t *testing.T) {
	db, tenantID, sensorID := ingestReportFixture(t)
	ctx := context.Background()
	repo := NewIngestReportRepository(&DB{DB: db})
	cmd := shared.NewID()
	asset := func(name string) string {
		t.Helper()
		id := shared.NewID().String()
		if _, err := db.ExecContext(ctx, `INSERT INTO assets (id, tenant_id, name, asset_type, status) VALUES ($1, $2, $3, 'ip_address', 'active')`,
			id, tenantID.String(), name); err != nil {
			t.Fatal(err)
		}
		return id
	}
	a, b, gone, other := asset("203.0.113.1"), asset("203.0.113.2"), asset("203.0.113.3"), asset("203.0.113.4")
	if _, err := db.ExecContext(ctx, `UPDATE assets SET deleted_at = now() WHERE id = $1`, gone); err != nil {
		t.Fatal(err)
	}
	report := func(command shared.ID, state string, touched ...string) {
		t.Helper()
		if _, err := db.ExecContext(ctx, `INSERT INTO commands (id, tenant_id, type) VALUES ($1, $2, 'connector_sync') ON CONFLICT DO NOTHING`,
			command.String(), tenantID.String()); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, `INSERT INTO ingest_reports (id, tenant_id, sensor_id, report_id, command_id, state, media_type,
				sensor_type, header_digest, header, tool_name, expires_at, received_at, touched_asset_ids)
			VALUES ($1, $2, $3, $4, $5, $6, 'application/vnd.ctis+json', 'scanner', 'sha-256=:AAAA:', '{}', 'tenable_sc', now() + interval '1 hour', now(), $7::uuid[])`,
			shared.NewID().String(), tenantID.String(), sensorID.String(), shared.NewID().String(), command.String(), state, "{"+joinIDs(touched)+"}"); err != nil {
			t.Fatal(err)
		}
	}
	report(cmd, "completed", a, b, gone)
	report(cmd, "completed", a)
	report(cmd, "processing", other)
	report(shared.NewID(), "completed", other)

	got, err := repo.TouchedAssetsByCommand(ctx, tenantID, cmd)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, id := range got {
		seen[id.String()] = true
	}
	if len(got) != 2 || !seen[a] || !seen[b] {
		t.Fatalf("touched %v, want %s and %s", got, a, b)
	}
	if got, err := repo.TouchedAssetsByCommand(ctx, shared.NewID(), cmd); err != nil || len(got) != 0 {
		t.Fatalf("another tenant: %v %v", got, err)
	}
}

func joinIDs(ids []string) string {
	out := ""
	for i, id := range ids {
		if i > 0 {
			out += ","
		}
		out += id
	}
	return out
}

// A segment reserved after the commit, or a commit racing a late segment,
// must never both succeed: the commit would otherwise freeze a segment set
// that does not include the late segment (L1).
func TestIngestReportRepository_CommitRacesLateSegment(t *testing.T) {
	db, tenantID, sensorID := ingestReportFixture(t)
	ctx := context.Background()
	repo := NewIngestReportRepository(&DB{DB: db})
	now := time.Now().UTC().Truncate(time.Microsecond)
	facts := ingestreport.CommitFacts{SegmentCount: 2, Integrity: protov2.IntegrityManifest}

	// A closed report refuses a reservation outright.
	closed := newTestReport(tenantID, sensorID, "0192a3b4-5c6d-7e8f-9a0b-000000000001", now)
	if err := repo.Create(ctx, closed); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if ok, err := repo.ReserveSegment(ctx, closed.ID, 0, 0, 100, 100, now.Add(time.Hour)); err != nil || !ok {
			t.Fatalf("reserve: %v %v", ok, err)
		}
	}
	if ok, err := repo.Commit(ctx, closed.ID, facts, now); err != nil || !ok {
		t.Fatalf("commit: %v %v", ok, err)
	}
	if ok, err := repo.ReserveSegment(ctx, closed.ID, 0, 0, 100, 100, now.Add(time.Hour)); err != nil || ok {
		t.Fatalf("reserve after commit: ok=%v err=%v, want refused", ok, err)
	}
	if got, _ := repo.GetByID(ctx, closed.ID); got.SegmentsReceived != 2 {
		t.Fatalf("segments_received %d after a refused reserve, want 2", got.SegmentsReceived)
	}

	// A commit for a count that does not match what was reserved fails.
	short := newTestReport(tenantID, sensorID, "0192a3b4-5c6d-7e8f-9a0b-000000000002", now)
	if err := repo.Create(ctx, short); err != nil {
		t.Fatal(err)
	}
	if ok, _ := repo.ReserveSegment(ctx, short.ID, 0, 0, 100, 100, now.Add(time.Hour)); !ok {
		t.Fatal("reserve")
	}
	if ok, err := repo.Commit(ctx, short.ID, facts, now); err != nil || ok {
		t.Fatalf("commit with 1 of 2 segments: ok=%v err=%v, want refused", ok, err)
	}

	// Races: reserve (the third segment) against commit of two.
	for i := 0; i < 40; i++ {
		rep := newTestReport(tenantID, sensorID, fmt.Sprintf("0192a3b4-5c6d-7e8f-9a0b-1%011x", i), now)
		if err := repo.Create(ctx, rep); err != nil {
			t.Fatal(err)
		}
		for s := 0; s < 2; s++ {
			if ok, _ := repo.ReserveSegment(ctx, rep.ID, 0, 0, 100, 100, now.Add(time.Hour)); !ok {
				t.Fatal("reserve")
			}
		}
		var reserved, committed bool
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			reserved, _ = repo.ReserveSegment(ctx, rep.ID, 0, 0, 100, 100, now.Add(time.Hour))
		}()
		go func() {
			defer wg.Done()
			committed, _ = repo.Commit(ctx, rep.ID, facts, now)
		}()
		wg.Wait()
		if reserved && committed {
			t.Fatalf("iteration %d: a segment was reserved AND the commit of 2 succeeded", i)
		}
	}
}

// Finalize needs an outcome for every real segment (numbers below the
// count); a stray outcome key past the count does not stand in for one.
func TestIngestReportRepository_ClaimFinalizeCountsRealSegments(t *testing.T) {
	db, tenantID, sensorID := ingestReportFixture(t)
	ctx := context.Background()
	repo := NewIngestReportRepository(&DB{DB: db})
	now := time.Now().UTC().Truncate(time.Microsecond)
	rep := newTestReport(tenantID, sensorID, "0192a3b4-5c6d-7e8f-9a0b-000000000003", now)
	if err := repo.Create(ctx, rep); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if ok, _ := repo.ReserveSegment(ctx, rep.ID, 0, 0, 100, 100, now.Add(time.Hour)); !ok {
			t.Fatal("reserve")
		}
	}
	if ok, err := repo.Commit(ctx, rep.ID, ingestreport.CommitFacts{SegmentCount: 2, Integrity: protov2.IntegrityManifest}, now); err != nil || !ok {
		t.Fatalf("commit: %v %v", ok, err)
	}
	o := ingestreport.SegmentOutcome{AcceptedFindings: 1}
	// Outcomes for segment 0 and a stray segment 5: only one real segment done.
	for _, seq := range []int{0, 5} {
		if err := repo.RecordSegmentOutcome(ctx, rep.ID, seq, o, nil); err != nil {
			t.Fatal(err)
		}
	}
	if _, ok, err := repo.ClaimFinalize(ctx, rep.ID); ok || err != nil {
		t.Fatalf("finalize claimed with segment 1 outstanding: %v %v", ok, err)
	}
	if err := repo.RecordSegmentOutcome(ctx, rep.ID, 1, o, nil); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := repo.ClaimFinalize(ctx, rep.ID); !ok || err != nil {
		t.Fatalf("finalize with every real segment done: %v %v", ok, err)
	}
}
