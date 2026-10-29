package postgres

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/ingestreceipt"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type receiptFixture struct {
	t      *testing.T
	ctx    context.Context
	db     *sql.DB
	repo   *IngestReceiptRepository
	tenant shared.ID
	asset  shared.ID
}

func newReceiptFixture(t *testing.T) *receiptFixture {
	t.Helper()
	db := openSensorDB(t)
	ctx := context.Background()
	tenant := seedTestTenant(ctx, t, db)
	return &receiptFixture{t: t, ctx: ctx, db: db, repo: NewIngestReceiptRepository(&DB{DB: db}),
		tenant: tenant, asset: seedTestAsset(ctx, t, db, tenant)}
}

func (f *receiptFixture) finding(tenant, asset shared.ID, fp, status string) shared.ID {
	f.t.Helper()
	id := shared.NewID()
	if _, err := f.db.ExecContext(f.ctx, `INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message,
			severity, fingerprint, status) VALUES ($1, $2, $3, 'dast', 'nuclei', 'm', 'high', $4, $5)`,
		id.String(), tenant.String(), asset.String(), fp, status); err != nil {
		f.t.Fatalf("seed finding %s: %v", fp, err)
	}
	return id
}

func (f *receiptFixture) count(q string, args ...any) int {
	f.t.Helper()
	var n int
	if err := f.db.QueryRowContext(f.ctx, q, args...).Scan(&n); err != nil {
		f.t.Fatalf("count %q: %v", q, err)
	}
	return n
}

func (f *receiptFixture) record(d *ingestreceipt.Delta) *ingestreceipt.Receipt {
	f.t.Helper()
	id, err := f.repo.Record(f.ctx, d)
	if err != nil {
		f.t.Fatalf("record: %v", err)
	}
	rec, err := f.repo.Get(f.ctx, d.TenantID, id)
	if err != nil {
		f.t.Fatalf("get: %v", err)
	}
	return rec
}

// One receipt per run: two batches of one run add up, a finding both batches
// report counts once (the first action wins), the action rows link each
// finding with what the run did to it, and the day's fact carries the same
// counts.
func TestIngestReceipt_RecordAccumulatesPerRun_DB(t *testing.T) {
	f := newReceiptFixture(t)
	created := f.finding(f.tenant, f.asset, "fp-new", "new")
	still := f.finding(f.tenant, f.asset, "fp-still", "confirmed")
	reopened := f.finding(f.tenant, f.asset, "fp-reopened", "new")
	closed := f.finding(f.tenant, f.asset, "fp-closed", "resolved")
	src := ingestreceipt.Source{Kind: ingestreceipt.SourceCIRun, Ref: shared.NewID().String()}

	rec := f.record(&ingestreceipt.Delta{TenantID: f.tenant, Source: src, Tool: "nuclei", Reports: 1, Received: 4,
		Created: []shared.ID{created}, Reopened: []shared.ID{reopened}, Closed: []shared.ID{closed},
		StillDetected: []string{"fp-new", "fp-still", "fp-reopened"}, Skipped: 1,
		Errors: []ingestreceipt.ErrorEntry{{Index: 3, Code: ingestreceipt.ErrorStoreFailed}}, Failed: 1})
	c := rec.Counts
	if c.Created != 1 || c.StillDetected != 1 || c.Reopened != 1 || c.Closed != 1 || c.Skipped != 1 || c.Failed != 1 ||
		c.Untouched != nil || rec.Reports != 1 || rec.Received != 4 || rec.SourceKind != ingestreceipt.SourceCIRun ||
		rec.ToolName != "nuclei" || rec.Coverage != ingestreceipt.CoveragePartial || rec.ActionsRecorded != 4 {
		t.Fatalf("first batch: %+v counts %+v", rec, c)
	}
	if len(rec.Errors) != 1 || rec.Errors[0].Code != ingestreceipt.ErrorStoreFailed {
		t.Fatalf("errors = %+v", rec.Errors)
	}

	// The second batch of the same run sees the created and the still
	// detected finding again: neither is counted a second time.
	rec2 := f.record(&ingestreceipt.Delta{TenantID: f.tenant, Source: src, Tool: "nuclei", Reports: 1, Received: 2,
		StillDetected: []string{"fp-new", "fp-still"}})
	if rec2.ID != rec.ID {
		t.Fatalf("second batch made another receipt")
	}
	if c := rec2.Counts; c.Created != 1 || c.StillDetected != 1 || rec2.Reports != 2 || rec2.Received != 6 {
		t.Fatalf("second batch: %+v", rec2)
	}
	want := map[shared.ID]string{created: "created", still: "still_detected", reopened: "reopened", closed: "closed"}
	for id, action := range want {
		if n := f.count(`SELECT count(*) FROM finding_ingest_actions WHERE tenant_id = $1 AND receipt_id = $2 AND finding_id = $3 AND action = $4`,
			f.tenant, rec.ID, id, action); n != 1 {
			t.Fatalf("finding %s: %d %s rows", id, n, action)
		}
	}
	var reports, received, cr, st, ro, cl, sk, fl int
	if err := f.db.QueryRowContext(f.ctx, `SELECT reports, received, created, still_detected, reopened, closed, skipped, failed
			FROM dash_ingest_day WHERE tenant_id = $1 AND source_kind = 'ci' AND tool = 'nuclei'`, f.tenant).
		Scan(&reports, &received, &cr, &st, &ro, &cl, &sk, &fl); err != nil {
		t.Fatalf("fact: %v", err)
	}
	if reports != 2 || received != 6 || cr != 1 || st != 1 || ro != 1 || cl != 1 || sk != 1 || fl != 1 {
		t.Fatalf("fact = %d %d %d %d %d %d %d %d", reports, received, cr, st, ro, cl, sk, fl)
	}
}

// Tenant isolation: a delta never acts on another tenant's findings (ids and
// fingerprints are matched inside the delta's tenant), another tenant cannot
// read the receipt, and a command of another tenant is not a source.
func TestIngestReceipt_TenantIsolation_DB(t *testing.T) {
	f := newReceiptFixture(t)
	other := seedTestTenant(f.ctx, t, f.db)
	otherAsset := seedTestAsset(f.ctx, t, f.db, other)
	foreign := f.finding(other, otherAsset, "fp-foreign", "new")
	f.finding(other, otherAsset, "fp-foreign-still", "new")

	rec := f.record(&ingestreceipt.Delta{TenantID: f.tenant, Tool: "nuclei", Reports: 1,
		Source:  ingestreceipt.Source{Kind: ingestreceipt.SourceConnector, Ref: "sync-1"},
		Created: []shared.ID{foreign}, Closed: []shared.ID{foreign}, StillDetected: []string{"fp-foreign-still"}})
	if c := rec.Counts; c.Created != 0 || c.Closed != 0 || c.StillDetected != 0 || rec.ActionsRecorded != 0 {
		t.Fatalf("a delta acted on another tenant's findings: %+v", c)
	}
	if n := f.count(`SELECT count(*) FROM finding_ingest_actions WHERE finding_id = $1`, foreign); n != 0 {
		t.Fatalf("%d action rows on another tenant's finding", n)
	}
	if _, err := f.repo.Get(f.ctx, other, rec.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("another tenant read the receipt: %v", err)
	}
	cmd := shared.NewID()
	if _, err := f.db.ExecContext(f.ctx, `INSERT INTO commands (id, tenant_id, type, status, payload) VALUES ($1, $2, 'scan', 'completed', '{}')`,
		cmd.String(), other.String()); err != nil {
		t.Fatal(err)
	}
	_, err := f.repo.Record(f.ctx, &ingestreceipt.Delta{TenantID: f.tenant, Reports: 1,
		Source: ingestreceipt.Source{Kind: ingestreceipt.SourceCommand, CommandID: &cmd}})
	if !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("another tenant's command was accepted as a source: %v", err)
	}
}

// A command in a scan run counts toward the run's receipt; a command outside
// one has its own. A coverage decision evaluated twice replaces its untouched
// count; two commands' decisions add up; only a decision makes the receipt
// "full".
func TestIngestReceipt_CommandSourceAndCoverage_DB(t *testing.T) {
	f := newReceiptFixture(t)
	run, step := shared.NewID(), shared.NewID()
	if _, err := f.db.ExecContext(f.ctx, `INSERT INTO scan_runs (id, tenant_id, trigger_type, status, kind) VALUES ($1, $2, 'manual', 'running', 'system')`,
		run.String(), f.tenant.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.ExecContext(f.ctx, `INSERT INTO scan_run_steps (id, scan_run_id, step_key, step_order, status) VALUES ($1, $2, 's', 1, 'running')`,
		step.String(), run.String()); err != nil {
		t.Fatal(err)
	}
	cmd := func(inRun bool) shared.ID {
		id := shared.NewID()
		var st any
		if inRun {
			st = step.String()
		}
		if _, err := f.db.ExecContext(f.ctx, `INSERT INTO commands (id, tenant_id, type, status, payload, scan_run_step_id)
				VALUES ($1, $2, 'scan', 'completed', '{}', $3)`, id.String(), f.tenant.String(), st); err != nil {
			t.Fatal(err)
		}
		return id
	}
	c1, c2, lone := cmd(true), cmd(true), cmd(false)
	decide := func(c shared.ID, untouched int) *ingestreceipt.Receipt {
		return f.record(&ingestreceipt.Delta{TenantID: f.tenant, Tool: "nuclei",
			Source: ingestreceipt.Source{Kind: ingestreceipt.SourceCommand, CommandID: &c}, Coverage: ingestreceipt.CoverageFull,
			CoverageNote: "resolved", Untouched: &untouched})
	}
	partial := f.record(&ingestreceipt.Delta{TenantID: f.tenant, Tool: "nuclei", Reports: 1,
		Source: ingestreceipt.Source{Kind: ingestreceipt.SourceCommand, CommandID: &c1}})
	if partial.SourceKind != ingestreceipt.SourceScanRun || partial.SourceRef != run.String() ||
		partial.Coverage != ingestreceipt.CoveragePartial || partial.Counts.Untouched != nil {
		t.Fatalf("run receipt = %+v", partial)
	}
	decide(c1, 3)
	again := decide(c1, 3)
	if again.ID != partial.ID || again.Coverage != ingestreceipt.CoverageFull || again.Counts.Untouched == nil || *again.Counts.Untouched != 3 {
		t.Fatalf("decision evaluated twice: %+v untouched %v", again, again.Counts.Untouched)
	}
	both := decide(c2, 2)
	if *both.Counts.Untouched != 5 {
		t.Fatalf("two commands' untouched = %d, want 5", *both.Counts.Untouched)
	}
	own := f.record(&ingestreceipt.Delta{TenantID: f.tenant, Reports: 1,
		Source: ingestreceipt.Source{Kind: ingestreceipt.SourceCommand, CommandID: &lone}})
	if own.SourceKind != ingestreceipt.SourceCommand || own.SourceRef != lone.String() || own.ID == partial.ID {
		t.Fatalf("lone command receipt = %+v", own)
	}
}

// Past the cap, action rows stop and the receipt says so; the counts keep
// counting from the batch sizes.
func TestIngestReceipt_ActionCap_DB(t *testing.T) {
	f := newReceiptFixture(t)
	src := ingestreceipt.Source{Kind: ingestreceipt.SourceConnector, Ref: "capped"}
	first := f.record(&ingestreceipt.Delta{TenantID: f.tenant, Source: src, Reports: 1})
	if _, err := f.db.ExecContext(f.ctx, `UPDATE ingest_receipts SET actions_recorded = $3 WHERE tenant_id = $1 AND id = $2`,
		f.tenant, first.ID, ingestreceipt.MaxActionsPerReceipt-1); err != nil {
		t.Fatal(err)
	}
	ids := []shared.ID{f.finding(f.tenant, f.asset, "c1", "new"), f.finding(f.tenant, f.asset, "c2", "new"), f.finding(f.tenant, f.asset, "c3", "new")}
	rec := f.record(&ingestreceipt.Delta{TenantID: f.tenant, Source: src, Reports: 1, Created: ids})
	if rec.Counts.Created != 3 || !rec.ActionsTruncated || rec.ActionsRecorded != ingestreceipt.MaxActionsPerReceipt {
		t.Fatalf("capped receipt = %+v", rec)
	}
	if n := f.count(`SELECT count(*) FROM finding_ingest_actions WHERE receipt_id = $1`, rec.ID); n != 1 {
		t.Fatalf("%d action rows past the cap, want 1", n)
	}
}

// An upload receipt is created before anything is written and finished with
// the file-level counts; the purge keeps it while it removes old run
// receipts, old action rows and old facts.
func TestIngestReceipt_UploadAndRetention_DB(t *testing.T) {
	f := newReceiptFixture(t)
	up := &ingestreceipt.Upload{ID: shared.NewID(), TenantID: f.tenant,
		FilenameSHA256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}
	if err := f.repo.CreateUpload(f.ctx, up); err != nil {
		t.Fatal(err)
	}
	rec, err := f.repo.Get(f.ctx, f.tenant, up.ID)
	if err != nil || rec.Status != ingestreceipt.StatusProcessing || rec.SourceRef != up.ID.String() {
		t.Fatalf("upload receipt = %+v, %v", rec, err)
	}
	id := f.finding(f.tenant, f.asset, "u1", "new")
	f.record(&ingestreceipt.Delta{TenantID: f.tenant, Source: ingestreceipt.Source{Kind: ingestreceipt.SourceUpload, Ref: up.ID.String()},
		Reports: 1, Created: []shared.ID{id}})
	if err := f.repo.FinishUpload(f.ctx, f.tenant, up.ID, &ingestreceipt.UploadResult{Format: "nessus", Components: 2,
		Errors: []ingestreceipt.ErrorEntry{{Index: 1, Code: "file_malformed"}}}); err != nil {
		t.Fatal(err)
	}
	if err := f.repo.FinishUpload(f.ctx, shared.NewID(), up.ID, &ingestreceipt.UploadResult{}); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("another tenant finished the upload: %v", err)
	}
	rec, _ = f.repo.Get(f.ctx, f.tenant, up.ID)
	if rec.Status != ingestreceipt.StatusCompleted || rec.Format != "nessus" || rec.Components != 2 || rec.Counts.Created != 1 ||
		rec.FinishedAt == nil || len(rec.Errors) != 1 {
		t.Fatalf("finished upload = %+v", rec)
	}

	run := f.record(&ingestreceipt.Delta{TenantID: f.tenant, Reports: 1, Created: []shared.ID{id},
		Source: ingestreceipt.Source{Kind: ingestreceipt.SourceConnector, Ref: "old-sync"}})
	old := time.Now().Add(-500 * 24 * time.Hour)
	for _, q := range []string{
		`UPDATE ingest_receipts SET updated_at = $2 WHERE tenant_id = $1`,
		`UPDATE finding_ingest_actions SET created_at = $2 WHERE tenant_id = $1`,
		`UPDATE dash_ingest_day SET day = ($2::timestamptz)::date WHERE tenant_id = $1`,
	} {
		if _, err := f.db.ExecContext(f.ctx, q, f.tenant, old); err != nil {
			t.Fatal(err)
		}
	}
	cutoff := time.Now().Add(-400 * 24 * time.Hour)
	if _, err := f.repo.PurgeActionsForPlatform(f.ctx, time.Now().Add(-ingestreceipt.ActionRetention), 1000); err != nil {
		t.Fatal(err)
	}
	if _, err := f.repo.PurgeRunReceiptsForPlatform(f.ctx, cutoff, 1000); err != nil {
		t.Fatal(err)
	}
	if _, err := f.repo.PurgeFactsForPlatform(f.ctx, cutoff, 1000); err != nil {
		t.Fatal(err)
	}
	if _, err := f.repo.Get(f.ctx, f.tenant, up.ID); err != nil {
		t.Fatalf("the upload receipt was purged: %v", err)
	}
	if _, err := f.repo.Get(f.ctx, f.tenant, run.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("an old run receipt was kept: %v", err)
	}
	if n := f.count(`SELECT count(*) FROM finding_ingest_actions WHERE tenant_id = $1`, f.tenant); n != 0 {
		t.Fatalf("%d old action rows kept", n)
	}
	if n := f.count(`SELECT count(*) FROM dash_ingest_day WHERE tenant_id = $1`, f.tenant); n != 0 {
		t.Fatalf("%d old fact rows kept", n)
	}
}

// Deleting a finding (or an asset with many findings) cascades into
// finding_ingest_actions by finding_id alone. Without an index that leads
// with finding_id, every deleted finding is a scan of the whole action log
// (up to 50,000 rows per receipt for 90 days).
func TestIngestReceipt_ActionsIndexedForFindingCascade_DB(t *testing.T) {
	f := newReceiptFixture(t)
	var n int
	if err := f.db.QueryRowContext(f.ctx, `
		SELECT count(*)
		FROM pg_index i
		JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = i.indkey[0]
		WHERE i.indrelid = 'finding_ingest_actions'::regclass AND a.attname = 'finding_id'`).Scan(&n); err != nil {
		t.Fatalf("index lookup: %v", err)
	}
	if n == 0 {
		t.Fatal("no index on finding_ingest_actions leads with finding_id: the ON DELETE CASCADE from findings scans the table")
	}
}

// A running scan run shows the findings its receipt holds as each report
// lands (the sensor's own findings_count is 0 for ingest-reported tools), and
// the step bookkeeping that follows never lowers that figure.
func TestIngestReceipt_RunTotalFindingsLive_DB(t *testing.T) {
	f := newReceiptFixture(t)
	run, step, cmd := shared.NewID(), shared.NewID(), shared.NewID()
	if _, err := f.db.ExecContext(f.ctx, `INSERT INTO scan_runs (id, tenant_id, trigger_type, status, kind) VALUES ($1, $2, 'manual', 'running', 'system')`,
		run.String(), f.tenant.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.ExecContext(f.ctx, `INSERT INTO scan_run_steps (id, scan_run_id, step_key, step_order, status) VALUES ($1, $2, 's', 1, 'running')`,
		step.String(), run.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.ExecContext(f.ctx, `INSERT INTO commands (id, tenant_id, type, status, payload, scan_run_step_id)
			VALUES ($1, $2, 'scan', 'running', '{}', $3)`, cmd.String(), f.tenant.String(), step.String()); err != nil {
		t.Fatal(err)
	}
	total := func() int {
		return f.count(`SELECT total_findings FROM scan_runs WHERE id = $1`, run)
	}
	a := f.finding(f.tenant, f.asset, "fp-a", "new")
	f.finding(f.tenant, f.asset, "fp-b", "confirmed")
	src := ingestreceipt.Source{Kind: ingestreceipt.SourceCommand, CommandID: &cmd}
	f.record(&ingestreceipt.Delta{TenantID: f.tenant, Source: src, Tool: "nuclei", Reports: 1, Received: 2,
		Created: []shared.ID{a}, StillDetected: []string{"fp-b"}})
	if got := total(); got != 2 {
		t.Fatalf("total_findings after one report = %d, want 2", got)
	}
	// The step settles with the sensor's own count (0): the run keeps its figure.
	if err := NewScanRunRepository(&DB{DB: f.db}).UpdateStats(f.ctx, f.tenant, run, 1, 0, 0, 0); err != nil {
		t.Fatal(err)
	}
	if got := total(); got != 2 {
		t.Fatalf("total_findings after UpdateStats(0) = %d, want 2", got)
	}
	// Another tenant's run id is never touched by a receipt of this tenant.
	other := seedTestTenant(f.ctx, t, f.db)
	otherRun := shared.NewID()
	if _, err := f.db.ExecContext(f.ctx, `INSERT INTO scan_runs (id, tenant_id, trigger_type, status, kind) VALUES ($1, $2, 'manual', 'running', 'system')`,
		otherRun.String(), other.String()); err != nil {
		t.Fatal(err)
	}
	if n := f.count(`SELECT total_findings FROM scan_runs WHERE id = $1`, otherRun); n != 0 {
		t.Fatalf("other tenant's run total_findings = %d", n)
	}
}
