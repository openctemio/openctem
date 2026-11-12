package postgres

// The story reads (docs/architecture/exploration.md): tenant-bound on every
// join, bounded, and served by indexes (EXPLAIN on a seeded table).

import (
	"strings"
	"testing"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/server/internal/testdb"
	"github.com/openctemio/openctem/server/pkg/domain/exploration"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

func (f *receiptFixture) runTarget(tenant, run, asset shared.ID, stage, origin, decision, relation string, at time.Time) {
	f.t.Helper()
	if _, err := f.db.ExecContext(f.ctx, `INSERT INTO scan_run_targets (tenant_id, run_id, stage_key, target_key, asset_id,
			origin, relation, decision, created_at) VALUES ($1, $2, $3, $4, $5, $6, NULLIF($7, ''), $8, $9)`,
		tenant.String(), run.String(), stage, "t-"+shared.NewID().String(), asset.String(), origin, relation, decision, at); err != nil {
		f.t.Fatalf("seed run target: %v", err)
	}
}

// storyRun seeds a scan definition with a unique name, a run of it and one
// step, in tenant.
func (f *receiptFixture) storyRun(tenant shared.ID) (scan, run, step shared.ID) {
	f.t.Helper()
	scan, run, step = shared.NewID(), shared.NewID(), shared.NewID()
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO scans (id, tenant_id, name, scan_type, scanner_name) VALUES ($1, $2, $3, 'single', 'nuclei')`,
			[]any{scan.String(), tenant.String(), "story-" + scan.String()}},
		{`INSERT INTO scan_runs (id, tenant_id, scan_id, trigger_type, status, kind) VALUES ($1, $2, $3, 'manual', 'completed', 'system')`,
			[]any{run.String(), tenant.String(), scan.String()}},
		{`INSERT INTO scan_run_steps (id, scan_run_id, step_key, step_order, status) VALUES ($1, $2, 's', 1, 'completed')`,
			[]any{step.String(), run.String()}},
	} {
		if _, err := f.db.ExecContext(f.ctx, q.sql, q.args...); err != nil {
			f.t.Fatalf("seed run: %v", err)
		}
	}
	return scan, run, step
}

func TestStoryRepository_ScanRunsTenantBound_DB(t *testing.T) {
	f := newReceiptFixture(t)
	repo := NewStoryRepository(&DB{DB: f.db})
	scan, run, step := f.storyRun(f.tenant)
	if _, err := f.db.ExecContext(f.ctx, `UPDATE scan_run_steps SET step_name = 'Find subdomains', capability = 'enumerate.subdomains',
		tool = 'subfinder' WHERE id = $1`, step.String()); err != nil {
		t.Fatal(err)
	}
	_, run2, _ := f.storyRun(f.tenant)
	other := seedTestTenant(f.ctx, t, f.db)
	_, foreignRun, foreignStep := f.storyRun(other)

	got, err := repo.ScanRuns(f.ctx, f.tenant, []exploration.RunRef{
		{RunID: run, StepRunID: &step},
		// A step of another run is not joined to this one.
		{RunID: run2, StepRunID: &step},
		// Another tenant's run is never read, even by id.
		{RunID: foreignRun, StepRunID: &foreignStep},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("runs: %+v", got)
	}
	byRun := map[shared.ID]exploration.ScanStep{}
	for _, s := range got {
		byRun[s.RunID] = s
	}
	a := byRun[run]
	if a.StepRunID == nil || *a.StepRunID != step || a.StepName != "Find subdomains" || a.Capability != "enumerate.subdomains" ||
		a.Tool != "subfinder" || a.ScanName != "story-"+scan.String() || a.ScanID == nil || *a.ScanID != scan || a.At == nil {
		t.Fatalf("run with step: %+v", a)
	}
	if b := byRun[run2]; b.StepRunID != nil || b.StepName != "" {
		t.Fatalf("step of another run joined: %+v", b)
	}
	if none, err := repo.ScanRuns(f.ctx, f.tenant, nil); err != nil || none != nil {
		t.Fatalf("no refs: %v %v", none, err)
	}
}

func TestStoryRepository_AssetRunsAndReceipt_DB(t *testing.T) {
	f := newReceiptFixture(t)
	repo := NewStoryRepository(&DB{DB: f.db})
	_, first, _ := f.storyRun(f.tenant)
	_, mid, _ := f.storyRun(f.tenant)
	_, last, _ := f.storyRun(f.tenant)
	base := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	f.runTarget(f.tenant, first, f.asset, "resolve", "derived", "planned", "resolves_to", base)
	f.runTarget(f.tenant, mid, f.asset, "probe", "derived", "planned", "exposes", base.Add(time.Hour))
	f.runTarget(f.tenant, last, f.asset, "probe", "seed", "planned", "", base.Add(2*time.Hour))
	f.runTarget(f.tenant, last, f.asset, "probe2", "seed", "skipped", "", base.Add(3*time.Hour))

	d, s, err := repo.AssetRuns(f.ctx, f.tenant, f.asset)
	if err != nil {
		t.Fatal(err)
	}
	if d == nil || d.RunID != first || d.Relation != "resolves_to" || d.Role != exploration.ScanDiscovered || !d.At.Equal(base) {
		t.Fatalf("discovered: %+v", d)
	}
	if s == nil || s.RunID != last || s.Role != exploration.ScanScanned || !s.At.Equal(base.Add(2*time.Hour)) {
		t.Fatalf("scanned: %+v", s)
	}

	// Another tenant reading this asset id gets nothing.
	other := seedTestTenant(f.ctx, t, f.db)
	if d, s, err := repo.AssetRuns(f.ctx, other, f.asset); err != nil || d != nil || s != nil {
		t.Fatalf("cross-tenant asset runs: %+v %+v %v", d, s, err)
	}

	// The upload that created the asset; none recorded is nil.
	if r, err := repo.AssetReceipt(f.ctx, f.tenant, f.asset); err != nil || r != nil {
		t.Fatalf("no receipt: %+v %v", r, err)
	}
	receipt := shared.NewID()
	if _, err := f.db.ExecContext(f.ctx, `INSERT INTO ingest_receipts (id, tenant_id, source_kind, source_ref, status, tool_name)
		VALUES ($1, $2, 'upload', $3, 'completed', 'nessus')`, receipt.String(), f.tenant.String(), receipt.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.ExecContext(f.ctx, `UPDATE assets SET import_id = $1 WHERE id = $2`, receipt.String(), f.asset.String()); err != nil {
		t.Fatal(err)
	}
	r, err := repo.AssetReceipt(f.ctx, f.tenant, f.asset)
	if err != nil || r == nil || r.ID != receipt || r.SourceKind != "upload" || r.Tool != "nessus" {
		t.Fatalf("receipt: %+v %v", r, err)
	}
	if r, err := repo.AssetReceipt(f.ctx, other, f.asset); err != nil || r != nil {
		t.Fatalf("cross-tenant receipt: %+v %v", r, err)
	}
}

// Each story read is served by an index on a seeded table: an asset that
// 4,000 runs targeted, among 40,000 targets of the tenant.
func TestStoryRepository_ReadsUseIndexes_DB(t *testing.T) {
	f := newReceiptFixture(t)
	_, run, step := f.storyRun(f.tenant)
	if _, err := f.db.ExecContext(f.ctx, `
		WITH a AS (
			INSERT INTO assets (id, tenant_id, name, asset_type, import_id)
			SELECT gen_random_uuid(), $1, 'story-bulk-' || g || '.example.com', 'domain', gen_random_uuid()
			FROM generate_series(1, 5000) g
			RETURNING import_id
		)
		INSERT INTO ingest_receipts (id, tenant_id, source_kind, source_ref, status)
		SELECT import_id, $1, 'upload', import_id::text, 'completed' FROM a`, f.tenant.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.ExecContext(f.ctx, `
		WITH runs AS (
			INSERT INTO scan_runs (id, tenant_id, trigger_type, status, kind)
			SELECT gen_random_uuid(), $1, 'manual', 'completed', 'system' FROM generate_series(1, 4000)
			RETURNING id
		), noise AS (
			INSERT INTO assets (id, tenant_id, name, asset_type)
			SELECT gen_random_uuid(), $1, 'story-noise-' || g || '.example.com', 'domain' FROM generate_series(1, 9) g
			RETURNING id
		), targets AS (
			SELECT id AS asset_id FROM noise UNION ALL SELECT $2::uuid
		)
		INSERT INTO scan_run_targets (tenant_id, run_id, stage_key, target_key, asset_id, origin, decision, created_at)
		SELECT $1, runs.id, 'probe', 't-' || targets.asset_id, targets.asset_id,
			(ARRAY['seed','derived'])[1 + (random() * 1)::int], 'planned', now() - random() * interval '300 days'
		FROM runs CROSS JOIN targets`, f.tenant.String(), f.asset.String()); err != nil {
		t.Fatal(err)
	}
	owner := testdb.OpenMigrator(t)
	for _, tbl := range []string{"scan_run_targets", "scan_runs", "scan_run_steps", "assets", "ingest_receipts"} {
		if _, err := owner.ExecContext(f.ctx, `ANALYZE `+tbl); err != nil {
			t.Fatal(err)
		}
	}
	explain := func(q string, args ...any) string {
		t.Helper()
		rows, err := f.db.QueryContext(f.ctx, "EXPLAIN "+q, args...)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = rows.Close() }()
		var b strings.Builder
		for rows.Next() {
			var line string
			if err := rows.Scan(&line); err != nil {
				t.Fatal(err)
			}
			b.WriteString(line + "\n")
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return b.String()
	}
	tid, aid := f.tenant.String(), f.asset.String()
	for name, c := range map[string]struct {
		plan  string
		index string
		table string
	}{
		"asset runs": {explain(storyAssetRunsQuery, tid, aid), "ix_scan_run_targets_asset", "scan_run_targets"},
		"scan runs": {explain(storyScanRunsQuery, tid, pq.Array([]string{run.String()}), pq.Array([]string{step.String()})),
			"uq_scan_runs_tenant_id_id", "scan_runs"},
		"asset receipt": {explain(storyAssetReceiptQuery, tid, aid), "ingest_receipts_pkey", "assets"},
	} {
		if !strings.Contains(c.plan, c.index) || strings.Contains(c.plan, "Seq Scan on "+c.table) {
			t.Errorf("%s: plan does not use %s:\n%s", name, c.index, c.plan)
		}
	}
}
