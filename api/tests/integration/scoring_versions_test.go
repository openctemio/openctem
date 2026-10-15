package integration

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	assetapp "github.com/openctemio/openctem/api/internal/app/asset"
	"github.com/openctemio/openctem/api/internal/app/finding"
	"github.com/openctemio/openctem/api/internal/app/reclassify"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/scoring"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Scoring versions (docs/architecture/scoring-versions.md): a scoring change
// recomputes open findings from the change time; closed findings keep the
// values they had when they were closed; every computed value stores the
// version it was computed with, and an older version is stale.

type scoringFixture struct {
	db       *sql.DB
	assets   *postgres.AssetRepository
	findings *postgres.FindingRepository
	scoring  *postgres.ScoringRepository
	recl     *reclassify.Reclassifier
	cls      *finding.PriorityClassificationService
}

func newScoringFixture(t *testing.T) scoringFixture {
	t.Helper()
	dsn := testdb.URL()
	if dsn == "" {
		t.Skip("DATABASE_URL not set; skipping scoring versions DB test")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.Ping(); err != nil {
		testdb.Skipf(t, "database not available: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	pdb := &postgres.DB{DB: db}
	fx := scoringFixture{
		db:       db,
		assets:   postgres.NewAssetRepository(pdb),
		findings: postgres.NewFindingRepository(pdb),
		scoring:  postgres.NewScoringRepository(pdb),
	}
	ti := postgres.NewThreatIntelRepository(pdb)
	cls := finding.NewPriorityClassificationService(fx.findings, fx.assets,
		postgres.NewEPSSAdapter(ti.EPSS().(*postgres.EPSSRepository)),
		postgres.NewKEVAdapter(ti.KEV().(*postgres.KEVRepository)),
		postgres.NewPriorityRuleRepository(pdb), postgres.NewPriorityAuditRepository(pdb), logger.NewNop())
	fx.cls = cls
	fx.recl = reclassify.NewReclassifier(fx.findings, fx.assets, cls, logger.NewNop())
	fx.recl.SetQueue(fx.scoring, fx.scoring)
	fx.recl.SetWriter(fx.scoring)
	return fx
}

func (fx scoringFixture) newTenant(t *testing.T) shared.ID {
	t.Helper()
	tid := shared.NewID()
	if _, err := fx.db.Exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'Scoring versions IT', $2)`,
		tid.String(), "scoring-it-"+strings.ReplaceAll(uuid.NewString()[:13], "-", "")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, q := range []string{
			`DELETE FROM findings WHERE tenant_id = $1`,
			`DELETE FROM priority_override_rules WHERE tenant_id = $1`,
			`DELETE FROM assets WHERE tenant_id = $1`,
			`DELETE FROM tenants WHERE id = $1`,
		} {
			_, _ = fx.db.Exec(q, tid.String())
		}
	})
	return tid
}

func (fx scoringFixture) newAsset(t *testing.T, tid shared.ID, name string) shared.ID {
	t.Helper()
	a, err := asset.NewAssetWithTenant(tid, name, asset.AssetTypeRepository, asset.CriticalityMedium)
	if err != nil {
		t.Fatal(err)
	}
	_, _, ids, err := fx.assets.UpsertBatch(context.Background(), []*asset.Asset{a})
	if err != nil {
		t.Fatal(err)
	}
	return ids[name]
}

func (fx scoringFixture) newFinding(t *testing.T, tid, aid shared.ID, sev vulnerability.Severity, name string) shared.ID {
	t.Helper()
	f, err := vulnerability.NewFinding(tid, aid, vulnerability.FindingSourceSAST, "semgrep", sev, name)
	if err != nil {
		t.Fatal(err)
	}
	f.SetFingerprint(name + "-" + aid.String()[:8])
	if _, err := fx.findings.CreateBatchWithResult(context.Background(), []*vulnerability.Finding{f}); err != nil {
		t.Fatal(err)
	}
	return f.ID()
}

type findingRow struct {
	status, class string
	version       sql.NullInt64
	deadline      sql.NullTime
}

func (fx scoringFixture) row(t *testing.T, tid, id shared.ID) findingRow {
	t.Helper()
	var r findingRow
	var class sql.NullString
	if err := fx.db.QueryRow(`SELECT status, priority_class, priority_version, sla_deadline FROM findings WHERE tenant_id = $1 AND id = $2`,
		tid.String(), id.String()).Scan(&r.status, &class, &r.version, &r.deadline); err != nil {
		t.Fatal(err)
	}
	r.class = class.String
	return r
}

func (fx scoringFixture) queued(t *testing.T, aid shared.ID) bool {
	t.Helper()
	var n int
	if err := fx.db.QueryRow(`SELECT COUNT(*) FROM finding_priority_queue WHERE asset_id = $1`, aid.String()).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n > 0
}

// drain runs the worker until none of the given assets is queued. Other
// tests' rows may share the queue, so it loops a bounded number of times.
func (fx scoringFixture) drain(t *testing.T, ids ...shared.ID) {
	t.Helper()
	for i := 0; i < 200; i++ {
		pending := false
		for _, id := range ids {
			if fx.queued(t, id) {
				pending = true
			}
		}
		if !pending {
			return
		}
		if _, err := fx.recl.ProcessQueue(context.Background(), 500, 500); err != nil {
			t.Fatalf("process queue: %v", err)
		}
	}
	t.Fatal("finding priority queue did not drain")
}

func (fx scoringFixture) version(t *testing.T, tid shared.ID) int64 {
	t.Helper()
	v, err := fx.scoring.CurrentVersion(context.Background(), tid, scoring.KindFindingPriority)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func (fx scoringFixture) addRule(t *testing.T, tid shared.ID, sev, class string) {
	t.Helper()
	if _, err := fx.db.Exec(`INSERT INTO priority_override_rules (tenant_id, name, description, priority_class, conditions, is_active)
		VALUES ($1, $2, '', $3, $4::jsonb, true)`, tid.String(), "it "+sev+" "+class, class,
		fmt.Sprintf(`[{"field":"severity","operator":"eq","value":%q}]`, sev)); err != nil {
		t.Fatal(err)
	}
}

// A priority rule change recomputes the open findings from the change time,
// stamps them with the new version and leaves a closed finding exactly as
// it was when it was closed.
func TestScoringVersions_ForwardOnly_ClosedFindingsFrozen(t *testing.T) {
	fx := newScoringFixture(t)
	tid := fx.newTenant(t)
	aid := fx.newAsset(t, tid, "github.com/acme/scoring-forward")

	openID := fx.newFinding(t, tid, aid, vulnerability.SeverityHigh, "open-high")
	closedID := fx.newFinding(t, tid, aid, vulnerability.SeverityHigh, "closed-high")
	if !fx.queued(t, aid) {
		t.Fatal("a new open finding did not queue its asset")
	}
	fx.drain(t, aid)
	v0 := fx.version(t, tid)
	if got := fx.row(t, tid, openID); !got.version.Valid || got.version.Int64 != v0 {
		t.Fatalf("open finding version = %v, want %d", got.version, v0)
	}

	// Close one finding with a known class and deadline.
	deadline := time.Now().Add(-48 * time.Hour).UTC().Truncate(time.Second)
	if _, err := fx.db.Exec(`UPDATE findings SET status = 'resolved', resolved_at = now(), priority_class = 'P3',
		sla_deadline = $3 WHERE tenant_id = $1 AND id = $2`, tid.String(), closedID.String(), deadline); err != nil {
		t.Fatal(err)
	}
	before := fx.row(t, tid, closedID)

	// The tenant adds a rule: high → P0.
	fx.addRule(t, tid, "high", "P0")
	v1 := fx.version(t, tid)
	if v1 <= v0 {
		t.Fatalf("rule change did not move the version: %d -> %d", v0, v1)
	}
	if !fx.queued(t, aid) {
		t.Fatal("the rule change did not queue the asset of the open finding")
	}
	fx.drain(t, aid)

	open := fx.row(t, tid, openID)
	if open.class != "P0" || !open.version.Valid || open.version.Int64 != v1 {
		var why string
		_ = fx.db.QueryRow(`SELECT COALESCE(priority_class_reason,'') FROM findings WHERE id = $1`, openID.String()).Scan(&why)
		t.Fatalf("open finding: class=%q version=%v (%s), want P0 at %d", open.class, open.version, why, v1)
	}
	closed := fx.row(t, tid, closedID)
	if closed.class != before.class || closed.version != before.version ||
		!closed.deadline.Valid || !closed.deadline.Time.Equal(before.deadline.Time) {
		t.Fatalf("closed finding changed: before=%+v after=%+v", before, closed)
	}

	// Reopening makes it open again: it is queued and recomputed.
	if _, err := fx.db.Exec(`UPDATE findings SET status = 'confirmed', resolved_at = NULL WHERE tenant_id = $1 AND id = $2`,
		tid.String(), closedID.String()); err != nil {
		t.Fatal(err)
	}
	if !fx.queued(t, aid) {
		t.Fatal("reopen did not queue the asset")
	}
	fx.drain(t, aid)
	if got := fx.row(t, tid, closedID); got.class != "P0" || got.version.Int64 != v1 {
		t.Fatalf("reopened finding: class=%q version=%v, want P0 at %d", got.class, got.version, v1)
	}
}

// The reconcile queues findings with a stale version now and the others
// behind the event-driven rows.
func TestScoringVersions_ReconcileQueuesStaleFirst(t *testing.T) {
	fx := newScoringFixture(t)
	tid := fx.newTenant(t)
	fresh := fx.newAsset(t, tid, "github.com/acme/scoring-fresh")
	stale := fx.newAsset(t, tid, "github.com/acme/scoring-stale")
	fx.newFinding(t, tid, fresh, vulnerability.SeverityLow, "fresh-low")
	staleID := fx.newFinding(t, tid, stale, vulnerability.SeverityLow, "stale-low")
	fx.drain(t, fresh, stale)

	if _, err := fx.db.Exec(`UPDATE findings SET priority_version = 1 WHERE tenant_id = $1 AND id = $2`, tid.String(), staleID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := fx.scoring.EnqueueReconcile(context.Background(), time.Hour); err != nil {
		t.Fatal(err)
	}
	due := func(aid shared.ID) bool {
		var d bool
		if err := fx.db.QueryRow(`SELECT enqueued_at <= now() FROM finding_priority_queue WHERE asset_id = $1`, aid.String()).Scan(&d); err != nil {
			t.Fatalf("asset %s not queued: %v", aid, err)
		}
		return d
	}
	if !due(stale) {
		t.Fatal("the stale asset is not due now")
	}
	if due(fresh) {
		t.Fatal("the fresh asset is due now; want it behind events")
	}
	_, _ = fx.db.Exec(`DELETE FROM finding_priority_queue WHERE tenant_id = $1`, tid.String())
}

// A process running an older model never stamps a version at or past a
// newer platform model, even when tenant changes come after it.
func TestScoringVersions_OlderModelStampsBelowNewerModel(t *testing.T) {
	fx := newScoringFixture(t)
	tid := fx.newTenant(t)
	newer := scoring.PriorityModelVersion + 1000
	var modelRow int64
	if err := fx.db.QueryRow(`INSERT INTO scoring_changes (tenant_id, kind, source, model_version, summary)
		VALUES (NULL, 'finding_priority', 'platform_model', $1, 'it newer model') RETURNING id`, newer).Scan(&modelRow); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = fx.db.Exec(`DELETE FROM scoring_changes WHERE id = $1`, modelRow) })
	fx.addRule(t, tid, "low", "P3") // a tenant change after the newer model

	var old, cur int64
	if err := fx.db.QueryRow(`SELECT scoring_version($1, 'finding_priority', $2), scoring_version($1, 'finding_priority', $3)`,
		tid.String(), scoring.PriorityModelVersion, newer).Scan(&old, &cur); err != nil {
		t.Fatal(err)
	}
	if old >= modelRow {
		t.Fatalf("old model stamps %d, want below the newer model row %d", old, modelRow)
	}
	if cur <= modelRow {
		t.Fatalf("new model stamps %d, want the tenant change after %d", cur, modelRow)
	}
}

// Enqueue ignores another tenant's assets, and a claim serves every tenant
// even when one has a large backlog.
func TestScoringVersions_QueueIsTenantScopedAndFair(t *testing.T) {
	fx := newScoringFixture(t)
	ctx := context.Background()
	ta, tb := fx.newTenant(t), fx.newTenant(t)
	foreign := fx.newAsset(t, tb, "github.com/acme/scoring-foreign")
	_, _ = fx.db.Exec(`DELETE FROM finding_priority_queue WHERE tenant_id = ANY($1::uuid[])`, "{"+ta.String()+","+tb.String()+"}")

	if err := fx.scoring.EnqueueAssets(ctx, ta, []shared.ID{foreign}, scoring.ReasonControl); err != nil {
		t.Fatal(err)
	}
	if fx.queued(t, foreign) {
		t.Fatal("tenant A queued tenant B's asset")
	}

	var backlog []shared.ID
	for i := 0; i < 6; i++ {
		backlog = append(backlog, fx.newAsset(t, ta, fmt.Sprintf("github.com/acme/scoring-a-%d", i)))
	}
	if err := fx.scoring.EnqueueAssets(ctx, ta, backlog, scoring.ReasonControl); err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)
	if err := fx.scoring.EnqueueAssets(ctx, tb, []shared.ID{foreign}, scoring.ReasonControl); err != nil {
		t.Fatal(err)
	}
	// Only this test's tenants: other tests may share the queue, so claim
	// generously and look for tenant B among tenant A's backlog.
	items, err := fx.scoring.Claim(ctx, 1000, 2)
	if err != nil {
		t.Fatal(err)
	}
	perTenant := map[shared.ID]int{}
	for _, it := range items {
		perTenant[it.TenantID]++
	}
	if perTenant[ta] != 2 {
		t.Fatalf("tenant A got %d rows in one claim, want the per-tenant cap 2", perTenant[ta])
	}
	if perTenant[tb] != 1 {
		t.Fatalf("tenant B got %d rows, want 1 (not starved by A's backlog)", perTenant[tb])
	}
	_, _ = fx.db.Exec(`DELETE FROM finding_priority_queue WHERE tenant_id = ANY($1::uuid[])`, "{"+ta.String()+","+tb.String()+"}")
}

// Risk scoring settings and the ownership floor record their own kinds and
// queue their own scope; the asset worker stamps the risk version.
func TestScoringVersions_TenantSettingsAndRiskVersion(t *testing.T) {
	fx := newScoringFixture(t)
	ctx := context.Background()
	tid := fx.newTenant(t)
	aid := fx.newAsset(t, tid, "github.com/acme/scoring-risk")
	fx.newFinding(t, tid, aid, vulnerability.SeverityCritical, "risk-crit")
	fx.drain(t, aid)
	_, _ = fx.db.Exec(`DELETE FROM asset_risk_queue WHERE tenant_id = $1`, tid.String())

	count := func(kind string) int {
		var n int
		if err := fx.db.QueryRow(`SELECT COUNT(*) FROM scoring_changes WHERE tenant_id = $1 AND kind = $2`, tid.String(), kind).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if _, err := fx.db.Exec(`UPDATE tenants SET settings = jsonb_set(COALESCE(settings, '{}'::jsonb), '{risk_scoring}', '{"preset":"default","risk_levels":{"critical_min":90}}'::jsonb) WHERE id = $1`, tid.String()); err != nil {
		t.Fatal(err)
	}
	if count("asset_risk") != 1 || count("finding_priority") != 0 {
		t.Fatalf("risk settings: asset_risk=%d finding_priority=%d, want 1/0", count("asset_risk"), count("finding_priority"))
	}
	var riskQueued int
	_ = fx.db.QueryRow(`SELECT COUNT(*) FROM asset_risk_queue WHERE asset_id = $1`, aid.String()).Scan(&riskQueued)
	if riskQueued != 1 {
		t.Fatal("risk settings change did not queue the asset for a rescore")
	}
	if _, err := fx.db.Exec(`UPDATE tenants SET settings = jsonb_set(settings, '{risk_scoring,floor_unowned_at_p2}', 'true') WHERE id = $1`, tid.String()); err != nil {
		t.Fatal(err)
	}
	if count("asset_risk") != 1 || count("finding_priority") != 1 {
		t.Fatalf("floor: asset_risk=%d finding_priority=%d, want 1/1", count("asset_risk"), count("finding_priority"))
	}
	if !fx.queued(t, aid) {
		t.Fatal("the floor change did not queue the asset's open findings")
	}

	// The asset worker stamps the version it scored with.
	svc := assetapp.NewAssetService(fx.assets, logger.NewNop())
	svc.SetRiskQueue(postgres.NewAssetRiskQueueRepository(&postgres.DB{DB: fx.db}), fx.assets)
	svc.SetScoringVersions(fx.scoring)
	if err := svc.UpdateRiskScores(ctx, tid, []shared.ID{aid}); err != nil {
		t.Fatal(err)
	}
	want, err := fx.scoring.CurrentVersion(ctx, tid, scoring.KindAssetRisk)
	if err != nil {
		t.Fatal(err)
	}
	var got sql.NullInt64
	if err := fx.db.QueryRow(`SELECT risk_version FROM assets WHERE tenant_id = $1 AND id = $2`, tid.String(), aid.String()).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if !got.Valid || got.Int64 != want {
		t.Fatalf("risk_version = %v, want %d", got, want)
	}
	_, _ = fx.db.Exec(`DELETE FROM finding_priority_queue WHERE tenant_id = $1`, tid.String())
	_, _ = fx.db.Exec(`DELETE FROM asset_risk_queue WHERE tenant_id = $1`, tid.String())
}

// The pass writes only its own columns and only while the finding is open:
// a finding closed while the pass ran stays closed and frozen.
func TestScoringVersions_PassNeverRevertsAConcurrentClose(t *testing.T) {
	fx := newScoringFixture(t)
	ctx := context.Background()
	tid := fx.newTenant(t)
	aid := fx.newAsset(t, tid, "github.com/acme/scoring-race")
	fid := fx.newFinding(t, tid, aid, vulnerability.SeverityHigh, "race-high")
	fx.drain(t, aid)

	f, err := fx.findings.GetByID(ctx, tid, fid) // the pass loaded it open
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fx.db.Exec(`UPDATE findings SET status = 'resolved', resolved_at = now(), priority_class = 'P3'
		WHERE tenant_id = $1 AND id = $2`, tid.String(), fid.String()); err != nil {
		t.Fatal(err)
	}
	f.SetPriorityClassification(vulnerability.PriorityP0, "computed while open")
	n, err := fx.scoring.SavePriorities(ctx, tid, []*vulnerability.Finding{f})
	if err != nil {
		t.Fatal(err)
	}
	got := fx.row(t, tid, fid)
	if n != 0 || got.status != "resolved" || got.class != "P3" {
		t.Fatalf("saved=%d status=%s class=%s, want nothing written to the closed finding", n, got.status, got.class)
	}

	// Another tenant's id is never written.
	other := fx.newTenant(t)
	if n, err := fx.scoring.SavePriorities(ctx, other, []*vulnerability.Finding{f}); err != nil || n != 0 {
		t.Fatalf("cross-tenant save wrote %d rows (err %v)", n, err)
	}
}
