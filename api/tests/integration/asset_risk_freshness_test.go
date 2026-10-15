package integration

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	assetapp "github.com/openctemio/openctem/api/internal/app/asset"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// An asset's risk score used to move only on a manual recalculation, so a
// repository whose findings arrived by CI upload kept a score of 0. These
// tests drive the real write paths (the ingest upserts, a bulk status change,
// an asset edit) and check that the database queues the asset and the
// worker rescores it, per tenant.

type riskFixture struct {
	db       *sql.DB
	assets   *postgres.AssetRepository
	findings *postgres.FindingRepository
	queue    *postgres.AssetRiskQueueRepository
	svc      *assetapp.AssetService
}

func newRiskFixture(t *testing.T) riskFixture {
	t.Helper()
	dsn := testdb.URL()
	if dsn == "" {
		t.Skip("DATABASE_URL not set; skipping asset risk freshness DB test")
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
	fx := riskFixture{
		db:       db,
		assets:   postgres.NewAssetRepository(pdb),
		findings: postgres.NewFindingRepository(pdb),
		queue:    postgres.NewAssetRiskQueueRepository(pdb),
	}
	fx.svc = assetapp.NewAssetService(fx.assets, logger.NewNop())
	fx.svc.SetRiskQueue(fx.queue, fx.assets)
	return fx
}

func (fx riskFixture) newTenant(t *testing.T) shared.ID {
	t.Helper()
	tid := shared.NewID()
	if _, err := fx.db.Exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'Risk freshness IT', $2)`,
		tid.String(), "risk-it-"+strings.ReplaceAll(uuid.NewString()[:13], "-", "")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = fx.db.Exec(`DELETE FROM findings WHERE tenant_id = $1`, tid.String())
		_, _ = fx.db.Exec(`DELETE FROM assets WHERE tenant_id = $1`, tid.String())
		_, _ = fx.db.Exec(`DELETE FROM asset_risk_queue WHERE tenant_id = $1`, tid.String())
		_, _ = fx.db.Exec(`DELETE FROM tenants WHERE id = $1`, tid.String())
	})
	return tid
}

// ingestAsset creates a repository asset through the ingest upsert.
func (fx riskFixture) ingestAsset(t *testing.T, tid shared.ID, name string) shared.ID {
	t.Helper()
	a, err := asset.NewAssetWithTenant(tid, name, asset.AssetTypeRepository, asset.CriticalityMedium)
	if err != nil {
		t.Fatal(err)
	}
	_, _, ids, err := fx.assets.UpsertBatch(context.Background(), []*asset.Asset{a})
	if err != nil {
		t.Fatal(err)
	}
	id, ok := ids[name]
	if !ok {
		t.Fatalf("asset %s not persisted", name)
	}
	return id
}

// ingestFindings writes findings through the ingest batch path.
func (fx riskFixture) ingestFindings(t *testing.T, tid, aid shared.ID, sev vulnerability.Severity, n int, prefix string) []shared.ID {
	t.Helper()
	batch := make([]*vulnerability.Finding, 0, n)
	for i := 0; i < n; i++ {
		f, err := vulnerability.NewFinding(tid, aid, vulnerability.FindingSourceSAST, "semgrep", sev, fmt.Sprintf("%s %d", prefix, i))
		if err != nil {
			t.Fatal(err)
		}
		f.SetFingerprint(fmt.Sprintf("%s-%s-%d", prefix, aid.String()[:8], i))
		batch = append(batch, f)
	}
	if _, err := fx.findings.CreateBatchWithResult(context.Background(), batch); err != nil {
		t.Fatal(err)
	}
	ids := make([]shared.ID, 0, n)
	for _, f := range batch {
		ids = append(ids, f.ID())
	}
	return ids
}

func (fx riskFixture) queued(t *testing.T, aid shared.ID) bool {
	t.Helper()
	var n int
	if err := fx.db.QueryRow(`SELECT COUNT(*) FROM asset_risk_queue WHERE asset_id = $1`, aid.String()).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n > 0
}

// drain runs the worker until none of the given assets is queued. Other
// tests' rows may share the queue, so it loops a bounded number of times.
func (fx riskFixture) drain(t *testing.T, ids ...shared.ID) {
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
		if _, err := fx.svc.ProcessRiskQueue(context.Background(), 1000); err != nil {
			t.Fatalf("process risk queue: %v", err)
		}
	}
	t.Fatal("risk queue did not drain")
}

func (fx riskFixture) get(t *testing.T, tid, aid shared.ID) *asset.Asset {
	t.Helper()
	a, err := fx.assets.GetByID(context.Background(), tid, aid)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestAssetRisk_IngestedAssetIsScoredAndFindingsMoveTheScore(t *testing.T) {
	fx := newRiskFixture(t)
	tid := fx.newTenant(t)
	aid := fx.ingestAsset(t, tid, "github.com/acme/risk-it")

	// A new asset is queued and is "not yet scored" until the worker runs.
	a := fx.get(t, tid, aid)
	if a.RiskScoredAt() != nil || !a.RiskScorePending() {
		t.Fatalf("new asset: scored_at=%v pending=%v, want never scored and pending", a.RiskScoredAt(), a.RiskScorePending())
	}
	fx.drain(t, aid)
	a = fx.get(t, tid, aid)
	if a.RiskScoredAt() == nil || a.RiskScorePending() {
		t.Fatalf("after worker: scored_at=%v pending=%v", a.RiskScoredAt(), a.RiskScorePending())
	}
	baseline := a.RiskScore()

	// Findings written by the ingest batch path queue the asset.
	ids := fx.ingestFindings(t, tid, aid, vulnerability.SeverityCritical, 5, "crit")
	if !fx.queued(t, aid) {
		t.Fatal("ingested findings did not queue the asset")
	}
	fx.drain(t, aid)
	withFindings := fx.get(t, tid, aid).RiskScore()
	if withFindings <= baseline {
		t.Fatalf("score with 5 critical findings = %d, want above the baseline %d", withFindings, baseline)
	}

	// Marking them false positive (bulk triage) removes their weight.
	if err := fx.findings.UpdateStatusBatch(context.Background(), tid, ids, vulnerability.FindingStatusFalsePositive, "not real", nil, ""); err != nil {
		t.Fatal(err)
	}
	if !fx.queued(t, aid) {
		t.Fatal("status change did not queue the asset")
	}
	fx.drain(t, aid)
	a = fx.get(t, tid, aid)
	if a.RiskScore() != baseline {
		t.Fatalf("score after false positive = %d, want baseline %d", a.RiskScore(), baseline)
	}
	if a.FindingCount() != 0 {
		t.Fatalf("finding_count after false positive = %d, want 0", a.FindingCount())
	}
}

func TestAssetRisk_AcceptedFindingsCarryNoRisk(t *testing.T) {
	fx := newRiskFixture(t)
	tid := fx.newTenant(t)
	aid := fx.ingestAsset(t, tid, "github.com/acme/risk-accepted")
	fx.drain(t, aid)
	baseline := fx.get(t, tid, aid).RiskScore()

	fx.ingestFindings(t, tid, aid, vulnerability.SeverityHigh, 3, "acc")
	// The lifecycle reaches accepted through an approval; the score only
	// cares about the stored status, so set it directly.
	if _, err := fx.db.Exec(`UPDATE findings SET status = 'accepted' WHERE tenant_id = $1 AND asset_id = $2`, tid.String(), aid.String()); err != nil {
		t.Fatal(err)
	}
	fx.drain(t, aid)
	if got := fx.get(t, tid, aid).RiskScore(); got != baseline {
		t.Fatalf("score with only accepted findings = %d, want baseline %d", got, baseline)
	}
}

func TestAssetRisk_CriticalityChangeRescores(t *testing.T) {
	fx := newRiskFixture(t)
	tid := fx.newTenant(t)
	aid := fx.ingestAsset(t, tid, "github.com/acme/risk-crit")
	fx.drain(t, aid)
	before := fx.get(t, tid, aid).RiskScore()

	if _, err := fx.db.Exec(`UPDATE assets SET criticality = 'critical' WHERE tenant_id = $1 AND id = $2`, tid.String(), aid.String()); err != nil {
		t.Fatal(err)
	}
	if !fx.queued(t, aid) {
		t.Fatal("criticality change did not queue the asset")
	}
	fx.drain(t, aid)
	if after := fx.get(t, tid, aid).RiskScore(); after <= before {
		t.Fatalf("score after criticality medium->critical = %d, want above %d", after, before)
	}

	// An edit that does not touch a score input does not queue it.
	if _, err := fx.db.Exec(`UPDATE assets SET description = 'renamed' WHERE tenant_id = $1 AND id = $2`, tid.String(), aid.String()); err != nil {
		t.Fatal(err)
	}
	if fx.queued(t, aid) {
		t.Fatal("a description edit queued the asset")
	}
}

func TestAssetRisk_BulkImportCoalescesPerAsset(t *testing.T) {
	fx := newRiskFixture(t)
	tid := fx.newTenant(t)
	aid := fx.ingestAsset(t, tid, "github.com/acme/risk-bulk")
	fx.drain(t, aid)

	for b := 0; b < 4; b++ {
		fx.ingestFindings(t, tid, aid, vulnerability.SeverityMedium, 250, fmt.Sprintf("bulk%d", b))
	}
	var rows int
	if err := fx.db.QueryRow(`SELECT COUNT(*) FROM asset_risk_queue WHERE tenant_id = $1`, tid.String()).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Fatalf("1000 findings in 4 batches queued %d rows, want 1", rows)
	}
	fx.drain(t, aid)
	if a := fx.get(t, tid, aid); a.FindingCount() != 1000 || a.RiskScorePending() {
		t.Fatalf("after drain: finding_count=%d pending=%v", a.FindingCount(), a.RiskScorePending())
	}
}

func TestAssetRisk_TenantIsolation(t *testing.T) {
	fx := newRiskFixture(t)
	tenantA := fx.newTenant(t)
	tenantB := fx.newTenant(t)
	assetA := fx.ingestAsset(t, tenantA, "github.com/acme/risk-a")
	assetB := fx.ingestAsset(t, tenantB, "github.com/acme/risk-b")
	fx.drain(t, assetA, assetB)
	scoreB := fx.get(t, tenantB, assetB).RiskScore()

	// Tenant A's findings queue only tenant A's asset.
	fx.ingestFindings(t, tenantA, assetA, vulnerability.SeverityCritical, 3, "iso")
	if fx.queued(t, assetB) {
		t.Fatal("tenant A's findings queued tenant B's asset")
	}

	// Enqueue with tenant A cannot queue tenant B's asset.
	if err := fx.queue.Enqueue(context.Background(), tenantA, []shared.ID{assetB}); err != nil {
		t.Fatal(err)
	}
	if fx.queued(t, assetB) {
		t.Fatal("Enqueue(tenant A, asset of B) queued it")
	}

	// A rescore under tenant A cannot read or write tenant B's asset: give
	// B a critical finding without letting the worker run, then rescore it
	// as tenant A.
	fx.ingestFindings(t, tenantB, assetB, vulnerability.SeverityCritical, 5, "isob")
	if _, err := fx.db.Exec(`DELETE FROM asset_risk_queue WHERE tenant_id = $1`, tenantB.String()); err != nil {
		t.Fatal(err)
	}
	if err := fx.svc.UpdateRiskScores(context.Background(), tenantA, []shared.ID{assetB}); err != nil {
		t.Fatal(err)
	}
	if got := fx.get(t, tenantB, assetB).RiskScore(); got != scoreB {
		t.Fatalf("tenant A's rescore changed tenant B's score: %d -> %d", scoreB, got)
	}
	// Tenant B's own rescore does move it.
	if err := fx.svc.UpdateRiskScores(context.Background(), tenantB, []shared.ID{assetB}); err != nil {
		t.Fatal(err)
	}
	if got := fx.get(t, tenantB, assetB).RiskScore(); got <= scoreB {
		t.Fatalf("tenant B's own rescore = %d, want above %d", got, scoreB)
	}
	fx.drain(t, assetA)
}

func TestAssetRisk_ReconcileQueuesBehindEvents(t *testing.T) {
	fx := newRiskFixture(t)
	tid := fx.newTenant(t)
	aid := fx.ingestAsset(t, tid, "github.com/acme/risk-reconcile")
	fx.drain(t, aid)

	if _, err := fx.svc.EnqueueRiskReconcile(context.Background(), 3600e9); err != nil {
		t.Fatal(err)
	}
	var due bool
	if err := fx.db.QueryRow(`SELECT enqueued_at <= now() FROM asset_risk_queue WHERE asset_id = $1`, aid.String()).Scan(&due); err != nil {
		t.Fatal(err)
	}
	if due {
		t.Fatal("reconcile row is due now, want it behind event rows")
	}
	// A real change pulls it forward.
	fx.ingestFindings(t, tid, aid, vulnerability.SeverityLow, 1, "rec")
	if err := fx.db.QueryRow(`SELECT enqueued_at <= now() FROM asset_risk_queue WHERE asset_id = $1`, aid.String()).Scan(&due); err != nil {
		t.Fatal(err)
	}
	if !due {
		t.Fatal("a finding did not pull the reconcile row forward")
	}
	fx.drain(t, aid)
	_, _ = fx.db.Exec(`DELETE FROM asset_risk_queue WHERE enqueued_at > now() AND tenant_id = $1`, tid.String())
}
