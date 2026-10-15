package integration

import (
	"context"
	"encoding/json"
	"testing"

	assetapp "github.com/openctemio/openctem/api/internal/app/asset"
	"github.com/openctemio/openctem/api/internal/app/finding"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// The preview of a risk scoring settings change is what applying it does:
// the same engine and inputs, over every asset (and, for the ownership
// floor, every open finding) of the tenant and of no other tenant
// (docs/architecture/scoring-versions.md, "Preview before apply").

func (fx scoringFixture) riskService(t *testing.T) *assetapp.AssetService {
	t.Helper()
	pdb := &postgres.DB{DB: fx.db}
	svc := assetapp.NewAssetService(fx.assets, logger.NewNop())
	svc.SetRiskQueue(postgres.NewAssetRiskQueueRepository(pdb), fx.assets)
	svc.SetScoringVersions(fx.scoring)
	svc.SetScoringConfigProvider(assetapp.NewTenantScoringConfigProvider(postgres.NewTenantRepository(pdb)))
	return svc
}

func (fx scoringFixture) drainRisk(t *testing.T, svc *assetapp.AssetService, tid shared.ID) {
	t.Helper()
	for i := 0; i < 200; i++ {
		var n int
		if err := fx.db.QueryRow(`SELECT COUNT(*) FROM asset_risk_queue WHERE tenant_id = $1`, tid.String()).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			return
		}
		if _, err := svc.ProcessRiskQueue(context.Background(), 1000); err != nil {
			t.Fatalf("process risk queue: %v", err)
		}
	}
	t.Fatal("risk queue did not drain")
}

func (fx scoringFixture) scores(t *testing.T, tid shared.ID) map[string]int {
	t.Helper()
	rows, err := fx.db.Query(`SELECT id, risk_score FROM assets WHERE tenant_id = $1 AND deleted_at IS NULL`, tid.String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]int{}
	for rows.Next() {
		var id string
		var s int
		if err := rows.Scan(&id, &s); err != nil {
			t.Fatal(err)
		}
		out[id] = s
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func (fx scoringFixture) setRiskScoring(t *testing.T, tid shared.ID, rs tenant.RiskScoringSettings) {
	t.Helper()
	raw, err := json.Marshal(rs)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fx.db.Exec(`UPDATE tenants SET settings = jsonb_set(COALESCE(settings, '{}'::jsonb), '{risk_scoring}', $2::jsonb) WHERE id = $1`,
		tid.String(), string(raw)); err != nil {
		t.Fatal(err)
	}
}

func TestScoringPreview_AssetImpactEqualsApply(t *testing.T) {
	fx := newScoringFixture(t)
	ctx := context.Background()
	tid := fx.newTenant(t)
	other := fx.newTenant(t)
	svc := fx.riskService(t)

	sevs := []vulnerability.Severity{vulnerability.SeverityCritical, vulnerability.SeverityHigh, vulnerability.SeverityMedium, vulnerability.SeverityLow}
	for i, sev := range sevs {
		aid := fx.newAsset(t, tid, "github.com/acme/preview-"+string(sev))
		for j := 0; j <= i; j++ {
			fx.newFinding(t, tid, aid, sev, "preview-"+string(sev)+"-"+string(rune('a'+j)))
		}
	}
	oaid := fx.newAsset(t, other, "github.com/acme/preview-other")
	fx.newFinding(t, other, oaid, vulnerability.SeverityCritical, "preview-other")
	base := tenant.DefaultRiskScoringPreset()
	fx.setRiskScoring(t, tid, base)
	fx.drainRisk(t, svc, tid)
	fx.drainRisk(t, svc, other)
	before := fx.scores(t, tid)
	otherBefore := fx.scores(t, other)

	// The admin halves every criticality factor and raises the bands.
	next := base
	next.CriticalityScores = tenant.CriticalityScoreConfig{Critical: 50, High: 45, Medium: 40, Low: 30, None: 40}
	next.RiskLevels.HighMin = 70
	impact, err := svc.PreviewRiskImpact(ctx, tid, assetapp.MapTenantToAssetScoringConfig(&next))
	if err != nil {
		t.Fatal(err)
	}
	if impact.TotalAssets != len(before) {
		t.Fatalf("preview counted %d assets, the tenant has %d (another tenant's assets must not count)", impact.TotalAssets, len(before))
	}
	if impact.Changed == 0 {
		t.Fatal("the change should move scores")
	}

	// Apply: the settings trigger queues every asset; the worker rescores.
	fx.setRiskScoring(t, tid, next)
	fx.drainRisk(t, svc, tid)
	after := fx.scores(t, tid)

	changed := 0
	for id, s := range after {
		if s != before[id] {
			changed++
		}
	}
	if changed != impact.Changed {
		t.Fatalf("preview said %d assets change, apply changed %d", impact.Changed, changed)
	}
	for _, c := range impact.TopChanges {
		if after[c.AssetID] != c.NewScore {
			t.Fatalf("asset %s: preview %d, applied %d", c.AssetName, c.NewScore, after[c.AssetID])
		}
	}
	nextCfg := assetapp.MapTenantToAssetScoringConfig(&next)
	baseCfg := assetapp.MapTenantToAssetScoringConfig(&base)
	moved := 0
	for id, s := range after {
		if baseCfg.Level(before[id]) != nextCfg.Level(s) {
			moved++
		}
	}
	if moved != impact.ChangedBands {
		t.Fatalf("preview said %d assets change band, apply moved %d", impact.ChangedBands, moved)
	}
	for id, s := range fx.scores(t, other) {
		if otherBefore[id] != s {
			t.Fatal("another tenant's scores moved")
		}
	}
}

// The ownership floor preview counts the open findings that would change
// class, exactly as the finding-priority worker then changes them; closed
// findings and other tenants are never counted.
func TestScoringPreview_FloorImpactEqualsApply(t *testing.T) {
	fx := newScoringFixture(t)
	ctx := context.Background()
	pdb := &postgres.DB{DB: fx.db}
	fx.cls.SetAssetOwnerLookup(postgres.NewAssetOwnershipLookupRepo(fx.db))
	fx.cls.SetOwnershipFloorPolicy(finding.NewTenantOwnershipFloorPolicy(postgres.NewTenantRepository(pdb)))
	tid := fx.newTenant(t)
	other := fx.newTenant(t)

	aid := fx.newAsset(t, tid, "github.com/acme/floor-unowned")
	low1 := fx.newFinding(t, tid, aid, vulnerability.SeverityLow, "floor-low-1")
	fx.newFinding(t, tid, aid, vulnerability.SeverityLow, "floor-low-2")
	closed := fx.newFinding(t, tid, aid, vulnerability.SeverityLow, "floor-low-closed")
	oaid := fx.newAsset(t, other, "github.com/acme/floor-other")
	fx.newFinding(t, other, oaid, vulnerability.SeverityLow, "floor-other")
	fx.drain(t, aid, oaid)
	if _, err := fx.db.Exec(`UPDATE findings SET status = 'resolved', resolved_at = now() WHERE tenant_id = $1 AND id = $2`,
		tid.String(), closed.String()); err != nil {
		t.Fatal(err)
	}
	beforeClass := fx.row(t, tid, low1).class

	impact, err := fx.cls.PreviewOwnershipFloor(ctx, tid, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if impact.OpenFindings != 2 {
		t.Fatalf("preview saw %d open findings, want 2 (closed and other tenants excluded)", impact.OpenFindings)
	}

	rs := tenant.DefaultRiskScoringPreset()
	rs.FloorUnownedAtP2 = true
	fx.setRiskScoring(t, tid, rs)
	fx.drain(t, aid)

	rows, err := fx.db.Query(`SELECT priority_class FROM findings WHERE tenant_id = $1 AND status = 'new'`, tid.String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	changed := 0
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			t.Fatal(err)
		}
		if c != beforeClass {
			changed++
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if changed != impact.Changed {
		t.Fatalf("preview said %d findings change class, apply changed %d", impact.Changed, changed)
	}
	if impact.Changed == 0 {
		t.Fatalf("the floor should raise the unowned low findings (class %s)", beforeClass)
	}
	if c := fx.row(t, tid, closed).class; c != beforeClass {
		t.Fatalf("closed finding class moved to %s", c)
	}
}
