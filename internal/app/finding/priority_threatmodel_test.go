package finding

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/api/pkg/domain/asset"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/logger"
)

// --- Part 1: threat-model signal raises priority ---------------------------

// An asset ON an open, high-score modeled threat path is treated as reachable,
// so a KEV finding on an otherwise-unreachable private asset becomes P0 — the
// same close-the-loop promotion attack-path reachability already gives.
func TestBuildPriorityContext_OpenThreatPathPromotesToP0(t *testing.T) {
	svc := newReachabilitySvc()
	a := newTestAsset(t, asset.ExposurePrivate)
	threatened := map[string]bool{a.ID().String(): true}

	ctx := svc.buildPriorityContext(newTestFinding(t), a, "", nil, threatened, nil, nil)

	if !ctx.OnOpenThreatPath {
		t.Fatal("asset in the threatened set must have OnOpenThreatPath=true")
	}
	// Crucially it must NOT be conflated with attack-surface reachability.
	if ctx.IsInternetAccessible {
		t.Fatal("threat-model signal must not set IsInternetAccessible (kept distinct for is_reachable)")
	}
	if got := vulnerability.ClassifyPriority(ctx); got.Class != vulnerability.PriorityP0 {
		t.Fatalf("KEV on an open-threat-path asset should be P0, got %s (%s)", got.Class, got.Reason)
	}
}

// The exact same finding on an identical asset that is NOT on any threat path
// must classify lower — proving the signal is what raised it.
func TestBuildPriorityContext_ThreatPathRaisesRelativeToOffPath(t *testing.T) {
	svc := newReachabilitySvc()

	onPath := newTestAsset(t, asset.ExposurePrivate)
	offPath := newTestAsset(t, asset.ExposurePrivate)
	threatened := map[string]bool{onPath.ID().String(): true}

	onCtx := svc.buildPriorityContext(newTestFinding(t), onPath, "", nil, threatened, nil, nil)
	offCtx := svc.buildPriorityContext(newTestFinding(t), offPath, "", nil, threatened, nil, nil)

	on := vulnerability.ClassifyPriority(onCtx)
	off := vulnerability.ClassifyPriority(offCtx)

	if !on.Class.IsHigherThan(off.Class) {
		t.Fatalf("on-threat-path finding (%s) should outrank off-path (%s)", on.Class, off.Class)
	}
	if off.Class == vulnerability.PriorityP0 {
		t.Fatalf("off-path KEV on a private, non-crown-jewel asset must not be P0, got %s", off.Reason)
	}
}

// A medium (non-KEV) finding is raised P3→P2 by the threat-path reachability
// gate — the signal must lift more than just the KEV case.
func TestBuildPriorityContext_ThreatPathRaisesMediumFinding(t *testing.T) {
	svc := newReachabilitySvc()

	mkMedium := func() *vulnerability.Finding {
		f, err := vulnerability.NewFinding(shared.NewID(), shared.NewID(), vulnerability.FindingSourceSCA, "trivy", vulnerability.SeverityMedium, "medium dep")
		if err != nil {
			t.Fatalf("NewFinding: %v", err)
		}
		return f
	}

	a := newTestAsset(t, asset.ExposurePrivate)
	off := vulnerability.ClassifyPriority(svc.buildPriorityContext(mkMedium(), a, "", nil, nil, nil, nil))
	on := vulnerability.ClassifyPriority(svc.buildPriorityContext(mkMedium(), a, "", nil, map[string]bool{a.ID().String(): true}, nil, nil))

	if off.Class != vulnerability.PriorityP3 {
		t.Fatalf("off-path medium on private asset should be P3, got %s", off.Class)
	}
	if on.Class != vulnerability.PriorityP2 {
		t.Fatalf("on-path medium should be raised to P2, got %s (%s)", on.Class, on.Reason)
	}
}

// Fail-safe: no threat model (nil/empty set) leaves classification unchanged.
func TestBuildPriorityContext_NoThreatModelNoChange(t *testing.T) {
	svc := newReachabilitySvc()
	a := newTestAsset(t, asset.ExposurePrivate)

	base := vulnerability.ClassifyPriority(svc.buildPriorityContext(newTestFinding(t), a, "", nil, nil, nil, nil))
	empty := vulnerability.ClassifyPriority(svc.buildPriorityContext(newTestFinding(t), a, "", nil, map[string]bool{}, nil, nil))

	if base.Class != empty.Class {
		t.Fatalf("nil vs empty threat set must classify identically: %s vs %s", base.Class, empty.Class)
	}
	if base.Class == vulnerability.PriorityP0 {
		t.Fatalf("with no threat model a private-asset KEV must not be P0, got %s", base.Reason)
	}
}

// The threatened set only promotes assets actually in it — no leak to others.
func TestBuildPriorityContext_ThreatSetDoesNotLeak(t *testing.T) {
	svc := newReachabilitySvc()
	a := newTestAsset(t, asset.ExposurePrivate)
	ctx := svc.buildPriorityContext(newTestFinding(t), a, "", nil, map[string]bool{"some-other-asset": true}, nil, nil)
	if ctx.OnOpenThreatPath {
		t.Fatal("an asset absent from the threatened set must have OnOpenThreatPath=false")
	}
}

// --- service-level: oracle wiring, nil-safety, no-N+1 ----------------------

type fakeThreatOracle struct {
	set   map[string]bool
	err   error
	calls int
}

func (o *fakeThreatOracle) OnOpenThreatPath(_ context.Context, _ shared.ID) (map[string]bool, error) {
	o.calls++
	if o.err != nil {
		return nil, o.err
	}
	return o.set, nil
}

func newClassifySvc() *PriorityClassificationService {
	return &PriorityClassificationService{
		ruleRepo:  explainRuleRepo{},
		auditRepo: noopAudit{},
		logger:    logger.NewNop(),
	}
}

type noopAudit struct{}

func (noopAudit) LogChange(_ context.Context, _ PriorityAuditEntry) error { return nil }

// threatenedSet returns nil for a nil oracle and never panics.
func TestThreatenedSet_NilOracle(t *testing.T) {
	svc := newClassifySvc()
	if got := svc.threatenedSet(context.Background(), shared.NewID()); got != nil {
		t.Fatalf("nil oracle should yield nil set, got %v", got)
	}
}

// An oracle error degrades to a nil set (no effect), not a failure/panic.
func TestThreatenedSet_ErrorDegrades(t *testing.T) {
	svc := newClassifySvc()
	svc.SetThreatModelOracle(&fakeThreatOracle{err: errors.New("db down")})
	if got := svc.threatenedSet(context.Background(), shared.NewID()); got != nil {
		t.Fatalf("oracle error should yield nil set, got %v", got)
	}
}

// EnrichAndClassifyBatch must consult the threat oracle exactly ONCE for the
// whole batch (no per-finding N+1), and the on-path finding must be raised.
func TestEnrichAndClassifyBatch_ThreatOracleCalledOncePerBatch(t *testing.T) {
	svc := newClassifySvc()
	svc.epssRepo = emptyEPSS{}
	svc.kevRepo = emptyKEV{}

	tenant := shared.NewID()
	onPath := newTestAsset(t, asset.ExposurePrivate)
	offPath := newTestAsset(t, asset.ExposurePrivate)
	oracle := &fakeThreatOracle{set: map[string]bool{onPath.ID().String(): true}}
	svc.SetThreatModelOracle(oracle)

	mkKEV := func(a *asset.Asset) *vulnerability.Finding {
		f, err := vulnerability.NewFinding(tenant, a.ID(), vulnerability.FindingSourceSCA, "trivy", vulnerability.SeverityCritical, "kev")
		if err != nil {
			t.Fatalf("NewFinding: %v", err)
		}
		f.SetIsInKEV(true)
		return f
	}
	fOn := mkKEV(onPath)
	fOff := mkKEV(offPath)

	assets := map[shared.ID]*asset.Asset{onPath.ID(): onPath, offPath.ID(): offPath}
	if err := svc.EnrichAndClassifyBatch(context.Background(), tenant, []*vulnerability.Finding{fOn, fOff}, assets); err != nil {
		t.Fatalf("EnrichAndClassifyBatch: %v", err)
	}

	if oracle.calls != 1 {
		t.Fatalf("threat oracle must be called once per batch (no N+1), got %d calls", oracle.calls)
	}
	if pc := fOn.PriorityClass(); pc == nil || *pc != vulnerability.PriorityP0 {
		t.Fatalf("on-threat-path KEV finding should be P0, got %v", pc)
	}
	if pc := fOff.PriorityClass(); pc != nil && *pc == vulnerability.PriorityP0 {
		t.Fatalf("off-path KEV finding on a private, non-crown-jewel asset must not be P0")
	}
}

// --- Part 2: is_reachable is persisted from the reachability oracle ---------

// With the reachability oracle available, a reachable asset's finding gets
// is_reachable persisted true; an unreachable one gets false.
func TestEnrichAndClassifyBatch_PersistsIsReachable(t *testing.T) {
	svc := newClassifySvc()
	svc.epssRepo = emptyEPSS{}
	svc.kevRepo = emptyKEV{}

	tenant := shared.NewID()
	pub := newTestAsset(t, asset.ExposurePublic)
	priv := newTestAsset(t, asset.ExposurePrivate)
	// Reachability oracle available (non-nil set) → persistence is enabled.
	svc.SetReachabilityOracle(&fakeReachOracle{set: map[string]bool{}})

	mk := func(a *asset.Asset) *vulnerability.Finding {
		f, err := vulnerability.NewFinding(tenant, a.ID(), vulnerability.FindingSourceSCA, "trivy", vulnerability.SeverityHigh, "x")
		if err != nil {
			t.Fatalf("NewFinding: %v", err)
		}
		return f
	}
	fPub := mk(pub)
	fPriv := mk(priv)

	assets := map[shared.ID]*asset.Asset{pub.ID(): pub, priv.ID(): priv}
	if err := svc.EnrichAndClassifyBatch(context.Background(), tenant, []*vulnerability.Finding{fPub, fPriv}, assets); err != nil {
		t.Fatalf("batch: %v", err)
	}

	if !fPub.IsReachable() {
		t.Fatal("public asset finding should have is_reachable persisted true")
	}
	if fPub.ReachableFromCount() == 0 {
		t.Fatal("public asset finding should have a non-zero reachable_from_count")
	}
	if fPriv.IsReachable() {
		t.Fatal("private asset finding should have is_reachable persisted false")
	}
}

// An asset promoted by the attack-path reachability oracle persists is_reachable
// true even though its own exposure is private.
func TestEnrichAndClassifyBatch_PersistsAttackPathReachable(t *testing.T) {
	svc := newClassifySvc()
	svc.epssRepo = emptyEPSS{}
	svc.kevRepo = emptyKEV{}

	tenant := shared.NewID()
	priv := newTestAsset(t, asset.ExposurePrivate)
	svc.SetReachabilityOracle(&fakeReachOracle{set: map[string]bool{priv.ID().String(): true}})

	f, err := vulnerability.NewFinding(tenant, priv.ID(), vulnerability.FindingSourceSCA, "trivy", vulnerability.SeverityHigh, "x")
	if err != nil {
		t.Fatalf("NewFinding: %v", err)
	}
	if err := svc.EnrichAndClassifyBatch(context.Background(), tenant, []*vulnerability.Finding{f}, map[shared.ID]*asset.Asset{priv.ID(): priv}); err != nil {
		t.Fatalf("batch: %v", err)
	}
	if !f.IsReachable() {
		t.Fatal("attack-path-reachable private asset finding should persist is_reachable true")
	}
}

// Fail-safe: reachability oracle unavailable → is_reachable is left untouched
// (NOT forced to false), even for a public asset.
func TestEnrichAndClassifyBatch_OracleUnavailableLeavesReachabilityUntouched(t *testing.T) {
	svc := newClassifySvc()
	svc.epssRepo = emptyEPSS{}
	svc.kevRepo = emptyKEV{}
	// No reachability oracle wired → reachableSet returns nil.

	tenant := shared.NewID()
	pub := newTestAsset(t, asset.ExposurePublic)
	f, err := vulnerability.NewFinding(tenant, pub.ID(), vulnerability.FindingSourceSCA, "trivy", vulnerability.SeverityHigh, "x")
	if err != nil {
		t.Fatalf("NewFinding: %v", err)
	}
	// Seed a pre-existing value to prove it is not clobbered.
	f.SetReachability(true, 3)

	if err := svc.EnrichAndClassifyBatch(context.Background(), tenant, []*vulnerability.Finding{f}, map[shared.ID]*asset.Asset{pub.ID(): pub}); err != nil {
		t.Fatalf("batch: %v", err)
	}
	if !f.IsReachable() || f.ReachableFromCount() != 3 {
		t.Fatalf("oracle unavailable must leave is_reachable/count untouched, got reachable=%v count=%d", f.IsReachable(), f.ReachableFromCount())
	}
}

// --- shared fakes ----------------------------------------------------------

type fakeReachOracle struct{ set map[string]bool }

func (o *fakeReachOracle) ReachableFromPublic(_ context.Context, _ shared.ID) (map[string]bool, error) {
	return o.set, nil
}

type emptyEPSS struct{}

func (emptyEPSS) GetByCVEIDs(_ context.Context, _ []string) (map[string]EPSSData, error) {
	return map[string]EPSSData{}, nil
}

type emptyKEV struct{}

func (emptyKEV) GetByCVEIDs(_ context.Context, _ []string) (map[string]KEVData, error) {
	return map[string]KEVData{}, nil
}
