package finding

import (
	"context"
	"strings"
	"testing"

	"github.com/openctemio/api/pkg/domain/asset"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
)

// stubOwnerLookup reports owner presence for a fixed set of asset IDs.
type stubOwnerLookup struct {
	owned map[shared.ID]bool
	calls int
}

func (s *stubOwnerLookup) HasOwnerByAssetIDs(
	_ context.Context, _ shared.ID, assetIDs []shared.ID,
) (map[shared.ID]bool, error) {
	s.calls++
	out := map[shared.ID]bool{}
	for _, id := range assetIDs {
		if s.owned[id] {
			out[id] = true
		}
	}
	return out, nil
}

// stubFloorPolicy is a fixed on/off ownership-floor toggle.
type stubFloorPolicy struct {
	on    bool
	calls int
}

func (s *stubFloorPolicy) FloorUnownedAtP2(_ context.Context, _ shared.ID) bool {
	s.calls++
	return s.on
}

// lowSeverityUnreachableFinding classifies P3 (low severity, unknown exposure →
// not reachable) so the ownership floor is the only thing that can raise it.
func lowSeverityUnreachableFinding(t *testing.T, tenantID shared.ID) (*vulnerability.Finding, *asset.Asset) {
	t.Helper()
	a, err := asset.NewAssetWithTenant(tenantID, "host-01", asset.AssetTypeHost, asset.CriticalityLow)
	if err != nil {
		t.Fatalf("NewAssetWithTenant: %v", err)
	}
	f, err := vulnerability.NewFinding(
		tenantID, a.ID(), vulnerability.FindingSourceSCA, "trivy",
		vulnerability.SeverityLow, "low dep",
	)
	if err != nil {
		t.Fatalf("NewFinding: %v", err)
	}
	return f, a
}

// With the tenant toggle ON, a P3 finding on an UNOWNED asset floors to P2 and
// the reason records it.
func TestClassifyFinding_OwnershipFloor_EnabledUnownedFloorsToP2(t *testing.T) {
	tenantID := shared.NewID()
	f, a := lowSeverityUnreachableFinding(t, tenantID)

	svc := newControlSvc()
	owners := &stubOwnerLookup{owned: map[shared.ID]bool{}} // asset absent → unowned
	policy := &stubFloorPolicy{on: true}
	svc.SetAssetOwnerLookup(owners)
	svc.SetOwnershipFloorPolicy(policy)

	if err := svc.ClassifyFinding(context.Background(), tenantID, f, a); err != nil {
		t.Fatalf("ClassifyFinding: %v", err)
	}
	if policy.calls == 0 {
		t.Fatal("ClassifyFinding must consult the ownership-floor policy")
	}
	if owners.calls == 0 {
		t.Fatal("enabled floor must consult the owner-presence lookup")
	}
	if got := f.PriorityClass(); got == nil || *got != vulnerability.PriorityP2 {
		t.Fatalf("unowned P3 must floor to P2 when enabled, got %v (%s)", got, f.PriorityClassReason())
	}
	if reason := f.PriorityClassReason(); !strings.Contains(reason, "no assigned owner") {
		t.Fatalf("reason should record the ownership floor, got %q", reason)
	}
}

// With the toggle ON but the asset OWNED, the finding stays P3.
func TestClassifyFinding_OwnershipFloor_EnabledOwnedStaysP3(t *testing.T) {
	tenantID := shared.NewID()
	f, a := lowSeverityUnreachableFinding(t, tenantID)

	svc := newControlSvc()
	svc.SetAssetOwnerLookup(&stubOwnerLookup{owned: map[shared.ID]bool{a.ID(): true}})
	svc.SetOwnershipFloorPolicy(&stubFloorPolicy{on: true})

	if err := svc.ClassifyFinding(context.Background(), tenantID, f, a); err != nil {
		t.Fatalf("ClassifyFinding: %v", err)
	}
	if got := f.PriorityClass(); got == nil || *got != vulnerability.PriorityP3 {
		t.Fatalf("owned P3 must stay P3, got %v (%s)", got, f.PriorityClassReason())
	}
	if reason := f.PriorityClassReason(); strings.Contains(reason, "no assigned owner") {
		t.Fatalf("owned finding must not carry the floor reason, got %q", reason)
	}
}

// With the toggle OFF, an unowned asset is NOT floored, and the owner lookup is
// never even consulted (no cost, no silent re-prioritization).
func TestClassifyFinding_OwnershipFloor_DisabledLeavesP3AndSkipsLookup(t *testing.T) {
	tenantID := shared.NewID()
	f, a := lowSeverityUnreachableFinding(t, tenantID)

	svc := newControlSvc()
	owners := &stubOwnerLookup{owned: map[shared.ID]bool{}} // would report unowned
	svc.SetAssetOwnerLookup(owners)
	svc.SetOwnershipFloorPolicy(&stubFloorPolicy{on: false})

	if err := svc.ClassifyFinding(context.Background(), tenantID, f, a); err != nil {
		t.Fatalf("ClassifyFinding: %v", err)
	}
	if got := f.PriorityClass(); got == nil || *got != vulnerability.PriorityP3 {
		t.Fatalf("disabled floor must leave P3 unchanged, got %v (%s)", got, f.PriorityClassReason())
	}
	if owners.calls != 0 {
		t.Fatalf("disabled floor must NOT consult the owner lookup, got %d calls", owners.calls)
	}
	if reason := f.PriorityClassReason(); strings.Contains(reason, "no assigned owner") {
		t.Fatalf("disabled floor must add no reason, got %q", reason)
	}
}

// Nil owner lookup with the toggle on is fail-safe: no floor, no crash.
func TestClassifyFinding_OwnershipFloor_NilLookupUnchanged(t *testing.T) {
	tenantID := shared.NewID()
	f, a := lowSeverityUnreachableFinding(t, tenantID)

	svc := newControlSvc()
	svc.SetOwnershipFloorPolicy(&stubFloorPolicy{on: true}) // enabled, but no lookup wired

	if err := svc.ClassifyFinding(context.Background(), tenantID, f, a); err != nil {
		t.Fatalf("ClassifyFinding: %v", err)
	}
	if got := f.PriorityClass(); got == nil || *got != vulnerability.PriorityP3 {
		t.Fatalf("nil owner lookup must leave P3 unchanged (fail-safe), got %v", got)
	}
}

// The batch path (main ingest/sweep) applies the same floor with a single
// owner-presence lookup for the whole batch.
func TestEnrichAndClassifyBatch_OwnershipFloor_EnabledUnownedFloorsToP2(t *testing.T) {
	tenantID := shared.NewID()
	f, a := lowSeverityUnreachableFinding(t, tenantID)

	svc := newControlSvc()
	owners := &stubOwnerLookup{owned: map[shared.ID]bool{}}
	svc.SetAssetOwnerLookup(owners)
	svc.SetOwnershipFloorPolicy(&stubFloorPolicy{on: true})

	assets := map[shared.ID]*asset.Asset{a.ID(): a}
	if err := svc.EnrichAndClassifyBatch(context.Background(), tenantID,
		[]*vulnerability.Finding{f}, assets); err != nil {
		t.Fatalf("EnrichAndClassifyBatch: %v", err)
	}
	if owners.calls != 1 {
		t.Fatalf("batch path should call the owner lookup exactly once, got %d", owners.calls)
	}
	if got := f.PriorityClass(); got == nil || *got != vulnerability.PriorityP2 {
		t.Fatalf("batch: unowned P3 must floor to P2, got %v (%s)", got, f.PriorityClassReason())
	}
}
