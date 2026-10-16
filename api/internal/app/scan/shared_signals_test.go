package scan

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type recordingSharedUse struct {
	deny    map[shared.ID]int
	targets map[shared.ID][]string
}

func (r *recordingSharedUse) ObserveSharedTargets(_ context.Context, tenantID shared.ID, targets []string) {
	r.targets[tenantID] = append(r.targets[tenantID], targets...)
}

func (r *recordingSharedUse) ObserveDenyListHits(_ context.Context, tenantID shared.ID, n int) {
	r.deny[tenantID] += n
}

// Every target the platform deny list refuses counts for the organization
// that asked, and only for it; other refusals are not deny-list hits.
func TestDenyListHitsCountedPerOrganization(t *testing.T) {
	gate := &stubGate{blockedTyped: map[string]attribution.State{
		"denied-one.example": attribution.StatePlatformDenied,
		"denied-two.example": attribution.StatePlatformDenied,
		"www.rejected.com":   attribution.StateRejected,
		"unattributed.net":   attribution.StateUnattributed,
	}}
	obs := &recordingSharedUse{deny: map[shared.ID]int{}, targets: map[shared.ID][]string{}}
	svc := &Service{attributionGate: gate, logger: logger.NewNop()}
	svc.SetSharedUseObserver(obs)
	orgA, orgB := shared.NewID(), shared.NewID()

	_ = svc.refuseUnownedTargets(context.Background(), orgA, "quick_scan",
		[]string{"denied-one.example", "denied-two.example", "www.rejected.com", "unattributed.net"}, false)
	if obs.deny[orgA] != 2 {
		t.Fatalf("deny-list hits of A = %d, want 2", obs.deny[orgA])
	}
	if obs.deny[orgB] != 0 {
		t.Fatalf("B was charged the hits of A: %d", obs.deny[orgB])
	}
}
