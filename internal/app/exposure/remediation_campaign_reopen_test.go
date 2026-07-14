package exposure

import (
	"context"
	"testing"

	"github.com/openctemio/api/pkg/domain/remediation"
	"github.com/openctemio/api/pkg/domain/shared"
)

// A completed campaign that tracks a regressed finding must reopen; a
// non-completed campaign (or one not tracking the finding) must not.
func TestReopenCampaignsForFinding(t *testing.T) {
	repo := newFakeCampaignRepo()
	svc := newService(repo, &fakeCounter{})

	tid := shared.NewID()
	findingID := shared.NewID()

	// Completed campaign tracking the finding — should reopen.
	hit, _ := remediation.NewCampaign(tid, "hit", remediation.CampaignPriorityHigh)
	hit.SetFindingFilter(map[string]any{"finding_ids": []string{findingID.String()}})
	_ = hit.Activate()
	_ = hit.Complete()
	repo.store[hit.ID().String()] = hit

	// Completed campaign NOT tracking it — should stay completed.
	miss, _ := remediation.NewCampaign(tid, "miss", remediation.CampaignPriorityHigh)
	miss.SetFindingFilter(map[string]any{"finding_ids": []string{shared.NewID().String()}})
	_ = miss.Activate()
	_ = miss.Complete()
	repo.store[miss.ID().String()] = miss

	n, err := svc.ReopenCampaignsForFinding(context.Background(), tid, findingID, "ioc regression")
	if err != nil {
		t.Fatalf("ReopenCampaignsForFinding: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 reopened, got %d", n)
	}
	if repo.store[hit.ID().String()].Status() != remediation.CampaignStatusActive {
		t.Fatalf("tracking campaign should be active, got %s", repo.store[hit.ID().String()].Status())
	}
	if repo.store[miss.ID().String()].Status() != remediation.CampaignStatusCompleted {
		t.Fatalf("non-tracking campaign should stay completed, got %s", repo.store[miss.ID().String()].Status())
	}
}
