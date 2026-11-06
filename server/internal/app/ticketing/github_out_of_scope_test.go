package ticketing

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/integration"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// A finding closed because its asset was marked out of scope was not fixed:
// its GitHub issue is left open, never closed by the platform.
func TestSyncFindingStatus_OutOfScopeLeavesIssueOpen(t *testing.T) {
	tenantID := shared.NewID()
	now := time.Now().UTC()
	f := vulnerability.ReconstituteFinding(vulnerability.FindingData{
		ID: shared.NewID(), TenantID: tenantID, AssetID: shared.NewID(),
		Source: vulnerability.FindingSourceDAST, ToolName: "tool", Severity: vulnerability.SeverityHigh,
		Message: "m", Status: vulnerability.FindingStatusResolved,
		ClosureReason: string(vulnerability.ClosureReasonOutOfScope), ResolvedAt: &now,
		WorkItemURIs:    []string{"https://github.com/octo/repo/issues/7"},
		FirstDetectedAt: now, LastSeenAt: now, CreatedAt: now, UpdatedAt: now,
	})
	ir := &fakeIntegrationRepo{list: []*integration.Integration{connectedGitHubIntegration(t, tenantID)}}
	ic := &fakeIssueCreator{}
	s := newService(t, &fakeFindingRepo{finding: f}, ir, ic)
	if err := s.SyncFindingStatus(context.Background(), tenantID, f.ID()); err != nil {
		t.Fatalf("SyncFindingStatus: %v", err)
	}
	if ic.stateCalls != 0 {
		t.Fatalf("an out-of-scope close must not change the issue; got %d calls (%q)", ic.stateCalls, ic.gotState)
	}
}
