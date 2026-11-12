package finding

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// Moving a finding out of an approved false positive or an accepted risk:
// a person needs findings:approve, a workflow cannot at all.
func TestBulkStatus_LeavingADisposition(t *testing.T) {
	workflowCtx := vulnerability.WithStatusTransition(context.Background(), vulnerability.StatusTransition{
		Source: "workflow", Reason: "workflow_action", ActorName: "workflow:test",
	})
	cases := []struct {
		name        string
		ctx         context.Context
		approve     bool
		wantUpdated int
	}{
		{"person with findings:status only", context.Background(), false, 0},
		{"person with findings:approve", context.Background(), true, 1},
		{"workflow", workflowCtx, true, 0},
	}
	for _, decided := range []vulnerability.FindingStatus{vulnerability.FindingStatusFalsePositive, vulnerability.FindingStatusAccepted} {
		for _, c := range cases {
			tenantID := shared.NewID()
			f := mkFinding(t, tenantID, vulnerability.FindingSourceDAST)
			if err := f.TransitionStatus(vulnerability.FindingStatusConfirmed, "", nil); err != nil {
				t.Fatal(err)
			}
			if err := f.TransitionStatus(decided, "", nil); err != nil {
				t.Fatal(err)
			}
			repo := &methodStubRepo{bulkStubRepo: bulkStubRepo{byID: map[string]*vulnerability.Finding{f.ID().String(): f}}}
			res, err := newBulkTestService(repo).BulkUpdateFindingsStatus(c.ctx, tenantID.String(), BulkUpdateStatusInput{
				FindingIDs:           []string{f.ID().String()},
				Status:               vulnerability.FindingStatusConfirmed.String(),
				ActorID:              shared.NewID().String(),
				HasStatusPermission:  true,
				HasApprovePermission: c.approve,
			})
			if err != nil {
				t.Fatalf("%s from %s: %v", c.name, decided, err)
			}
			if res.Updated != c.wantUpdated || res.Failed != 1-c.wantUpdated {
				t.Errorf("%s from %s: updated=%d failed=%d, want updated=%d", c.name, decided, res.Updated, res.Failed, c.wantUpdated)
			}
			if c.wantUpdated == 0 && len(repo.written) != 0 {
				t.Errorf("%s from %s: a refused move wrote %v", c.name, decided, repo.written)
			}
		}
	}
}
