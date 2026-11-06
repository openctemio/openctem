package integration

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/finding"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// staticApprovers is an approver directory of fixed people.
type staticApprovers []shared.ID

func (s staticApprovers) FindingApprovers(context.Context, shared.ID) ([]finding.FindingApprover, error) {
	out := make([]finding.FindingApprover, 0, len(s))
	for _, id := range s {
		out = append(out, finding.FindingApprover{UserID: id.String()})
	}
	return out, nil
}

// requireTwoSignoffs asserts the rule for a request made by a platform actor
// (ticket, VEX, AI): one approver does not apply it, the same approver cannot
// sign twice, and a second distinct eligible approver does. It returns the
// approval after the second sign-off.
func requireTwoSignoffs(t *testing.T, svc *finding.VulnerabilityService, tenant shared.ID, approvalID string,
	first, second shared.ID, statusOf func() string, before, after string,
) {
	t.Helper()
	ctx := context.Background()
	in := func(by shared.ID) finding.ApproveStatusInput {
		return finding.ApproveStatusInput{TenantID: tenant.String(), ApprovalID: approvalID, ApprovedBy: by.String()}
	}
	a, err := svc.ApproveStatus(ctx, in(first))
	if err != nil {
		t.Fatalf("first sign-off: %v", err)
	}
	if a.RequiredApprovals < 2 || a.ApprovalsCollected != 1 {
		t.Fatalf("actor request: collected %d of %d, want 1 of at least 2", a.ApprovalsCollected, a.RequiredApprovals)
	}
	if s := statusOf(); s != before {
		t.Fatalf("one approver changed the finding to %s, want %s", s, before)
	}
	if _, err := svc.ApproveStatus(ctx, in(first)); err == nil {
		t.Fatal("the same approver signed twice")
	}
	if s := statusOf(); s != before {
		t.Fatalf("a repeated sign-off changed the finding to %s", s)
	}
	if _, err := svc.ApproveStatus(ctx, in(second)); err != nil {
		t.Fatalf("second sign-off: %v", err)
	}
	if s := statusOf(); s != after {
		t.Fatalf("after two approvers: %s, want %s", s, after)
	}
}
