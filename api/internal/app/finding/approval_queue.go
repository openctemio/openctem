package finding

// My Work's approval queues: the requests waiting for the caller's decision
// and the ones they made, each row with the facts of its finding now and
// what changed since the request (research 229 §8.5).

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/openctemio/openctem/api/pkg/domain/approvalpolicy"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// ApprovalQueueInput selects one personal queue page.
type ApprovalQueueInput struct {
	TenantID string
	// CallerID is the person whose queue it is (the authenticated user).
	CallerID string
	Queue    string
	// Status narrows the page (empty: every status; review is pending only).
	Status  string
	Page    int
	PerPage int
	// CanApprove: the caller holds findings:approve.
	CanApprove bool
}

// ListApprovalQueue lists one personal queue of the caller, in their data
// scope and pentest visibility like every approval list. The page carries
// the pending count of both queues.
func (s *VulnerabilityService) ListApprovalQueue(ctx context.Context, in ApprovalQueueInput) (vulnerability.ApprovalPage, error) {
	q, ok := vulnerability.ParseApprovalQueue(in.Queue)
	if !ok {
		return vulnerability.ApprovalPage{}, fmt.Errorf("%w: invalid approval queue %q", shared.ErrValidation, in.Queue)
	}
	caller, err := shared.IDFromString(in.CallerID)
	if err != nil {
		// An API key or a platform caller has no personal queue.
		return vulnerability.ApprovalPage{}, fmt.Errorf("%w: a personal queue needs a signed-in person", shared.ErrValidation)
	}
	return s.listApprovals(ctx, in.TenantID, in.Status, in.Page, in.PerPage, vulnerability.ApprovalFilter{
		Queue: q, CallerID: &caller, CallerCanApprove: in.CanApprove,
	})
}

// ApprovalFindingFacts are the facts of an approval's finding now, for a
// queue row: what the approver weighs at a glance.
type ApprovalFindingFacts struct {
	Facts     approvalpolicy.Facts
	AssetName string
}

// approvalFindingFactsReader reads them for many findings in one
// tenant-scoped query (*postgres.FindingApprovalRepository).
type approvalFindingFactsReader interface {
	ApprovalFindingFacts(ctx context.Context, tenantID shared.ID, findingIDs []shared.ID) (map[shared.ID]ApprovalFindingFacts, error)
}

// ApprovalRowFacts is one queue row's finding facts and the class reasons
// that hold now but did not when the request was made.
type ApprovalRowFacts struct {
	Finding ApprovalFindingFacts
	// ChangedSinceRequest lists approval-policy class reasons (kev,
	// severity_critical, exploit_validated, ...) true now and not at
	// request time, in a stable order. Nil for a request made before the
	// policy kept its evaluation, and for a decided request.
	ChangedSinceRequest []string
}

// ApprovalQueueFacts returns, by approval id, the finding facts of each
// approval on a page and what changed since its request. The approvals were
// already filtered to the caller's scope; the read is tenant-scoped too. A
// finding that no longer exists has no entry.
func (s *VulnerabilityService) ApprovalQueueFacts(ctx context.Context, tenantID string, approvals []*vulnerability.Approval) (map[shared.ID]ApprovalRowFacts, error) {
	r, ok := s.approvalRepo.(approvalFindingFactsReader)
	if !ok || len(approvals) == 0 {
		return nil, nil
	}
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	ids := make([]shared.ID, 0, len(approvals))
	for _, a := range approvals {
		ids = append(ids, a.FindingID)
	}
	facts, err := r.ApprovalFindingFacts(ctx, tid, ids)
	if err != nil {
		return nil, err
	}
	threshold := approvalpolicy.PlatformEPSSThreshold
	if op, err := s.orgApprovalPolicy(ctx, tid); err == nil {
		threshold = op.policy.EPSS()
	}
	out := make(map[shared.ID]ApprovalRowFacts, len(approvals))
	for _, a := range approvals {
		f, ok := facts[a.FindingID]
		if !ok {
			continue
		}
		row := ApprovalRowFacts{Finding: f}
		if a.IsPending() {
			row.ChangedSinceRequest = changedSinceRequest(a, f.Facts, threshold)
		}
		out[a.ID] = row
	}
	return out, nil
}

// changedSinceRequest is the class reasons of the finding now that the
// request-time evaluation did not have. Only the fact reasons are compared
// (severity, priority, KEV, EPSS, validated exploit, asset exposure); the
// policy's own reasons (tier floors, levels) are not finding changes.
func changedSinceRequest(a *vulnerability.Approval, now approvalpolicy.Facts, epssThreshold float64) []string {
	if len(a.PolicyEval) == 0 {
		return nil
	}
	kind, ok := kindOfStatus(vulnerability.FindingStatus(a.RequestedStatus))
	if !ok {
		return nil
	}
	var then struct {
		Reasons []string `json:"reasons"`
	}
	if err := json.Unmarshal(a.PolicyEval, &then); err != nil {
		return nil
	}
	_, reasons := approvalpolicy.ClassOf(kind, now, epssThreshold)
	var changed []string
	for _, r := range reasons {
		if !slices.Contains(then.Reasons, r) {
			changed = append(changed, r)
		}
	}
	return changed
}
