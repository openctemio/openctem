package finding

// Deciding many requests at once in Findings > Approvals
// (server/docs/architecture/finding-status-lifecycle.md, "Approvals").
//
// Threat model: a bulk decision must not be a way around the rules of a
// single one. Each id goes through the existing path (ApproveStatus,
// ApproveGroupException, RejectApproval, RejectGroupException), so the
// approval policy, four-eyes, eligibility, step-up per tier and the data
// scope are judged per item exactly as for one call. An id of another tenant
// or outside the caller's scope is reported like a missing one. One failed
// item never aborts the rest. A replay is safe by state: a decided item
// answers "not pending", so no idempotency record is kept.

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/vulnerability"
)

// MaxBulkApprovalDecisions bounds the requests and groups decided in one call.
const MaxBulkApprovalDecisions = 100

// MaxBulkApprovalFindings bounds the findings one bulk approval changes: a
// group counts every finding inside it (a group of 500 counts 500), so one
// call under one re-authentication cannot change tens of thousands.
const MaxBulkApprovalFindings = 1000

// Kinds of a bulk decision item.
const (
	BulkItemApproval = "approval"
	BulkItemBatch    = "batch"
)

// ErrApprovalNotPending: the request or group was decided, canceled or
// expired already.
var ErrApprovalNotPending = shared.NewDomainError("NOT_PENDING",
	"this request is no longer pending", shared.ErrConflict)

// BulkDecisionInput names the requests and groups to decide. Reason is the
// rejection reason (reject only).
type BulkDecisionInput struct {
	TenantID    string
	UserID      string
	ApprovalIDs []string
	BatchIDs    []string
	Reason      string
}

// BulkDecisionItem is the outcome of one id: on success Approval (a single
// request), Group (an approved group) or Batch (a rejected group) is set; on
// failure Err says why.
type BulkDecisionItem struct {
	ID       string
	Kind     string
	Approval *vulnerability.Approval
	Group    *GroupExceptionDecision
	Batch    *vulnerability.ApprovalBatch
	Err      error
}

// BulkApproveApprovals approves each listed request and group through the
// path of a single approval, in the order given (requests first).
func (s *VulnerabilityService) BulkApproveApprovals(ctx context.Context, in BulkDecisionInput) ([]BulkDecisionItem, error) {
	return s.bulkDecide(ctx, in, false)
}

// BulkRejectApprovals rejects each listed request and group with one reason
// through the path of a single rejection.
func (s *VulnerabilityService) BulkRejectApprovals(ctx context.Context, in BulkDecisionInput) ([]BulkDecisionItem, error) {
	in.Reason = strings.TrimSpace(in.Reason)
	if in.Reason == "" {
		return nil, fmt.Errorf("%w: a rejection needs a reason", shared.ErrValidation)
	}
	if len(in.Reason) > MaxRejectionReasonLength {
		return nil, fmt.Errorf("%w: the reason is at most %d characters", shared.ErrValidation, MaxRejectionReasonLength)
	}
	return s.bulkDecide(ctx, in, true)
}

func (s *VulnerabilityService) bulkDecide(ctx context.Context, in BulkDecisionInput, reject bool) ([]BulkDecisionItem, error) {
	if s.approvalRepo == nil {
		return nil, fmt.Errorf("%w: approval workflow not configured", shared.ErrValidation)
	}
	total := len(in.ApprovalIDs) + len(in.BatchIDs)
	if total == 0 {
		return nil, fmt.Errorf("%w: name at least one request or group", shared.ErrValidation)
	}
	if total > MaxBulkApprovalDecisions {
		return nil, fmt.Errorf("%w: at most %d requests and groups at once", shared.ErrValidation, MaxBulkApprovalDecisions)
	}
	tid, err := shared.IDFromString(in.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	uid, err := shared.IDFromString(in.UserID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid user id", shared.ErrValidation)
	}
	if !reject {
		if err := s.checkBulkApprovalFindings(ctx, tid, in); err != nil {
			return nil, err
		}
	}
	out := make([]BulkDecisionItem, 0, total)
	seen := make(map[string]bool, total)
	for _, raw := range in.ApprovalIDs {
		key := BulkItemApproval + ":" + raw
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, s.bulkDecideApproval(ctx, tid, uid, raw, in.Reason, reject))
	}
	for _, raw := range in.BatchIDs {
		key := BulkItemBatch + ":" + raw
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, s.bulkDecideBatch(ctx, tid, uid, raw, in.Reason, reject))
	}
	return out, nil
}

func (s *VulnerabilityService) bulkDecideApproval(ctx context.Context, tid, uid shared.ID, raw, reason string, reject bool) BulkDecisionItem {
	item := BulkDecisionItem{ID: raw, Kind: BulkItemApproval}
	id, err := shared.IDFromString(raw)
	if err != nil {
		item.Err = shared.ErrNotFound
		return item
	}
	// Tenant, then scope, then state: an id the caller may not see answers
	// like a missing one, whatever its state.
	a, err := s.approvalRepo.GetByTenantAndID(ctx, tid, id)
	if err != nil {
		item.Err = err
		return item
	}
	if err := s.AssertFindingAccess(ctx, tid, a.FindingID); err != nil {
		item.Err = err
		return item
	}
	if !a.IsPending() {
		item.Err = ErrApprovalNotPending
		return item
	}
	if reject {
		item.Approval, item.Err = s.RejectApproval(ctx, RejectApprovalInput{
			TenantID: tid.String(), ApprovalID: id.String(), RejectedBy: uid.String(), Reason: reason,
		})
		return item
	}
	item.Approval, item.Err = s.ApproveStatus(ctx, ApproveStatusInput{
		TenantID: tid.String(), ApprovalID: id.String(), ApprovedBy: uid.String(),
	})
	return item
}

func (s *VulnerabilityService) bulkDecideBatch(ctx context.Context, tid, uid shared.ID, raw, reason string, reject bool) BulkDecisionItem {
	item := BulkDecisionItem{ID: raw, Kind: BulkItemBatch}
	id, err := shared.IDFromString(raw)
	if err != nil {
		item.Err = shared.ErrNotFound
		return item
	}
	// Reads the group and checks every member is in the caller's scope.
	b, _, err := s.GetGroupException(ctx, tid, id)
	if err != nil {
		item.Err = err
		return item
	}
	if b.Status != vulnerability.ApprovalStatusPending {
		item.Err = ErrApprovalNotPending
		return item
	}
	if reject {
		item.Batch, item.Err = s.RejectGroupException(ctx, tid, id, uid, reason)
		return item
	}
	item.Group, item.Err = s.ApproveGroupException(ctx, tid, id, uid)
	if item.Err != nil && errors.Is(item.Err, vulnerability.ErrBatchNotPending) {
		item.Err = ErrApprovalNotPending
	}
	return item
}

// checkBulkApprovalFindings refuses, before anything changes, an approval
// that would change more than MaxBulkApprovalFindings findings: each request
// is one, each group its members. A group that cannot be read counts as
// nothing here; it fails on its own later.
func (s *VulnerabilityService) checkBulkApprovalFindings(ctx context.Context, tid shared.ID, in BulkDecisionInput) error {
	count := len(uniqueStrings(in.ApprovalIDs))
	if batchIDs := uniqueStrings(in.BatchIDs); len(batchIDs) > 0 {
		// Without a group store every group fails on its own later.
		store, _ := s.batches()
		for _, raw := range batchIDs {
			if store == nil {
				break
			}
			id, err := shared.IDFromString(raw)
			if err != nil {
				continue
			}
			if members, err := store.BatchMembers(ctx, tid, id); err == nil {
				count += len(members)
			}
		}
	}
	if count > MaxBulkApprovalFindings {
		return fmt.Errorf("%w: this would approve %d findings (a group counts every finding in it); at most %d findings at once, send fewer groups",
			shared.ErrValidation, count, MaxBulkApprovalFindings)
	}
	return nil
}

func uniqueStrings(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}
