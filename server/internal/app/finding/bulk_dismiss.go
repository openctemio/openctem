package finding

// Bulk "Dismiss" of findings: mark many findings a false positive, or accept
// their risk, in one action from the findings list
// (docs/architecture/findings-bulk-by-filter.md, "Bulk dismiss"; design
// research/533 D1, D2, D4, D7, D8). Each finding is decided by the SAME
// evaluation as a single request (RequestApproval): the organization's
// lifecycle, a pending request, and evaluateFindingRequest. The selection
// splits into findings decided alone now (applySinglePerson, which re-checks
// the level inside its transaction), one approval group for the ones that
// need a second person (RequestGroupException, source "selection") and the
// skipped ones. A preview runs the same plan without changing anything.
//
// Threat model: bulk dismiss is the cheapest way to hide findings (an
// insider, a stolen session, an API key, an AI agent). Controls:
//   - no bulk shortcut: per finding the single-request policy; automation,
//     delegated credentials, AI agents and asset owners never decide alone;
//     a raised level or a finding that turned serious since the plan sends it
//     to the group (the in-transaction re-check), never decides it alone;
//   - tenant from the principal; out-of-scope and other-tenant ids are
//     reported exactly like missing ones (not_found), never their titles;
//   - at most 500 findings per call; at most 1,000 decided alone per person
//     per rolling 24 hours (reserved under a per-person advisory lock with
//     the bulk row), the rest goes to the group, never silently dropped;
//   - more than 25 decided alone needs a recent re-authentication, checked
//     before anything changes;
//   - one activity entry per finding (with bulk_id), the per-decision audit
//     row, one bulk audit event (high when more than 100 are decided alone,
//     with an immediate notice to the organization's owners);
//   - undo by its creator only, within 24 hours, once, through the normal
//     status path; nothing is deleted.

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/openctemio/openctem/server/internal/app/datascope"
	"github.com/openctemio/openctem/server/internal/app/outbox"
	"github.com/openctemio/openctem/server/pkg/domain/approvalpolicy"
	lc "github.com/openctemio/openctem/server/pkg/domain/findinglifecycle"
	"github.com/openctemio/openctem/server/pkg/domain/integration"
	notificationdom "github.com/openctemio/openctem/server/pkg/domain/notification"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/server/pkg/filterspec"
	"github.com/openctemio/openctem/server/pkg/logger"
)

const (
	// MaxBulkDismiss caps the findings of one bulk dismiss (the group cap):
	// a larger repeating pattern is a suppression rule.
	MaxBulkDismiss = vulnerability.MaxApprovalBatchMembers
	// BulkDismissDailyBudget is how many findings one person may decide alone
	// by bulk dismiss in a rolling 24 hours; the rest goes to approval.
	BulkDismissDailyBudget = 1000
	// BulkDismissStepUpAbove: deciding more than this many alone in one call,
	// or within one hour counting the earlier calls, needs a recent
	// re-authentication.
	BulkDismissStepUpAbove = 25
	// BulkDismissStepUpWindow is the span over which calls add up for the
	// step-up rule.
	BulkDismissStepUpWindow = time.Hour
	// BulkDismissNoticeAbove: deciding more than this many alone in one call
	// is a high-severity audit event and a notice to the owners.
	BulkDismissNoticeAbove = 100
	// BulkDismissUndoWindow is how long a bulk dismiss can be undone.
	BulkDismissUndoWindow = 24 * time.Hour
	// BulkDismissRuleHintMin: a tool rule shared by at least this many
	// selected findings is suggested as a suppression rule instead.
	BulkDismissRuleHintMin = 20
	// bulkDismissListMax caps each preview list (the counts stay complete).
	bulkDismissListMax = 50
	// bulkDismissApplyTimeout bounds an apply once it has started. It does
	// not stop with the request: a client that gave up retries with its key
	// and gets the stored result, and a half-applied bulk is never left
	// without its record.
	bulkDismissApplyTimeout = 5 * time.Minute
	bulkDismissLabelMax     = 200
)

// Reasons a finding of a bulk dismiss (or of its undo) is skipped.
const (
	BulkSkipNotFound       = GroupSkipNotFound
	BulkSkipCannotMove     = GroupSkipCannotMove
	BulkSkipPendingRequest = GroupSkipPendingRequest
	// BulkSkipNoteRequired: the finding now needs a second person (a raced
	// decision), and the bulk has no note an approver could read.
	BulkSkipNoteRequired = "note_required"
	// BulkSkipFailed: the decision or the group could not be saved.
	BulkSkipFailed = "failed"
	// BulkSkipChanged (undo): the finding is no longer in the status the
	// bulk set; it is left as it is.
	BulkSkipChanged = "changed"
	// BulkSkipNotAllowed (undo): the status path refused the reopen.
	BulkSkipNotAllowed = "not_allowed"
)

// Bulk dismissal row statuses.
const (
	BulkDismissApplied = "applied"
	BulkDismissUndone  = "undone"
)

var (
	// ErrBulkDismissNoUser: only a person can dismiss in bulk.
	ErrBulkDismissNoUser = fmt.Errorf("%w: a bulk dismiss needs a signed-in user", shared.ErrForbidden)
	// ErrBulkDismissUnavailable: the bulk dismiss store is not wired.
	ErrBulkDismissUnavailable = fmt.Errorf("%w: bulk dismiss is not available", shared.ErrValidation)
	// ErrIdempotencyMismatch: the idempotency key was used with another
	// request.
	ErrIdempotencyMismatch = errors.New("this idempotency key was already used with a different request")
	// ErrBulkDismissRunning: the first request with this key is still being
	// applied.
	ErrBulkDismissRunning = fmt.Errorf("%w: a bulk dismiss with this key is still running; try again in a moment", shared.ErrConflict)
	// ErrBulkDismissNotFound: no bulk dismiss of the caller with this id.
	ErrBulkDismissNotFound = fmt.Errorf("%w: bulk dismissal not found", shared.ErrNotFound)
	// ErrBulkDismissUndone: the bulk dismiss was undone already.
	ErrBulkDismissUndone = fmt.Errorf("%w: this bulk dismissal was undone already", shared.ErrConflict)
	// ErrBulkDismissUndoExpired: the undo window has passed.
	ErrBulkDismissUndoExpired = fmt.Errorf("%w: a bulk dismissal can be undone within 24 hours only", shared.ErrConflict)
)

// BulkDismissTooLargeError: the selection has more than MaxBulkDismiss
// findings. Count is the selection's size.
type BulkDismissTooLargeError struct{ Count int }

func (e *BulkDismissTooLargeError) Error() string {
	return fmt.Sprintf("dismiss takes at most %d findings at a time; the selection has %d", MaxBulkDismiss, e.Count)
}

// BulkDismissal is a stored bulk dismiss.
type BulkDismissal struct {
	ID              shared.ID
	TenantID        shared.ID
	CreatedBy       shared.ID
	IdempotencyKey  string
	RequestHash     string
	RequestedStatus string
	ClosureReason   string
	SourceLabel     string
	FilterHash      string
	DecidedIDs      []shared.ID
	BatchID         *shared.ID
	Result          []byte
	DecidedCount    int
	GroupedCount    int
	SkippedCount    int
	Status          string
	CreatedAt       time.Time
}

// BulkDismissStore stores bulk dismissals (*postgres.FindingBulkDismissRepository).
// Every method is scoped to the tenant and the creator.
type BulkDismissStore interface {
	// ByKey reads the creator's bulk dismissal with this idempotency key
	// (ErrBulkDismissNotFound when none).
	ByKey(ctx context.Context, tenantID, createdBy shared.ID, key string) (*BulkDismissal, error)
	// DecidedSince sums decided_count of the creator's rows since since.
	DecidedSince(ctx context.Context, tenantID, createdBy shared.ID, since time.Time) (int, error)
	// Reserve inserts d with decided_count = the part of want that fits the
	// creator's budget (max over since), under a per-(tenant, creator)
	// advisory lock in the same transaction. A concurrent insert with the
	// same key answers the stored row and replay = true.
	Reserve(ctx context.Context, d *BulkDismissal, want, budget int, since time.Time) (stored *BulkDismissal, granted int, replay bool, err error)
	// Finish records the outcome of the apply.
	Finish(ctx context.Context, d *BulkDismissal) error
	// Get reads the creator's bulk dismissal (ErrBulkDismissNotFound for
	// anything else).
	Get(ctx context.Context, tenantID, createdBy, id shared.ID) (*BulkDismissal, error)
	// MarkUndone moves the creator's applied row created after since to
	// undone, once; it answers false when no such row moved.
	MarkUndone(ctx context.Context, tenantID, createdBy, id shared.ID, since time.Time) (bool, error)
}

// SetBulkDismissStore wires bulk dismiss. Without it the routes refuse.
func (s *VulnerabilityService) SetBulkDismissStore(st BulkDismissStore) { s.bulkDismissals = st }

// findingCountRepo counts the findings of a compiled filter.
type findingCountRepo interface {
	CountWhere(ctx context.Context, w *filterspec.Where) (int64, error)
}

// BulkDismissInput is one bulk dismiss (preview or apply).
type BulkDismissInput struct {
	TenantID shared.ID
	UserID   shared.ID
	// FindingIDs, or Spec (the list's filter) with ExpectedCount: exactly
	// one of the two. Caller compiles the filter in the caller's scope.
	FindingIDs    []shared.ID
	Spec          *filterspec.Spec
	Caller        FilterCaller
	ExpectedCount int
	// FilterSummary is a short plain-text summary of the filter for the
	// group's label; FilterHash identifies it in the audit trail.
	FilterSummary string
	FilterHash    string
	// Status is false_positive (default) or accepted (ExpiresAt optional).
	Status        string
	ClosureReason string
	Note          string
	ExpiresAt     *time.Time
	// IdempotencyKey is required to apply; RequestHash identifies the
	// request it was used with.
	IdempotencyKey string
	RequestHash    string
	// CanApprove: the caller's own session holds findings:approve
	// (requesterMayDecideAlone); ByAutomation: a delegated credential.
	CanApprove   bool
	ByAutomation bool
}

// BulkDismissItem is one finding of a preview list.
type BulkDismissItem struct {
	ID       string `json:"id"`
	Title    string `json:"title,omitempty"`
	Severity string `json:"severity,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

// BulkDismissSkip is one skipped finding.
type BulkDismissSkip struct {
	ID     string `json:"id"`
	Reason string `json:"reason"`
}

// BulkDismissGroup is the approval group of a bulk dismiss.
type BulkDismissGroup struct {
	BatchID string `json:"batch_id,omitempty"`
	Count   int    `json:"count"`
	Tier    string `json:"tier"`
}

// BulkDismissCounts are the counts of a bulk dismiss.
type BulkDismissCounts struct {
	Decided        int `json:"decided"`
	Grouped        int `json:"grouped"`
	Skipped        int `json:"skipped"`
	BudgetOverflow int `json:"budget_overflow"`
}

// BulkDismissSameRule is the tool rule most selected findings share.
type BulkDismissSameRule struct {
	Tool    string `json:"tool"`
	RuleID  string `json:"rule_id"`
	Count   int    `json:"count"`
	Suggest bool   `json:"suggest"`
}

// BulkDismissResult is the outcome of a bulk dismiss, or its preview. The
// apply's result is stored and returned verbatim on a replay.
type BulkDismissResult struct {
	BulkID         string            `json:"bulk_id,omitempty"`
	Status         string            `json:"status"`
	Decided        []string          `json:"decided"`
	Grouped        *BulkDismissGroup `json:"grouped"`
	Skipped        []BulkDismissSkip `json:"skipped"`
	Counts         BulkDismissCounts `json:"counts"`
	StepUpRequired bool              `json:"step_up_required"`
	NoteRequired   bool              `json:"note_required"`
	NoteMinLength  int               `json:"note_min_length"`
	Replay         bool              `json:"replay"`
	// Preview only: the findings of each part (at most 50 each).
	DecideNow  []BulkDismissItem    `json:"decided_now,omitempty"`
	ToApproval []BulkDismissItem    `json:"to_approval,omitempty"`
	SkipList   []BulkDismissItem    `json:"skipped_items,omitempty"`
	SameRule   *BulkDismissSameRule `json:"same_rule,omitempty"`

	// Applied are the decisions made alone (for the per-decision audit
	// rows; not stored).
	Applied []*vulnerability.Approval `json:"-"`
	// FilterHash and SourceLabel of the bulk (for the audit event).
	FilterHash  string `json:"-"`
	SourceLabel string `json:"-"`
}

// bulkMember is one finding of the plan with its evaluation.
type bulkMember struct {
	f       *vulnerability.Finding
	ev      policyEvaluation
	end     *time.Time
	serious bool
}

// bulkPlan is how a bulk dismiss splits.
type bulkPlan struct {
	status         vulnerability.FindingStatus
	reason         vulnerability.ClosureReason
	decide         []bulkMember
	group          []bulkMember
	skipped        []BulkDismissItem
	budgetOverflow int
	// recentAlone is what the person decided alone by bulk in the last hour
	// (across calls), for the step-up rule.
	recentAlone   int
	groupTier     string
	groupMinNote  int
	lifecycleNote int
	sameRule      *BulkDismissSameRule
	memo          *approvalMemo
	ctx           context.Context // carries the memo
	label         string
}

// stepUpRequired: more than BulkDismissStepUpAbove decided alone, counting
// the calls of the last hour.
func (p *bulkPlan) stepUpRequired() bool {
	return len(p.decide) > 0 && p.recentAlone+len(p.decide) > BulkDismissStepUpAbove
}

// noteMin is the shortest note the plan needs (0: optional).
func (p *bulkPlan) noteMin() int {
	need := p.lifecycleNote
	for _, m := range p.decide {
		need = max(need, noteRequired(true, m.ev.facts, m.ev.org.policy.EPSS(), m.ev.result.MinNoteLength))
	}
	if len(p.group) > 0 {
		need = max(need, noteRequired(false, approvalpolicy.Facts{}, 0, p.groupMinNote))
	}
	return need
}

// PreviewBulkDismiss answers how a bulk dismiss would split, changing
// nothing.
func (s *VulnerabilityService) PreviewBulkDismiss(ctx context.Context, in BulkDismissInput) (*BulkDismissResult, error) {
	if err := s.checkBulkDismiss(in); err != nil {
		return nil, err
	}
	ids, err := s.bulkDismissSelection(ctx, in)
	if err != nil {
		return nil, err
	}
	plan, err := s.planBulkDismiss(ctx, in, ids)
	if err != nil {
		return nil, err
	}
	out := plan.result(in, true)
	return out, nil
}

// BulkDismiss applies a bulk dismiss: the findings the policy lets the
// caller decide alone are decided now, the rest becomes one approval group.
func (s *VulnerabilityService) BulkDismiss(ctx context.Context, in BulkDismissInput) (*BulkDismissResult, error) {
	if err := s.checkBulkDismiss(in); err != nil {
		return nil, err
	}
	if strings.TrimSpace(in.IdempotencyKey) == "" {
		return nil, fmt.Errorf("%w: idempotency_key is required", shared.ErrValidation)
	}
	// A replay answers the first request's result before anything is
	// re-read or changed.
	if prev, err := s.bulkDismissals.ByKey(ctx, in.TenantID, in.UserID, in.IdempotencyKey); err == nil {
		return replayBulkDismiss(prev, in.RequestHash)
	} else if !errors.Is(err, ErrBulkDismissNotFound) {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), bulkDismissApplyTimeout)
	defer cancel()
	ids, err := s.bulkDismissSelection(ctx, in)
	if err != nil {
		return nil, err
	}
	plan, err := s.planBulkDismiss(ctx, in, ids)
	if err != nil {
		return nil, err
	}
	// Everything that can refuse the call is checked before anything
	// changes: the note, then the re-authentication.
	if need := plan.noteMin(); noteLength(in.Note) < need {
		return nil, errNoteRequired(need, approvalpolicy.Tier(plan.groupTierOr()))
	}
	if plan.stepUpRequired() {
		if err := s.requireApproverStepUp(ctx, in.UserID); err != nil {
			return nil, err
		}
	}

	row := &BulkDismissal{
		ID: shared.NewID(), TenantID: in.TenantID, CreatedBy: in.UserID, IdempotencyKey: in.IdempotencyKey,
		RequestHash: in.RequestHash, RequestedStatus: string(plan.status), ClosureReason: plan.reason.String(),
		SourceLabel: plan.label, FilterHash: in.FilterHash, Status: BulkDismissApplied,
	}
	now := time.Now()
	stored, granted, replay, err := s.bulkDismissals.Reserve(ctx, row, len(plan.decide), BulkDismissDailyBudget, now.Add(-24*time.Hour))
	if err != nil {
		return nil, err
	}
	if replay {
		return replayBulkDismiss(stored, in.RequestHash)
	}
	// Others used the budget between the plan and the reservation: the rest
	// waits for a second person.
	var lateOverflow []bulkMember
	if granted < len(plan.decide) {
		lateOverflow = plan.decide[granted:]
		plan.decide = plan.decide[:granted]
		plan.budgetOverflow += len(lateOverflow)
	}
	out := s.applyBulkDismiss(ctx, in, plan, row, lateOverflow)
	out.FilterHash, out.SourceLabel = in.FilterHash, plan.label

	row.DecidedIDs = make([]shared.ID, 0, len(out.Decided))
	for _, id := range out.Decided {
		if fid, err := shared.IDFromString(id); err == nil {
			row.DecidedIDs = append(row.DecidedIDs, fid)
		}
	}
	row.DecidedCount, row.GroupedCount, row.SkippedCount = out.Counts.Decided, out.Counts.Grouped, out.Counts.Skipped
	if out.Grouped != nil && out.Grouped.BatchID != "" {
		if bid, err := shared.IDFromString(out.Grouped.BatchID); err == nil {
			row.BatchID = &bid
		}
	}
	if b, err := json.Marshal(out); err == nil {
		row.Result = b
	}
	if err := s.bulkDismissals.Finish(ctx, row); err != nil {
		s.logger.Error("bulk dismiss: record the outcome", "bulk_id", row.ID.String(), "error", logger.SanitizeError(err))
	}
	if out.Counts.Decided > BulkDismissNoticeAbove {
		s.announceBulkDismiss(ctx, row, out)
	}
	return out, nil
}

func (p *bulkPlan) groupTierOr() string {
	if p.groupTier != "" {
		return p.groupTier
	}
	return string(approvalpolicy.TierSingle)
}

func (s *VulnerabilityService) checkBulkDismiss(in BulkDismissInput) error {
	if s.bulkDismissals == nil || s.approvalRepo == nil {
		return ErrBulkDismissUnavailable
	}
	if in.UserID.IsZero() {
		return ErrBulkDismissNoUser
	}
	if in.TenantID.IsZero() {
		return fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	if (in.Spec == nil) == (len(in.FindingIDs) == 0) {
		return fmt.Errorf("%w: send finding_ids or a filter, not both", shared.ErrValidation)
	}
	if len(in.FindingIDs) > MaxBulkDismiss {
		return &BulkDismissTooLargeError{Count: len(in.FindingIDs)}
	}
	return nil
}

func replayBulkDismiss(prev *BulkDismissal, requestHash string) (*BulkDismissResult, error) {
	if prev.RequestHash != requestHash {
		return nil, ErrIdempotencyMismatch
	}
	var out BulkDismissResult
	if len(prev.Result) == 0 || string(prev.Result) == "{}" {
		return nil, ErrBulkDismissRunning
	}
	if err := json.Unmarshal(prev.Result, &out); err != nil {
		return nil, fmt.Errorf("read the stored bulk dismiss result: %w", err)
	}
	out.Replay = true
	return &out, nil
}

// bulkDismissSelection is the ids of the call: the ids sent (deduplicated),
// or the filter compiled in the caller's scope, capped and checked against
// the count the caller confirmed.
func (s *VulnerabilityService) bulkDismissSelection(ctx context.Context, in BulkDismissInput) ([]shared.ID, error) {
	if in.Spec == nil {
		seen := make(map[shared.ID]bool, len(in.FindingIDs))
		out := make([]shared.ID, 0, len(in.FindingIDs))
		for _, id := range in.FindingIDs {
			if !seen[id] {
				seen[id] = true
				out = append(out, id)
			}
		}
		return out, nil
	}
	repo, ok := s.findingRepo.(findingIDsRepo)
	if !ok {
		return nil, errNoFindingWhereRepo
	}
	actor, err := s.FilterActor(ctx, in.Caller)
	if err != nil {
		return nil, err
	}
	where, err := filterspec.Compile(vulnerability.WithBranchOnlyDefault(in.Spec), vulnerability.FindingFields, actor)
	if err != nil {
		return nil, err
	}
	ids, err := repo.IDsWhere(ctx, where, MaxBulkDismiss+1)
	if err != nil {
		return nil, err
	}
	if len(ids) > MaxBulkDismiss {
		n := len(ids)
		if counter, ok := s.findingRepo.(findingCountRepo); ok {
			if c, err := counter.CountWhere(ctx, where); err == nil && c > int64(n) {
				n = int(min(c, int64(1<<31-1)))
			}
		}
		return nil, &BulkDismissTooLargeError{Count: n}
	}
	if len(ids) != in.ExpectedCount {
		return nil, &SelectionChangedError{Count: len(ids)}
	}
	return ids, nil
}

// planBulkDismiss splits ids into decided now, the group and skipped, with
// the per-finding evaluation of a single request.
func (s *VulnerabilityService) planBulkDismiss(ctx context.Context, in BulkDismissInput, ids []shared.ID) (*bulkPlan, error) {
	status, kind, reason, err := bulkDismissTarget(in)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	store, err := s.batches()
	if err != nil {
		return nil, err
	}
	plan := &bulkPlan{status: status, reason: reason}
	// The caller's scope answers are kept for this call (the group's
	// per-member checks then cost no query).
	ctx = datascope.WithRequestMemo(ctx)
	byID, visible, err := s.bulkVisibleFindings(ctx, in.TenantID, ids)
	if err != nil {
		return nil, err
	}
	memoCtx, memo := withApprovalMemo(ctx, in.TenantID, visible)
	plan.memo, plan.ctx = memo, memoCtx
	loaded := make([]*vulnerability.Finding, 0, len(byID))
	for _, f := range byID {
		loaded = append(loaded, f)
	}
	memo.putFindings(loaded)

	cands, err := s.lifecycleCandidates(memoCtx, in.TenantID)
	if err != nil {
		return nil, err
	}
	pending, err := store.PendingFindingIDs(memoCtx, in.TenantID, visible)
	if err != nil {
		return nil, err
	}
	canApprove := in.CanApprove
	evalCtx := memoCtx
	if in.ByAutomation {
		canApprove = false
		evalCtx = withAutomationRequest(memoCtx)
	}
	actor := lifecycleActor(memoCtx, personActor(in.UserID, TransitionPermissions{Write: true}))
	soleChecked, sole := false, false
	rules := map[[2]string]int{}
	for _, id := range ids {
		f, ok := byID[id]
		if !ok {
			plan.skipped = append(plan.skipped, BulkDismissItem{ID: id.String(), Reason: BulkSkipNotFound})
			continue
		}
		skip, noteMin := bulkMoveCheck(cands, f, actor, status, pending[id])
		if skip != "" {
			plan.skipped = append(plan.skipped, BulkDismissItem{ID: id.String(), Title: f.Title(), Severity: string(f.Severity()), Reason: skip})
			continue
		}
		plan.lifecycleNote = max(plan.lifecycleNote, noteMin)
		ev, err := s.evaluateFindingRequest(evalCtx, f, kind, in.UserID, false, canApprove, in.UserID)
		if err != nil {
			return nil, err
		}
		alone := ev.result.SinglePerson() && !in.ByAutomation
		if alone && status == vulnerability.FindingStatusAccepted {
			if !soleChecked {
				sole, soleChecked = s.requesterIsSoleMember(memoCtx, in.TenantID, in.UserID), true
			}
			// The organization's only member accepts a risk with their own
			// approval (an authenticator code), never alone in bulk.
			alone = !sole
		}
		m := bulkMember{f: f, ev: ev, serious: approvalpolicy.MaterialForFalsePositive(ev.facts, ev.org.policy.EPSS())}
		if status == vulnerability.FindingStatusAccepted {
			m.end, _ = memberEnd(in.ExpiresAt, now, ev.result.MaxAcceptance)
		}
		if alone {
			plan.decide = append(plan.decide, m)
		} else {
			plan.group = append(plan.group, m)
		}
		if f.RuleID() != "" {
			rules[[2]string{f.ToolName(), f.RuleID()}]++
		}
	}
	plan.sameRule = sameRule(rules)

	// The budget of decisions made alone (read here; reserved under a lock
	// when applying).
	used, err := s.bulkDismissals.DecidedSince(ctx, in.TenantID, in.UserID, now.Add(-24*time.Hour))
	if err != nil {
		return nil, err
	}
	if room := max(BulkDismissDailyBudget-used, 0); len(plan.decide) > room {
		plan.budgetOverflow = len(plan.decide) - room
		plan.group = append(plan.group, plan.decide[room:]...)
		plan.decide = plan.decide[:room]
	}
	// Splitting into small calls must not avoid the step-up: the last hour's
	// decisions count with this call's.
	recent, err := s.bulkDismissals.DecidedSince(ctx, in.TenantID, in.UserID, now.Add(-BulkDismissStepUpWindow))
	if err != nil {
		return nil, err
	}
	plan.recentAlone = recent
	plan.label = bulkDismissLabel(len(ids), in.FilterSummary)

	// The group as it will be asked (tier, members still able to join), so
	// the note it needs is known before anything changes.
	if len(plan.group) > 0 {
		gp, err := s.planBulkGroup(plan, in, store, plan.group)
		if err != nil {
			return nil, err
		}
		plan.applyGroupPreview(gp)
	}
	return plan, nil
}

// bulkDismissTarget validates the status, reason and end of a bulk dismiss.
func bulkDismissTarget(in BulkDismissInput) (vulnerability.FindingStatus, approvalpolicy.Kind, vulnerability.ClosureReason, error) {
	status := vulnerability.FindingStatusFalsePositive
	if in.Status != "" {
		status = vulnerability.FindingStatus(in.Status)
	}
	kind, ok := kindOfStatus(status)
	if !ok {
		return "", "", "", fmt.Errorf("%w: status must be false_positive or accepted", shared.ErrValidation)
	}
	reason, err := vulnerability.ParseClosureReason(status, in.ClosureReason)
	if err != nil {
		return "", "", "", err
	}
	if reason == "" {
		return "", "", "", fmt.Errorf("%w: closure_reason is required: one of %v", shared.ErrValidation, vulnerability.PersonClosureReasons(status))
	}
	if in.ExpiresAt != nil {
		if status != vulnerability.FindingStatusAccepted {
			return "", "", "", fmt.Errorf("%w: a false positive takes no end", shared.ErrValidation)
		}
		if _, err := vulnerability.DecisionEnd(status, in.ExpiresAt, time.Now()); err != nil {
			return "", "", "", err
		}
	}
	return status, kind, reason, nil
}

// bulkVisibleFindings loads ids of the tenant in one query and keeps the ones in
// the caller's scope (asset only, as assertFindingScope on a single request;
// one or two queries). Out of scope reads exactly like missing. visible keeps
// the order of ids.
func (s *VulnerabilityService) bulkVisibleFindings(ctx context.Context, tenantID shared.ID, ids []shared.ID) (map[shared.ID]*vulnerability.Finding, []shared.ID, error) {
	findings, err := s.findingRepo.GetByIDs(ctx, tenantID, ids)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to batch fetch findings: %w", err)
	}
	byID := make(map[shared.ID]*vulnerability.Finding, len(findings))
	assetIDs := make([]shared.ID, 0, len(findings))
	for _, f := range findings {
		if f.TenantID() == tenantID {
			byID[f.ID()] = f
			assetIDs = append(assetIDs, f.AssetID())
		}
	}
	if s.dataScope != nil && len(byID) > 0 {
		inScope, err := s.dataScope.FindingFilterForCaller(ctx, tenantID, assetIDs)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to resolve data scope: %w", err)
		}
		for id, f := range byID {
			if !inScope(f.AssetID(), nil) {
				delete(byID, id)
			}
		}
	}
	visibleAssets := make([]shared.ID, 0, len(byID))
	for _, f := range byID {
		visibleAssets = append(visibleAssets, f.AssetID())
	}
	s.dataScope.PrimeAssets(ctx, tenantID, visibleAssets)
	visible := make([]shared.ID, 0, len(byID))
	for _, id := range ids {
		if _, ok := byID[id]; ok {
			visible = append(visible, id)
		}
	}
	return byID, visible, nil
}

// bulkMoveCheck is the lifecycle check of a single request for one finding:
// the skip reason ("" when it may be requested) and the note length the
// organization's lifecycle asks for.
func bulkMoveCheck(cands []lc.Candidate, f *vulnerability.Finding, actor lc.Actor, status vulnerability.FindingStatus, pending bool) (string, int) {
	decision, _ := lifecycleDecision(cands, f, transitionFactsOf(f), actor, lc.Target{Status: status})
	blocked := false
	for _, b := range decision.Blocked {
		if _, ok := lifecycleBlockMessage(b); ok {
			blocked = true
		}
	}
	switch {
	case f.Status() == status, decision.Mode != vulnerability.TransitionRequest, blocked, !decision.Allowed, len(decision.Fields) > 0:
		return BulkSkipCannotMove, 0
	case pending:
		return BulkSkipPendingRequest, 0
	}
	return "", decision.NoteMinLen
}

// planBulkGroup plans the group of members (planGroupException).
func (s *VulnerabilityService) planBulkGroup(plan *bulkPlan, in BulkDismissInput, store batchStore, members []bulkMember) (*GroupExceptionPreview, error) {
	gp, _, _, err := s.planGroupException(plan.ctx, s.bulkGroupInput(plan, in, shared.NewID(), memberIDs(members)), store)
	if err != nil && gp == nil {
		return nil, err
	}
	return gp, nil
}

// applyGroupPreview keeps the members the group takes and moves the others
// to skipped with the group's reason.
func (p *bulkPlan) applyGroupPreview(gp *GroupExceptionPreview) {
	left := map[shared.ID]string{}
	for _, m := range gp.Members {
		if m.Skipped != "" {
			left[m.FindingID] = m.Skipped
		}
	}
	kept := p.group[:0]
	for _, m := range p.group {
		if r, ok := left[m.f.ID()]; ok {
			p.skipped = append(p.skipped, BulkDismissItem{ID: m.f.ID().String(), Title: m.f.Title(), Severity: string(m.f.Severity()), Reason: r})
			continue
		}
		kept = append(kept, m)
	}
	p.group = kept
	if len(p.group) > 0 {
		p.groupTier = string(gp.Result.Tier)
		p.groupMinNote = gp.Result.MinNoteLength
	}
}

func (s *VulnerabilityService) bulkGroupInput(plan *bulkPlan, in BulkDismissInput, sourceID shared.ID, ids []shared.ID) GroupExceptionInput {
	return GroupExceptionInput{
		TenantID: in.TenantID, SourceType: vulnerability.ApprovalBatchSourceSelection, SourceID: sourceID,
		SourceLabel: plan.label, FindingIDs: ids, RequestedStatus: string(plan.status),
		ClosureReason: plan.reason.String(), Justification: in.Note, ExpiresAt: in.ExpiresAt, RequestedBy: in.UserID,
	}
}

func memberIDs(ms []bulkMember) []shared.ID {
	out := make([]shared.ID, 0, len(ms))
	for _, m := range ms {
		out = append(out, m.f.ID())
	}
	return out
}

// applyBulkDismiss decides the decide-now members one by one, then asks for
// the group once.
func (s *VulnerabilityService) applyBulkDismiss(ctx context.Context, in BulkDismissInput, plan *bulkPlan, row *BulkDismissal, lateOverflow []bulkMember) *BulkDismissResult {
	out := plan.result(in, false)
	out.BulkID = row.ID.String()
	out.Decided = []string{}
	extras := map[string]any{"bulk_id": row.ID.String()}
	now := time.Now()
	groupMembers := append([]bulkMember{}, plan.group...)
	var raced []bulkMember
	applied := make([]*vulnerability.Finding, 0, len(plan.decide))
	secondLookRaised := false
	secondLookShare := 0
	for _, m := range plan.decide {
		level := m.ev.org.fpLevel
		if plan.status == vulnerability.FindingStatusAccepted {
			level = m.ev.org.acceptLevel
		}
		a := vulnerability.NewApproval(in.TenantID, m.f.ID(), in.UserID, string(plan.status), strings.TrimSpace(in.Note), m.end)
		a.ClosureReason = plan.reason
		stampPolicy(a, m.ev, now)
		a.DecisionFacts = factsJSON(m.ev.facts)
		done, err := s.applySinglePerson(s.ticketSyncCtx(ctx, in.TenantID, []*vulnerability.Finding{m.f}), a, FPPolicyDecision{
			Level: level, SinglePerson: true, SecondLookPercent: m.ev.org.secondLookPercent,
			SecondLookRaised: &secondLookRaised,
		}, extras)
		switch {
		case err == nil:
			out.Decided = append(out.Decided, m.f.ID().String())
			out.Applied = append(out.Applied, done)
			applied = append(applied, m.f)
			if m.ev.org.secondLookPercent > secondLookShare {
				secondLookShare = m.ev.org.secondLookPercent
			}
		case errors.Is(err, vulnerability.ErrSinglePersonNotAllowed):
			// Raced with a raised level or a finding that turned serious:
			// a second person decides it, never this call alone.
			plan.memo.forgetOrg()
			raced = append(raced, m)
		default:
			s.logger.Warn("bulk dismiss: decide alone", "finding_id", m.f.ID().String(), "error", logger.SanitizeError(err))
			out.Skipped = append(out.Skipped, BulkDismissSkip{ID: m.f.ID().String(), Reason: BulkSkipFailed})
		}
	}
	if plan.status != vulnerability.FindingStatusAccepted && secondLookShare > 0 &&
		len(applied) >= BulkSecondLookMin && !secondLookRaised {
		s.raiseBulkSecondLook(ctx, out.Applied, secondLookShare)
	}
	if len(applied) > 0 {
		s.afterApplied(ctx, in.TenantID, in.UserID.String(), applied, plan.status)
	}

	// Members that joined the group after the plan (a raced decision, or a
	// budget used meanwhile) join only when the bulk carries a note the group
	// accepts; otherwise they are reported, never grouped without a note.
	late := append(append([]bulkMember{}, raced...), lateOverflow...)
	if len(late) > 0 {
		store, err := s.batches()
		ok := err == nil && noteLength(in.Note) > 0
		if ok {
			gp, perr := s.planBulkGroup(plan, in, store, append(append([]bulkMember{}, groupMembers...), late...))
			ok = perr == nil && noteLength(in.Note) >= noteRequired(false, approvalpolicy.Facts{}, 0, gp.Result.MinNoteLength)
		}
		if ok {
			groupMembers = append(groupMembers, late...)
		} else {
			for _, m := range late {
				out.Skipped = append(out.Skipped, BulkDismissSkip{ID: m.f.ID().String(), Reason: BulkSkipNoteRequired})
			}
		}
	}

	out.Grouped = nil
	if len(groupMembers) > 0 {
		res, err := s.RequestGroupException(plan.ctx, s.bulkGroupInput(plan, in, row.ID, memberIDs(groupMembers)))
		if err != nil {
			s.logger.Warn("bulk dismiss: request the group", "bulk_id", row.ID.String(), "error", logger.SanitizeError(err))
			for _, m := range groupMembers {
				out.Skipped = append(out.Skipped, BulkDismissSkip{ID: m.f.ID().String(), Reason: BulkSkipFailed})
			}
		} else {
			out.Grouped = &BulkDismissGroup{BatchID: res.Batch.ID.String(), Count: res.Batch.MemberCount, Tier: res.Batch.Tier}
			for _, gm := range res.Preview.Members {
				if gm.Skipped != "" {
					out.Skipped = append(out.Skipped, BulkDismissSkip{ID: gm.FindingID.String(), Reason: gm.Skipped})
				}
			}
		}
	}
	out.Counts = BulkDismissCounts{Decided: len(out.Decided), Skipped: len(out.Skipped), BudgetOverflow: plan.budgetOverflow}
	if out.Grouped != nil {
		out.Counts.Grouped = out.Grouped.Count
	}
	return out
}

// BulkSecondLookMin is the number of findings decided alone from which a
// bulk always gets at least one second look (when the share is above 0).
const BulkSecondLookMin = 10

// secondLookApprovalKey is the evidence key naming the decision that was sampled.
const secondLookApprovalKey = "approval_id"

// raiseBulkSecondLook raises a second look on one randomly chosen decided
// finding (crypto/rand), after the per-finding sampling raised none.
func (s *VulnerabilityService) raiseBulkSecondLook(ctx context.Context, approvals []*vulnerability.Approval, share int) {
	raiser, ok := s.findingRepo.(decisionReviewRaiser)
	if !ok || len(approvals) == 0 {
		return
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(approvals))))
	if err != nil {
		n = big.NewInt(0)
	}
	a := approvals[int(n.Int64())]
	if _, err := raiser.RaiseDecisionReview(ctx, a.TenantID, a.FindingID, DecisionReviewSecondLook,
		map[string]any{secondLookApprovalKey: a.ID.String(), "second_look_percent": share}); err != nil {
		s.logger.Warn("bulk dismiss: raise the guaranteed second look", "error", logger.SanitizeError(err))
	}
}

// result is the response shape of the plan (a preview lists the findings).
func (p *bulkPlan) result(in BulkDismissInput, preview bool) *BulkDismissResult {
	out := &BulkDismissResult{
		Status: string(p.status), Decided: []string{}, Skipped: make([]BulkDismissSkip, 0, len(p.skipped)),
		StepUpRequired: p.stepUpRequired(),
		NoteMinLength:  p.noteMin(),
		Counts: BulkDismissCounts{Decided: len(p.decide), Grouped: len(p.group), Skipped: len(p.skipped),
			BudgetOverflow: p.budgetOverflow},
	}
	out.NoteRequired = out.NoteMinLength > 0
	for _, it := range p.skipped {
		out.Skipped = append(out.Skipped, BulkDismissSkip{ID: it.ID, Reason: it.Reason})
	}
	if len(p.group) > 0 {
		out.Grouped = &BulkDismissGroup{Count: len(p.group), Tier: p.groupTier}
	}
	if !preview {
		return out
	}
	out.DecideNow = listOf(p.decide)
	out.ToApproval = listOf(p.group)
	out.SkipList = make([]BulkDismissItem, 0, min(len(p.skipped), bulkDismissListMax))
	for _, it := range p.skipped {
		if len(out.SkipList) == bulkDismissListMax {
			break
		}
		out.SkipList = append(out.SkipList, it)
	}
	out.SameRule = p.sameRule
	return out
}

func listOf(ms []bulkMember) []BulkDismissItem {
	out := make([]BulkDismissItem, 0, min(len(ms), bulkDismissListMax))
	for _, m := range ms {
		if len(out) == bulkDismissListMax {
			break
		}
		out = append(out, BulkDismissItem{ID: m.f.ID().String(), Title: m.f.Title(), Severity: string(m.f.Severity())})
	}
	return out
}

// sameRule is the tool rule most findings share (nil when none has a rule).
func sameRule(rules map[[2]string]int) *BulkDismissSameRule {
	var best *BulkDismissSameRule
	keys := make([][2]string, 0, len(rules))
	for k := range rules {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i][0]+"\x00"+keys[i][1] < keys[j][0]+"\x00"+keys[j][1] })
	for _, k := range keys {
		if n := rules[k]; best == nil || n > best.Count {
			best = &BulkDismissSameRule{Tool: k[0], RuleID: k[1], Count: n}
		}
	}
	if best != nil {
		best.Suggest = best.Count >= BulkDismissRuleHintMin
	}
	return best
}

// bulkDismissLabel names the group: "42 findings", and the filter when the
// selection was one.
func bulkDismissLabel(n int, filterSummary string) string {
	label := fmt.Sprintf("%d findings", n)
	if n == 1 {
		label = "1 finding"
	}
	if f := strings.TrimSpace(filterSummary); f != "" {
		label += ", filter: " + f
	}
	if r := []rune(label); len(r) > bulkDismissLabelMax {
		label = string(r[:bulkDismissLabelMax-1]) + "…"
	}
	return label
}

// announceBulkDismiss tells the organization's owners at once that one
// person decided more than BulkDismissNoticeAbove findings alone (in-app,
// and the organization's channels as a security alert). Best effort: the
// decisions are saved and audited already.
func (s *VulnerabilityService) announceBulkDismiss(ctx context.Context, row *BulkDismissal, out *BulkDismissResult) {
	title := fmt.Sprintf("%d findings marked %s by one person in one action", out.Counts.Decided, statusLabel(row.RequestedStatus))
	body := fmt.Sprintf("Decided alone under the organization's approval level: %d; sent for approval: %d; skipped: %d. Review them under Findings.",
		out.Counts.Decided, out.Counts.Grouped, out.Counts.Skipped)
	if s.notificationService != nil {
		agg, _ := uuid.Parse(row.ID.String())
		if err := s.notificationService.Enqueue(ctx, outbox.EnqueueParams{
			TenantID: row.TenantID, EventType: string(integration.EventTypeSecurityAlert), AggregateType: "finding_bulk_dismissal",
			AggregateID: &agg, Title: title, Body: body, Severity: notificationdom.SeverityHigh, URL: approvalInboxURL,
		}); err != nil {
			s.logger.Warn("bulk dismiss notice: enqueue", "error", logger.SanitizeError(err))
		}
	}
	if s.approvalInApp == nil || s.approverDir == nil {
		return
	}
	people, err := s.approverDir.FindingApprovers(ctx, row.TenantID)
	if err != nil {
		s.logger.Warn("bulk dismiss notice: owners", "error", logger.SanitizeError(err))
		return
	}
	for _, p := range people {
		uid, err := shared.IDFromString(p.UserID)
		if err != nil || !p.Owner || uid == row.CreatedBy {
			continue
		}
		if err := s.approvalInApp.Notify(ctx, notificationdom.NotificationParams{
			TenantID: row.TenantID, Audience: notificationdom.AudienceUser, AudienceID: &uid,
			NotificationType: notificationdom.TypeFindingApproval, Title: title, Body: body,
			Severity: notificationdom.SeverityHigh, ResourceType: "finding_bulk_dismissal", ResourceID: &row.ID, URL: approvalInboxURL,
		}); err != nil {
			s.logger.Warn("bulk dismiss notice: in-app", "error", logger.SanitizeError(err))
		}
	}
}

// UndoBulkDismissInput is an undo of a bulk dismiss by its creator.
type UndoBulkDismissInput struct {
	TenantID shared.ID
	UserID   shared.ID
	BulkID   shared.ID
	// The caller's permissions for the status path.
	HasApprovePermission  bool
	HasVerifyPermission   bool
	HasFixApplyPermission bool
}

// UndoBulkDismissResult is the outcome of an undo.
type UndoBulkDismissResult struct {
	BulkID        string            `json:"bulk_id"`
	Reopened      []string          `json:"reopened"`
	Skipped       []BulkDismissSkip `json:"skipped"`
	GroupCanceled bool              `json:"group_canceled"`
	Status        string            `json:"-"`
}

// UndoBulkDismiss reopens the findings the caller's bulk dismiss decided
// alone (each still in the status it set) through the normal status path,
// and cancels its pending group. Only the creator, within 24 hours, once;
// another person's bulk, or another tenant's, is not found.
func (s *VulnerabilityService) UndoBulkDismiss(ctx context.Context, in UndoBulkDismissInput) (*UndoBulkDismissResult, error) {
	if s.bulkDismissals == nil {
		return nil, ErrBulkDismissUnavailable
	}
	if in.UserID.IsZero() {
		return nil, ErrBulkDismissNoUser
	}
	row, err := s.bulkDismissals.Get(ctx, in.TenantID, in.UserID, in.BulkID)
	if err != nil {
		return nil, err
	}
	moved, err := s.bulkDismissals.MarkUndone(ctx, in.TenantID, in.UserID, in.BulkID, time.Now().Add(-BulkDismissUndoWindow))
	if err != nil {
		return nil, err
	}
	if !moved {
		// An apply that has not recorded its outcome yet has nothing to
		// reopen: answer "running" instead of closing the undo for good.
		if row.Status == BulkDismissApplied && (len(row.Result) == 0 || string(row.Result) == "{}") {
			return nil, ErrBulkDismissRunning
		}
		if row.Status == BulkDismissUndone {
			return nil, ErrBulkDismissUndone
		}
		if again, gerr := s.bulkDismissals.Get(ctx, in.TenantID, in.UserID, in.BulkID); gerr == nil && again.Status == BulkDismissUndone {
			return nil, ErrBulkDismissUndone
		}
		return nil, ErrBulkDismissUndoExpired
	}
	out := &UndoBulkDismissResult{BulkID: row.ID.String(), Reopened: []string{}, Skipped: []BulkDismissSkip{}, Status: row.RequestedStatus}
	note := "Undo of bulk dismissal " + row.ID.String()
	for _, fid := range row.DecidedIDs {
		f, err := s.findingRepo.GetByID(ctx, in.TenantID, fid)
		if err != nil {
			out.Skipped = append(out.Skipped, BulkDismissSkip{ID: fid.String(), Reason: BulkSkipNotFound})
			continue
		}
		if string(f.Status()) != row.RequestedStatus {
			out.Skipped = append(out.Skipped, BulkDismissSkip{ID: fid.String(), Reason: BulkSkipChanged})
			continue
		}
		if _, err := s.UpdateFindingStatus(ctx, fid.String(), in.TenantID.String(), UpdateFindingStatusInput{
			Status: string(vulnerability.FindingStatusConfirmed), Resolution: note, ActorID: in.UserID.String(),
			HasApprovePermission: in.HasApprovePermission, HasVerifyPermission: in.HasVerifyPermission,
			HasFixApplyPermission: in.HasFixApplyPermission,
		}); err != nil {
			reason := BulkSkipNotAllowed
			if errors.Is(err, shared.ErrNotFound) {
				reason = BulkSkipNotFound
			}
			out.Skipped = append(out.Skipped, BulkDismissSkip{ID: fid.String(), Reason: reason})
			continue
		}
		out.Reopened = append(out.Reopened, fid.String())
	}
	if row.BatchID != nil {
		if _, err := s.CancelGroupException(ctx, in.TenantID, *row.BatchID, in.UserID); err == nil {
			out.GroupCanceled = true
		} else if !errors.Is(err, vulnerability.ErrBatchNotPending) {
			s.logger.Warn("bulk dismiss undo: cancel the group", "bulk_id", row.ID.String(), "error", logger.SanitizeError(err))
		}
	}
	return out, nil
}
