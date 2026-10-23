package finding

// Bulk changes of findings selected by a filter, "select all matching" on
// the findings list (docs/architecture/findings-bulk-by-filter.md): the
// server recompiles the list's filter in the caller's scope, checks the
// count the caller confirmed, and applies the change through the same
// per-finding rules as a bulk change by ids, as an operation the caller
// reads back (GET /api/v1/operations/{id}).

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/internal/app/audit"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/operation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/filterspec"
)

const (
	// MaxBulkByFilter caps the findings one bulk change by filter touches.
	MaxBulkByFilter = 10000
	// BulkByFilterInlineMax: up to this many findings the change runs in the
	// request; above it, in the background.
	BulkByFilterInlineMax = 1000
	// BulkByFilterHourlyBudget bounds the findings a tenant changes by
	// filter per rolling hour, across every replica.
	BulkByFilterHourlyBudget = 20000
	// bulkByFilterChunk is the number of findings applied at a time; each
	// chunk re-applies the filter and the caller's scope first.
	bulkByFilterChunk = 100
	// bulkByFilterTimeout bounds a background run.
	bulkByFilterTimeout = 30 * time.Minute
)

// Bulk-by-filter verbs.
const (
	BulkVerbStatus = "status"
	BulkVerbAssign = "assign"
)

var (
	// ErrBulkByFilterTooLarge: the filter selects more than MaxBulkByFilter.
	ErrBulkByFilterTooLarge = fmt.Errorf("the filter selects more than %d findings; narrow it", MaxBulkByFilter)
	// ErrBulkByFilterNotAllowed: the target is never set in bulk by filter.
	ErrBulkByFilterNotAllowed = errors.New("false positive, accepted risk and duplicate are never set in bulk by filter: request them per finding")
	// ErrBulkByFilterBudget: the tenant's hourly budget is spent.
	ErrBulkByFilterBudget = fmt.Errorf("the organization changed %d findings by filter in the last hour; try later", BulkByFilterHourlyBudget)
	// ErrBulkByFilterNoUser: only a person can run a bulk change by filter.
	ErrBulkByFilterNoUser = errors.New("a bulk change by filter needs a signed-in user")
	// ErrBulkByFilterNote: a closing change needs a note.
	ErrBulkByFilterNote = errors.New("a closing change needs a note (resolution)")
)

// SelectionChangedError: the filter, recompiled now in the caller's scope,
// selects Count findings, not the count the caller confirmed.
type SelectionChangedError struct{ Count int }

func (e *SelectionChangedError) Error() string {
	return fmt.Sprintf("the selection changed: the filter now selects %d findings", e.Count)
}

// SetOperationStore wires the operations store bulk changes by filter run
// as. Without it they are refused.
func (s *VulnerabilityService) SetOperationStore(st operation.Store) { s.operations = st }

type findingIDsRepo interface {
	IDsWhere(ctx context.Context, w *filterspec.Where, limit int) ([]shared.ID, error)
}

// BulkByFilterInput is one bulk change by filter.
type BulkByFilterInput struct {
	Caller FilterCaller
	Verb   string
	// Spec is the list's filter, parsed strictly (paging and sort ignored).
	Spec          *filterspec.Spec
	ExpectedCount int
	// IdempotencyKey makes a retried request return the first one's
	// operation; RequestHash identifies the request it was used with.
	IdempotencyKey string
	RequestHash    string
	// Status is the status change (verb status): Status, Resolution,
	// ClosureReason and the caller's permissions. FindingIDs is ignored.
	Status BulkUpdateStatusInput
	// AssigneeID is the user to assign (verb assign).
	AssigneeID string
	Audit      audit.AuditContext
}

// BulkByFilterResult is the operation, and whether it runs in the background.
type BulkByFilterResult struct {
	Operation *operation.Operation
	Async     bool
	Replay    bool
}

// BulkByFilter selects the findings of in.Spec as the caller, checks the
// expected count, the cap and the tenant's hourly budget, records an
// operation and applies the change: inline up to BulkByFilterInlineMax, in
// the background above. Each chunk recompiles the filter as the caller
// restricted to the chunk's ids, so a finding that left the filter or the
// caller's scope since the count is skipped, and goes through the bulk
// service of its verb (per-finding transition rules, data scope, audit).
func (s *VulnerabilityService) BulkByFilter(ctx context.Context, in BulkByFilterInput) (*BulkByFilterResult, error) {
	if s.operations == nil {
		return nil, errors.New("operations store not configured")
	}
	repo, ok := s.findingRepo.(findingIDsRepo)
	if !ok {
		return nil, errNoFindingWhereRepo
	}
	userID, err := shared.IDFromString(in.Caller.UserID)
	if err != nil || in.Caller.UserID == "" {
		return nil, ErrBulkByFilterNoUser
	}
	tenantID, err := shared.IDFromString(in.Caller.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	kind, err := s.checkBulkByFilterVerb(ctx, tenantID, in)
	if err != nil {
		return nil, err
	}

	actor, err := s.FilterActor(ctx, in.Caller)
	if err != nil {
		return nil, err
	}
	spec := vulnerability.WithBranchOnlyDefault(in.Spec)
	where, err := filterspec.Compile(spec, vulnerability.FindingFields, actor)
	if err != nil {
		return nil, err
	}

	// A replay returns the first request's operation before anything is
	// recounted or changed.
	if in.IdempotencyKey != "" {
		prev, err := s.operations.ByKey(ctx, tenantID, userID, in.IdempotencyKey)
		switch {
		case err == nil:
			if prev.RequestHash != in.RequestHash {
				return nil, operation.ErrIdempotencyMismatch
			}
			return &BulkByFilterResult{Operation: prev, Async: prev.Status == operation.StatusRunning, Replay: true}, nil
		case !errors.Is(err, operation.ErrNotFound):
			return nil, err
		}
	}

	ids, err := repo.IDsWhere(ctx, where, MaxBulkByFilter+1)
	if err != nil {
		return nil, err
	}
	if len(ids) > MaxBulkByFilter {
		return nil, ErrBulkByFilterTooLarge
	}
	if len(ids) != in.ExpectedCount {
		return nil, &SelectionChangedError{Count: len(ids)}
	}
	// The hourly budget is checked by the insert itself, under a per-tenant
	// lock, so concurrent requests cannot overrun it together.
	op, replay, err := s.operations.Create(ctx, &operation.Operation{
		TenantID: tenantID, CreatedBy: userID, Kind: kind,
		IdempotencyKey: in.IdempotencyKey, RequestHash: in.RequestHash, Total: len(ids),
	}, operation.Budget{
		Kinds: []operation.Kind{operation.KindFindingsBulkStatus, operation.KindFindingsBulkAssign},
		Since: time.Now().Add(-time.Hour), Max: BulkByFilterHourlyBudget,
	})
	if errors.Is(err, operation.ErrBudget) {
		return nil, ErrBulkByFilterBudget
	}
	if err != nil {
		return nil, err
	}
	if replay {
		return &BulkByFilterResult{Operation: op, Async: op.Status == operation.StatusRunning, Replay: true}, nil
	}
	s.auditBulkByFilter(ctx, in, op, spec, "started", operation.Progress{})

	run := func(ctx context.Context) {
		var p operation.Progress
		runErr := s.runBulkByFilterSafe(ctx, in, op, spec, actor, ids, &p)
		status, msg := operation.StatusSucceeded, ""
		if runErr != nil {
			status, msg = operation.StatusFailed, runErr.Error()
		}
		// The outcome is recorded even when the run's deadline passed.
		end := context.WithoutCancel(ctx)
		if err := s.operations.Finish(end, tenantID, op.ID, status, p, msg); err != nil {
			s.logger.Error("bulk by filter: finish operation", "operation_id", op.ID.String(), "error", err)
		}
		s.auditBulkByFilter(end, in, op, spec, string(status), p)
	}
	if len(ids) <= BulkByFilterInlineMax {
		// A client that disconnects does not stop a change half way.
		inline, cancel := context.WithTimeout(context.WithoutCancel(ctx), bulkByFilterTimeout)
		run(inline)
		cancel()
		done, err := s.operations.Get(ctx, tenantID, userID, op.ID)
		if err != nil {
			return nil, err
		}
		return &BulkByFilterResult{Operation: done}, nil
	}
	// The background run keeps the request's values (tenant, user, data
	// scope caller, permissions), not its cancellation.
	bg, cancel := context.WithTimeout(context.WithoutCancel(ctx), bulkByFilterTimeout)
	go func() {
		defer cancel()
		run(bg)
	}()
	return &BulkByFilterResult{Operation: op, Async: true}, nil
}

// checkBulkByFilterVerb validates the change before anything is read.
func (s *VulnerabilityService) checkBulkByFilterVerb(ctx context.Context, tenantID shared.ID, in BulkByFilterInput) (operation.Kind, error) {
	switch in.Verb {
	case BulkVerbStatus:
		st, err := vulnerability.ParseFindingStatus(in.Status.Status)
		if err != nil {
			return "", fmt.Errorf("%w: %w", shared.ErrValidation, err)
		}
		for _, d := range vulnerability.FindingLensStatuses(vulnerability.FindingLensDispositioned) {
			if st == d {
				return "", ErrBulkByFilterNotAllowed
			}
		}
		if st.IsClosed() && strings.TrimSpace(in.Status.Resolution) == "" {
			return "", ErrBulkByFilterNote
		}
		return operation.KindFindingsBulkStatus, nil
	case BulkVerbAssign:
		assignee, err := shared.IDFromString(in.AssigneeID)
		if err != nil {
			return "", fmt.Errorf("%w: invalid user id format", shared.ErrValidation)
		}
		if err := s.assertAssignee(ctx, tenantID, assignee); err != nil {
			return "", err
		}
		return operation.KindFindingsBulkAssign, nil
	}
	return "", fmt.Errorf("%w: unknown bulk verb", shared.ErrValidation)
}

// errBulkByFilterInternal is what an operation records when its run
// panicked (the panic itself goes to the log only).
var errBulkByFilterInternal = errors.New("internal error while applying the change")

// runBulkByFilterSafe runs runBulkByFilter and turns a panic into a failed
// run: a background run has no request recoverer above it, so a panic would
// otherwise stop the whole API process and leave the operation running.
func (s *VulnerabilityService) runBulkByFilterSafe(ctx context.Context, in BulkByFilterInput, op *operation.Operation,
	spec *filterspec.Spec, actor filterspec.Actor, ids []shared.ID, p *operation.Progress,
) (err error) {
	defer func() {
		if r := recover(); r != nil {
			s.logger.Error("bulk by filter: run panicked", "operation_id", op.ID.String(), "panic", fmt.Sprint(r))
			err = errBulkByFilterInternal
		}
	}()
	return s.runBulkByFilter(ctx, in, op, spec, actor, ids, p)
}

// runBulkByFilter applies the change chunk by chunk and records progress in
// p (kept up to the last finished chunk when the run stops early).
func (s *VulnerabilityService) runBulkByFilter(ctx context.Context, in BulkByFilterInput, op *operation.Operation,
	spec *filterspec.Spec, actor filterspec.Actor, ids []shared.ID, p *operation.Progress,
) error {
	repo, _ := s.findingRepo.(findingIDsRepo)
	tenantID := op.TenantID.String()
	for start := 0; start < len(ids); start += bulkByFilterChunk {
		if err := ctx.Err(); err != nil {
			return err
		}
		chunk := ids[start:min(start+bulkByFilterChunk, len(ids))]
		// Re-apply the filter and the caller's scope to this chunk now.
		still, err := s.chunkStillSelected(ctx, repo, spec, actor, chunk)
		if err != nil {
			return err
		}
		keep := make(map[shared.ID]bool, len(still))
		apply := make([]string, 0, len(still))
		for _, id := range still {
			keep[id] = true
			apply = append(apply, id.String())
		}
		for _, id := range chunk {
			if !keep[id] {
				p.Skipped++
				p.Items = appendItem(p.Items, operation.ItemResult{ID: id.String(), Outcome: BulkRowSkipped,
					Reason: "no longer matches the filter"})
			}
		}
		if len(apply) > 0 {
			var res *BulkUpdateResult
			switch in.Verb {
			case BulkVerbStatus:
				input := in.Status
				input.FindingIDs = apply
				res, err = s.BulkUpdateFindingsStatus(ctx, tenantID, input)
			case BulkVerbAssign:
				res, err = s.BulkAssignFindings(ctx, tenantID, BulkAssignInput{
					FindingIDs: apply, UserID: in.AssigneeID, AssignerID: in.Caller.UserID,
				})
			}
			if err != nil {
				return err
			}
			p.Succeeded += res.Updated
			p.Skipped += res.Skipped
			p.Failed += res.Failed
			for _, r := range res.Rows {
				p.Items = appendItem(p.Items, operation.ItemResult{ID: r.FindingID, Outcome: r.Outcome, Reason: r.Reason})
			}
			if len(res.Rows) == 0 {
				for _, e := range res.Errors {
					id, reason, _ := strings.Cut(e, ": ")
					p.Items = appendItem(p.Items, operation.ItemResult{ID: id, Outcome: BulkRowFailed, Reason: reason})
				}
			}
		}
		p.Processed += len(chunk)
		if err := s.operations.Advance(ctx, op.TenantID, op.ID, *p); err != nil {
			s.logger.Warn("bulk by filter: record progress", "operation_id", op.ID.String(), "error", err)
		}
	}
	return nil
}

func appendItem(items []operation.ItemResult, it operation.ItemResult) []operation.ItemResult {
	if len(items) >= operation.MaxResultRows {
		return items
	}
	return append(items, it)
}

// chunkStillSelected returns the ids of chunk that the filter, compiled as
// the caller, still selects.
func (s *VulnerabilityService) chunkStillSelected(ctx context.Context, repo findingIDsRepo, spec *filterspec.Spec,
	actor filterspec.Actor, chunk []shared.ID,
) ([]shared.ID, error) {
	vals := make([]any, len(chunk))
	for i, id := range chunk {
		vals[i] = id.String()
	}
	idLeaf := &filterspec.Node{Leaf: &filterspec.Leaf{Field: "id", Op: filterspec.OpIn, Values: vals}}
	narrowed := *spec
	if spec.Root == nil {
		narrowed.Root = idLeaf
	} else {
		narrowed.Root = &filterspec.Node{All: []*filterspec.Node{spec.Root, idLeaf}}
	}
	w, err := filterspec.Compile(&narrowed, vulnerability.FindingFields, actor)
	if err != nil {
		return nil, err
	}
	return repo.IDsWhere(ctx, w, len(chunk))
}

// auditBulkByFilter records a summary row when the change starts and when
// it ends: the verb, the operation, the filter's shape and a hash of the
// filter (never its values), the count and the outcome. Every finding it
// changes gets its own row from the bulk service of the verb.
func (s *VulnerabilityService) auditBulkByFilter(ctx context.Context, in BulkByFilterInput, op *operation.Operation,
	spec *filterspec.Spec, phase string, p operation.Progress,
) {
	if s.auditService == nil {
		return
	}
	shape := make([]string, 0, len(spec.Leaves()))
	for _, l := range spec.Leaves() {
		shape = append(shape, l.Field+":"+string(l.Op))
	}
	sort.Strings(shape)
	target := in.Status.Status
	if in.Verb == BulkVerbAssign {
		target = in.AssigneeID
	}
	ev := audit.NewSuccessEvent(auditdom.ActionFindingBulkUpdated, auditdom.ResourceTypeFinding, op.ID.String()).
		WithMessage(fmt.Sprintf("Bulk %s by filter %s: %d findings", in.Verb, phase, op.Total)).
		WithMetadata("operation_id", op.ID.String()).
		WithMetadata("by_filter", true).
		WithMetadata("verb", in.Verb).
		WithMetadata("target", target).
		WithMetadata("phase", phase).
		WithMetadata("count", op.Total).
		WithMetadata("filter", shape).
		WithMetadata("filter_hash", in.RequestHash).
		WithMetadata("search", spec.Q != "").
		WithSeverity(auditdom.SeverityHigh)
	if phase != "started" {
		ev = ev.WithMetadata("succeeded", p.Succeeded).WithMetadata("skipped", p.Skipped).WithMetadata("failed", p.Failed)
	}
	if err := s.auditService.LogEvent(ctx, in.Audit, ev); err != nil {
		s.logger.Warn("audit bulk by filter failed", "operation_id", op.ID.String(), "error", err)
	}
}

// GetOperation reads an operation of its creator (operation.ErrNotFound for
// any other caller, any other tenant or an unknown id).
func (s *VulnerabilityService) GetOperation(ctx context.Context, tenantID, userID, id shared.ID) (*operation.Operation, error) {
	if s.operations == nil {
		return nil, operation.ErrNotFound
	}
	return s.operations.Get(ctx, tenantID, userID, id)
}
