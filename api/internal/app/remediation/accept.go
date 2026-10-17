package remediation

// Accepting remediation suggestions: docs/rfcs/RFC-098-remediation-tasks.md §6.
//
// A person accepts a suggestion as it is, or edits it first (removes
// findings, names other owners, a title, a tighter deadline). A new group
// creates the action and one task per owner; a join adds the findings to the
// owner's live task; a task route creates a task under the existing action.
// Removed findings are remembered for the key. The auto-join rule is a
// person's opt-in per action, for exact keys only, and never changes a
// finding's status.

import (
	"context"
	"errors"
	"fmt"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	remediationdom "github.com/openctemio/openctem/api/pkg/domain/remediation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// SetTasks wires the task service (task scope checks on join).
func (s *SuggestionService) SetTasks(t *TaskService) { s.tasks = t }

// PartitionOwner names another owner for one partition of a suggestion.
type PartitionOwner struct {
	Index   int
	UserID  *shared.ID
	GroupID *shared.ID
}

// AcceptInput accepts a suggestion, with optional edits.
type AcceptInput struct {
	TenantID shared.ID
	ID       shared.ID
	Version  int
	ActorID  *shared.ID
	// Title replaces the suggested title of the new action and tasks.
	Title *string
	// Exclude are findings to leave out; they are not proposed for this
	// fix again.
	Exclude []shared.ID
	// Owners replaces the owner of some partitions (by index).
	Owners []PartitionOwner
	// Deadline is a deadline for the new tasks (it can only tighten).
	Deadline *time.Time
	// AutoJoin turns the auto-join rule on for the action.
	AutoJoin bool
	// AsOwner: the caller has no remediation write access and accepts as
	// the asset owner (owner_accept.go).
	AsOwner bool
}

// ErrAutoJoinNeedsFullScope: the auto-join rule acts on findings the caller
// cannot all see, so it needs a caller with no data-scope restriction.
var ErrAutoJoinNeedsFullScope = fmt.Errorf("%w: turning on auto-join needs access to every asset of the organization", shared.ErrForbidden)

// Accept accepts a suggestion.
func (s *SuggestionService) Accept(ctx context.Context, in AcceptInput, actx auditapp.AuditContext) (*remediationdom.AcceptResult, error) {
	sg, err := s.decidable(ctx, in.TenantID, in.ID)
	if err != nil {
		return nil, err
	}
	if !sg.State.IsOpen() || sg.Version != in.Version {
		return nil, remediationdom.ErrSuggestionDecided
	}
	if in.AsOwner {
		if err := s.checkOwnerAccept(ctx, in, sg); err != nil {
			return nil, err
		}
	}
	members := map[shared.ID]bool{}
	for _, id := range sg.FindingIDs {
		members[id] = true
	}
	excluded := map[shared.ID]bool{}
	for _, id := range dedupeIDs(in.Exclude) {
		if !members[id] {
			return nil, fmt.Errorf("%w: a removed finding is not part of the suggestion", shared.ErrValidation)
		}
		excluded[id] = true
	}
	title := sg.Title
	if in.Title != nil {
		if title, err = remediationdom.NormalizeTaskTitle(*in.Title); err != nil {
			return nil, err
		}
	}
	if in.AutoJoin {
		if !remediationdom.AutoJoinAllowed(sg.KeyKind) {
			return nil, fmt.Errorf("%w: auto-join is only for package upgrades and secret rotations (an exact fix)", shared.ErrValidation)
		}
		if err := s.requireFullScope(ctx, in.TenantID); err != nil {
			return nil, err
		}
	}
	owners, err := s.acceptOwners(ctx, in, sg)
	if err != nil {
		return nil, err
	}
	plan, err := s.buildAcceptPlan(ctx, sg, in, title, owners, excluded)
	if err != nil {
		return nil, err
	}
	res, err := s.repo.AcceptSuggestion(ctx, plan)
	if err != nil {
		return nil, err
	}
	if in.AutoJoin && sg.Kind != remediationdom.SuggestionNewGroup {
		if _, err := s.repo.SetAutoJoin(ctx, in.TenantID, res.ActionID, true, in.ActorID); err != nil {
			return nil, err
		}
	}
	s.logAudit(ctx, actx, auditapp.NewSuccessEvent(auditdom.ActionRemediationSuggestionAccepted, auditdom.ResourceTypeRemediationSuggestion, sg.ID.String()).
		WithResourceName(title).
		WithMessage(fmt.Sprintf("Remediation suggestion %q accepted: %d task(s) created, %d finding(s) joined, %d removed, %d left out", title,
			len(res.TaskIDs), res.Joined, len(excluded), len(res.Dropped))).
		WithMetadata("kind", string(sg.Kind)).WithMetadata("action_id", res.ActionID.String()).
		WithMetadata("tasks", len(res.TaskIDs)).WithMetadata("removed", len(excluded)).
		WithMetadata("edited", in.Title != nil || len(excluded) > 0 || len(in.Owners) > 0 || in.Deadline != nil).
		WithMetadata("auto_join", in.AutoJoin).WithMetadata("as_owner", in.AsOwner))
	return res, nil
}

// acceptOwners returns each partition's owner, with the person's changes,
// checked against the tenant.
func (s *SuggestionService) acceptOwners(ctx context.Context, in AcceptInput, sg *remediationdom.Suggestion) ([]remediationdom.Owner, error) {
	owners := make([]remediationdom.Owner, len(sg.Partitions))
	for i, p := range sg.Partitions {
		owners[i] = p.Owner
	}
	for _, o := range in.Owners {
		if o.Index < 0 || o.Index >= len(owners) {
			return nil, fmt.Errorf("%w: unknown partition %d", shared.ErrValidation, o.Index)
		}
		owners[o.Index] = remediationdom.Owner{UserID: o.UserID, GroupID: o.GroupID}
	}
	if s.tasks != nil {
		for i := range owners {
			if err := s.tasks.checkOwner(ctx, in.TenantID, owners[i].UserID, owners[i].GroupID); err != nil {
				return nil, err
			}
		}
	}
	return owners, nil
}

// buildAcceptPlan turns a suggestion and the person's edits into what the
// repository stores.
func (s *SuggestionService) buildAcceptPlan(ctx context.Context, sg *remediationdom.Suggestion, in AcceptInput, title string, owners []remediationdom.Owner, excluded map[shared.ID]bool) (remediationdom.AcceptPlan, error) {
	plan := remediationdom.AcceptPlan{TenantID: in.TenantID, SuggestionID: sg.ID, Version: sg.Version, Kind: sg.Kind,
		ActorID: in.ActorID, AutoJoin: in.AutoJoin}
	for id := range excluded {
		plan.Excluded = append(plan.Excluded, id)
	}
	keep := func(ids []shared.ID) []shared.ID {
		out := make([]shared.ID, 0, len(ids))
		for _, id := range ids {
			if !excluded[id] {
				out = append(out, id)
			}
		}
		return out
	}
	switch sg.Kind {
	case remediationdom.SuggestionNewGroup:
		plan.NewAction = &remediationdom.Action{Key: sg.Key, Kind: sg.KeyKind, Title: title, FixSpec: sg.FixSpec}
		for i, p := range sg.Partitions {
			plan.Tasks = append(plan.Tasks, remediationdom.AcceptPlanTask{Title: title, Owner: owners[i],
				FindingIDs: keep(p.FindingIDs), Deadline: in.Deadline})
		}
	case remediationdom.SuggestionTaskRoute:
		plan.ActionID = sg.TargetActionID
		for i, p := range sg.Partitions {
			plan.Tasks = append(plan.Tasks, remediationdom.AcceptPlanTask{Title: title, Owner: owners[i],
				FindingIDs: keep(p.FindingIDs), Deadline: in.Deadline})
		}
	case remediationdom.SuggestionJoin:
		if sg.TargetTaskID == nil || sg.TargetActionID == nil {
			return remediationdom.AcceptPlan{}, fmt.Errorf("%w: the suggestion has no target task", shared.ErrValidation)
		}
		if s.tasks != nil {
			// Adding to a task is a change of that task: the caller must
			// see all of its findings.
			if _, err := s.tasks.writableTask(ctx, in.TenantID, *sg.TargetTaskID); err != nil {
				return remediationdom.AcceptPlan{}, err
			}
		}
		plan.ActionID, plan.TargetTaskID, plan.JoinIDs = sg.TargetActionID, sg.TargetTaskID, keep(sg.FindingIDs)
	default:
		return remediationdom.AcceptPlan{}, fmt.Errorf("%w: unknown suggestion kind", shared.ErrValidation)
	}
	return plan, nil
}

// BulkAcceptItem is the outcome of one suggestion in a bulk accept.
type BulkAcceptItem struct {
	ID     shared.ID                    `json:"id"`
	Result *remediationdom.AcceptResult `json:"result,omitempty"`
	Error  string                       `json:"error,omitempty"`
}

// AcceptMany accepts suggestions as they are, each on its own: one failure
// does not stop the others. At most MaxBulkAccept suggestions and
// MaxBulkAcceptFindings findings per request.
func (s *SuggestionService) AcceptMany(ctx context.Context, tenantID shared.ID, ids []shared.ID, actor *shared.ID, actx auditapp.AuditContext) ([]BulkAcceptItem, error) {
	ids = dedupeIDs(ids)
	if len(ids) == 0 {
		return nil, fmt.Errorf("%w: no suggestion selected", shared.ErrValidation)
	}
	if len(ids) > remediationdom.MaxBulkAccept {
		return nil, fmt.Errorf("%w: at most %d suggestions at once", shared.ErrValidation, remediationdom.MaxBulkAccept)
	}
	loaded := make([]*remediationdom.Suggestion, 0, len(ids))
	total := 0
	for _, id := range ids {
		sg, err := s.Get(ctx, tenantID, id)
		if err != nil {
			return nil, err
		}
		total += sg.MemberCount
		loaded = append(loaded, sg)
	}
	if total > remediationdom.MaxBulkAcceptFindings {
		return nil, fmt.Errorf("%w: at most %d findings at once (selected %d)", shared.ErrValidation, remediationdom.MaxBulkAcceptFindings, total)
	}
	out := make([]BulkAcceptItem, 0, len(loaded))
	for _, sg := range loaded {
		res, err := s.Accept(ctx, AcceptInput{TenantID: tenantID, ID: sg.ID, Version: sg.Version, ActorID: actor}, actx)
		item := BulkAcceptItem{ID: sg.ID, Result: res}
		if err != nil {
			item.Error = publicError(err)
		}
		out = append(out, item)
	}
	return out, nil
}

// publicError is the message of a domain error, without internals.
func publicError(err error) string {
	switch {
	case isDomainError(err):
		return err.Error()
	default:
		return "internal error"
	}
}

func isDomainError(err error) bool {
	for _, e := range []error{shared.ErrValidation, shared.ErrConflict, shared.ErrForbidden, shared.ErrNotFound} {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
}

// ChangeActionAutoJoin turns an action's auto-join rule on or off.
func (s *SuggestionService) ChangeActionAutoJoin(ctx context.Context, tenantID, actionID shared.ID, on bool, actor *shared.ID, actx auditapp.AuditContext) (*remediationdom.Action, error) {
	if err := s.requireFullScope(ctx, tenantID); err != nil {
		return nil, err
	}
	a, err := s.repo.SetAutoJoin(ctx, tenantID, actionID, on, actor)
	if err != nil {
		return nil, err
	}
	state := "off"
	if on {
		state = "on"
	}
	s.logAudit(ctx, actx, auditapp.NewSuccessEvent(auditdom.ActionRemediationActionAutoJoinChanged, auditdom.ResourceTypeRemediationAction, a.ID.String()).
		WithResourceName(a.Title).WithMessage(fmt.Sprintf("Auto-join turned %s for %q", state, a.Title)).
		WithMetadata("auto_join", on).WithMetadata("key_kind", a.Kind))
	return a, nil
}

// requireFullScope refuses a caller restricted to part of the organization.
func (s *SuggestionService) requireFullScope(ctx context.Context, tenantID shared.ID) error {
	scope, err := s.scope(ctx, tenantID)
	if err != nil {
		return err
	}
	if scope.Restricted() {
		return ErrAutoJoinNeedsFullScope
	}
	return nil
}

// GetAction returns an action of the tenant.
// A restricted caller sees an action only through one of its tasks they can
// see (a task with at least one of their findings); otherwise it is not
// found, so its title, key and fix are not readable by id.
func (s *SuggestionService) GetAction(ctx context.Context, tenantID, actionID shared.ID) (*remediationdom.Action, error) {
	notFound := fmt.Errorf("%w: remediation action not found", shared.ErrNotFound)
	if s.tasks == nil {
		return nil, notFound
	}
	a, err := s.tasks.repo.GetAction(ctx, tenantID, actionID)
	if err != nil {
		return nil, err
	}
	scope, err := s.scope(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if scope.Restricted() {
		res, err := s.tasks.ListTasks(ctx, ListTasksInput{TenantID: tenantID,
			Filter: remediationdom.TaskFilter{ActionID: &actionID}}, pagination.New(1, 1))
		if err != nil {
			return nil, err
		}
		if res.Total == 0 {
			return nil, notFound
		}
	}
	return a, nil
}

// applyAutoJoin adds the findings of join suggestions into their task when
// the action's auto-join rule is on and the task is open or in progress.
// Returns how many findings joined.
func (s *SuggestionService) applyAutoJoin(ctx context.Context, tenantID shared.ID, ss []remediationdom.Suggestion, accepted map[string]remediationdom.AcceptedAction) int {
	n := 0
	for _, sg := range ss {
		if sg.Kind != remediationdom.SuggestionJoin || sg.TargetTaskID == nil || sg.TargetActionID == nil {
			continue
		}
		a, ok := accepted[sg.Key]
		if !ok || !a.AutoJoin || !remediationdom.AutoJoinAllowed(sg.KeyKind) {
			continue
		}
		live := false
		for _, t := range a.Tasks {
			if t.ID == *sg.TargetTaskID && remediationdom.CanAutoJoinInto(t.State) {
				live = true
			}
		}
		if !live {
			continue
		}
		joined, err := s.repo.AutoJoin(ctx, tenantID, *sg.TargetActionID, *sg.TargetTaskID, sg.FindingIDs)
		if err != nil {
			s.logger.Warn("remediation auto-join failed", "tenant", tenantID.String(), "error", logger.SanitizeError(err))
			continue
		}
		n += joined
	}
	return n
}
