package remediation

// Remediation tasks created from a custom query:
// docs/rfcs/RFC-098-remediation-tasks.md, "Tasks from a query".
//
// Security model. The query always runs as one person with that person's
// access resolved on the server: the creator in the request (preview,
// create, re-run), and the stored owner for auto mode, whose membership,
// role and permissions are read again on every run. The tenant, the data
// scope, the pentest member rule and the mandatory exclusions come from the
// query service (pkg/querylang plan layer), never from the request. Task
// queries additionally leave out closed findings and pentest findings (a
// pentest finding is fixed through its pentest campaign). A finding another
// active task holds is never taken silently: create answers 409 with the
// conflicts (skip or move them), auto mode skips them.

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	queryapp "github.com/openctemio/openctem/api/internal/app/query"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	moduledom "github.com/openctemio/openctem/api/pkg/domain/module"
	notificationdom "github.com/openctemio/openctem/api/pkg/domain/notification"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	remediationdom "github.com/openctemio/openctem/api/pkg/domain/remediation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/querylang/pgsql"
)

// QueryMatcher runs a filter-only findings query as a caller
// (*queryapp.Service).
type QueryMatcher interface {
	MatchFindings(ctx context.Context, c queryapp.Caller, text string, o pgsql.MatchOptions) (*queryapp.MatchResult, error)
}

// QueryTaskRepository is what query tasks store and read
// (postgres.RemediationTaskRepository).
type QueryTaskRepository interface {
	remediationdom.TaskQueryRepository
	remediationdom.QueryPreviewReader
}

// QueryOwnerDirectory reads the owner of an auto task outside a request:
// membership, role and permissions (the same readers automation runs use).
type QueryOwnerDirectory interface {
	IsActiveTenantMember(ctx context.Context, tenantID, userID shared.ID) (bool, error)
	GetMembership(ctx context.Context, userID, tenantID shared.ID) (*tenantdom.Membership, error)
	GetUserPermissions(ctx context.Context, tenantID, userID string) ([]string, error)
}

// QueryTaskNotifier sends one in-app notification (*notification service).
type QueryTaskNotifier interface {
	Notify(ctx context.Context, p notificationdom.NotificationParams) error
}

// SetQueryTasks wires tasks from a query. Without it every query-task call
// answers that the feature is not configured.
func (s *TaskService) SetQueryTasks(repo QueryTaskRepository, m QueryMatcher, owners QueryOwnerDirectory, n QueryTaskNotifier) {
	s.queries, s.matcher, s.owners, s.queryNotifier = repo, m, owners, n
}

// SetModuleGuard skips tenants with the remediation module off in the
// auto-include run.
func (s *TaskService) SetModuleGuard(g ModuleGuard) { s.modules = g }

var errQueryTasksOff = errors.New("tasks from a query are not configured")

// queryMatchOptions are the server-side narrowing of every task query.
func queryMatchOptions(limit int, unclaimedOnly bool) pgsql.MatchOptions {
	return pgsql.MatchOptions{
		Limit:           limit,
		ExcludeStatuses: statusStrings(vulnerability.ClosedFindingStatuses()),
		ExcludeSources:  []string{string(vulnerability.FindingSourcePentest)},
		ExcludeClaimed:  unclaimedOnly,
	}
}

func statusStrings(ss []vulnerability.FindingStatus) []string {
	out := make([]string, len(ss))
	for i, v := range ss {
		out[i] = string(v)
	}
	return out
}

// QueryTaskPreview is what a task created from a query would hold.
type QueryTaskPreview struct {
	Query       string
	Version     int
	Description string
	Scope       queryapp.Scope
	// Total is every open, non-pentest match in the caller's scope;
	// TooMany when it is above MaxFindingsPerQueryTask (nothing else is
	// computed then).
	Total   int
	TooMany bool
	Max     int
	// Claimable matches no other active task holds.
	Claimable         int
	Stats             *remediationdom.QueryPreviewStats
	Conflicts         []remediationdom.FindingConflict
	SuggestedAssignee *remediationdom.Owner
}

// checkQueryCaller refuses a caller of another tenant than the one the
// service was asked for.
func checkQueryCaller(tenantID shared.ID, c queryapp.Caller) error {
	if c.TenantID != tenantID.String() {
		return fmt.Errorf("%w: caller tenant mismatch", shared.ErrForbidden)
	}
	return nil
}

// PreviewQueryTask runs the query as the caller and describes what a task
// created from it would hold. Read-only: nothing is claimed.
func (s *TaskService) PreviewQueryTask(ctx context.Context, tenantID shared.ID, c queryapp.Caller, text string) (*QueryTaskPreview, error) {
	if s.queries == nil || s.matcher == nil {
		return nil, errQueryTasksOff
	}
	if err := checkQueryCaller(tenantID, c); err != nil {
		return nil, err
	}
	text, err := remediationdom.NormalizeTaskQueryText(text)
	if err != nil {
		return nil, err
	}
	m, err := s.matcher.MatchFindings(ctx, c, text, queryMatchOptions(remediationdom.MaxFindingsPerQueryTask, false))
	if err != nil {
		return nil, err
	}
	p := &QueryTaskPreview{Query: m.Query, Version: m.Version, Description: m.Description, Scope: m.Scope,
		Total: m.Total, TooMany: m.Truncated, Max: remediationdom.MaxFindingsPerQueryTask, Conflicts: []remediationdom.FindingConflict{}}
	if m.Truncated {
		return p, nil
	}
	conflicts, err := s.queryConflicts(ctx, tenantID, m.IDs)
	if err != nil {
		return nil, err
	}
	p.Conflicts = conflicts
	p.Claimable = len(m.IDs) - len(conflicts)
	if p.Stats, err = s.queries.QueryPreviewStats(ctx, tenantID, m.IDs, remediationdom.QueryPreviewSample); err != nil {
		return nil, err
	}
	if len(p.Stats.Owners) > 0 {
		top := p.Stats.Owners[0]
		p.SuggestedAssignee = &remediationdom.Owner{UserID: top.UserID, GroupID: top.GroupID}
	}
	return p, nil
}

// queryConflicts lists the matches other active tasks hold, as the caller
// may see them (the shared claim-conflict view: the holding task's title
// and owner only when the caller may read it, can_move only when they may
// change it).
func (s *TaskService) queryConflicts(ctx context.Context, tenantID shared.ID, ids []shared.ID) ([]remediationdom.FindingConflict, error) {
	holders, err := s.queries.PrimaryHolders(ctx, tenantID, ids)
	if err != nil {
		return nil, err
	}
	if len(holders) == 0 {
		return nil, nil
	}
	cs := make([]remediationdom.FindingConflict, 0, len(holders))
	for _, h := range holders {
		cs = append(cs, remediationdom.FindingConflict{FindingID: h.FindingID, FindingTitle: h.FindingTitle, TaskID: h.TaskID})
	}
	derr := s.describeConflicts(ctx, tenantID, &remediationdom.FindingsInOtherTaskError{Conflicts: cs}, true)
	e, ok := remediationdom.AsFindingsInOtherTask(derr)
	if !ok {
		return nil, derr
	}
	return e.Conflicts, nil
}

// CreateQueryTaskInput creates a task from a query.
type CreateQueryTaskInput struct {
	TenantID        shared.ID
	Caller          queryapp.Caller
	ActorID         *shared.ID
	Title           string
	Description     string
	Query           string
	Mode            remediationdom.QueryMode
	Cap             int
	AssigneeUserID  *shared.ID
	AssigneeGroupID *shared.ID
	CampaignID      *shared.ID
	Deadline        *time.Time
	Conflicts       remediationdom.ConflictResolution
}

// CreateQueryTaskResult is the created task and what happened to the
// matches.
type CreateQueryTaskResult struct {
	Task    *remediationdom.Task
	Query   *remediationdom.TaskQuery
	Added   int
	Skipped int
	Moved   int
	Matched int
}

// CreateQueryTask runs the query as the caller and creates a task holding
// the matches. Conflicts answer 409 unless the request resolves them.
func (s *TaskService) CreateQueryTask(ctx context.Context, in CreateQueryTaskInput, actx auditapp.AuditContext) (*CreateQueryTaskResult, error) {
	if s.queries == nil || s.matcher == nil {
		return nil, errQueryTasksOff
	}
	if err := checkQueryCaller(in.TenantID, in.Caller); err != nil {
		return nil, err
	}
	if in.ActorID == nil {
		// Auto mode runs as its owner: a user-less key cannot own one, and
		// every query task records who selected its findings.
		return nil, fmt.Errorf("%w: a task from a query is created by a person", shared.ErrForbidden)
	}
	title, err := remediationdom.NormalizeTaskTitle(in.Title)
	if err != nil {
		return nil, err
	}
	desc, err := normalizeDescription(in.Description)
	if err != nil {
		return nil, err
	}
	text, err := remediationdom.NormalizeTaskQueryText(in.Query)
	if err != nil {
		return nil, err
	}
	mode := in.Mode
	if mode == "" {
		mode = remediationdom.QueryModeSnapshot
	}
	if !mode.IsValid() {
		return nil, fmt.Errorf("%w: mode must be snapshot or auto", shared.ErrValidation)
	}
	capN, err := remediationdom.NormalizeQueryCap(in.Cap)
	if err != nil {
		return nil, err
	}
	if err := s.checkOwner(ctx, in.TenantID, in.AssigneeUserID, in.AssigneeGroupID); err != nil {
		return nil, err
	}
	if err := s.checkCampaign(ctx, in.TenantID, in.CampaignID); err != nil {
		return nil, err
	}
	m, err := s.matcher.MatchFindings(ctx, in.Caller, text, queryMatchOptions(capN, false))
	if err != nil {
		return nil, err
	}
	if m.Truncated {
		return nil, remediationdom.ErrTooManyMatches
	}
	res, err := s.prepareConflicts(ctx, in.TenantID, m.IDs, in.Conflicts, true, nil)
	if err != nil {
		return nil, err
	}
	if len(m.IDs) == 0 {
		return nil, remediationdom.ErrNoFindingLeft
	}

	taskID := shared.NewID()
	tq := &remediationdom.TaskQuery{TaskID: taskID, TenantID: in.TenantID, Text: m.Query, Version: m.Version,
		Mode: mode, Cap: capN, OwnerUserID: in.ActorID}
	if mode == remediationdom.QueryModeAuto {
		st := remediationdom.AutoStateActive
		tq.AutoState = &st
	}
	rec := &remediationdom.NewTaskRecord{
		Task: remediationdom.Task{
			ID: taskID, TenantID: in.TenantID, CampaignID: in.CampaignID, Title: title, Description: desc,
			AssigneeUserID: in.AssigneeUserID, AssigneeGroupID: in.AssigneeGroupID, ManualDeadline: in.Deadline,
			CreatedBy: in.ActorID,
		},
		Action: remediationdom.Action{
			TenantID: in.TenantID, Key: remediationdom.ManualActionKey(taskID), Kind: remediationdom.ActionKindManual,
			Title: title, Origin: remediationdom.ActionOriginManual, CreatedBy: in.ActorID,
		},
		Members: m.IDs, Source: remediationdom.JoinSourceQuery, ActorID: in.ActorID, Conflicts: res,
		EventData: map[string]any{"title": title, "query": m.Query, "mode": string(mode)},
		Query:     tq,
	}
	if err := s.repo.CreateTask(ctx, rec); err != nil {
		// Conflicts the request did not resolve, or a concurrent claim the
		// unique index refused: 409 with what the caller may know.
		return nil, s.describeConflicts(ctx, in.TenantID, err, true)
	}
	s.recordClaimMoves(ctx, actx, in.TenantID, rec.Claimed, in.ActorID)
	moved := 0
	for _, mv := range rec.Claimed.Moves {
		moved += len(mv.FindingIDs)
	}
	out := &CreateQueryTaskResult{Matched: len(m.IDs), Added: len(rec.Members) - moved, Moved: moved,
		Skipped: len(rec.Claimed.Skipped)}
	task, err := s.repo.GetTask(ctx, in.TenantID, taskID)
	if err != nil {
		return nil, err
	}
	out.Task, out.Query = task, tq
	s.logAudit(ctx, actx, auditapp.NewSuccessEvent(auditdom.ActionRemediationTaskCreatedFromQuery, auditdom.ResourceTypeRemediationTask, taskID.String()).
		WithResourceName(title).
		WithMessage(fmt.Sprintf("Remediation task %q created from a query (%s) with %d finding(s)", title, mode, out.Added+out.Moved)).
		WithMetadata("query", m.Query).WithMetadata("query_version", m.Version).WithMetadata("mode", string(mode)).
		WithMetadata("matched", out.Matched).WithMetadata("added", out.Added).WithMetadata("moved", out.Moved).
		WithMetadata("skipped", out.Skipped).WithMetadata("cap", capN))
	return out, nil
}

// GetTaskQuery returns the query a task was created from, to a caller who
// may see the task.
func (s *TaskService) GetTaskQuery(ctx context.Context, tenantID, taskID shared.ID) (*remediationdom.TaskQuery, error) {
	if s.queries == nil {
		return nil, remediationdom.ErrTaskNotFromQuery
	}
	if _, err := s.GetTask(ctx, tenantID, taskID); err != nil {
		return nil, err
	}
	return s.queries.GetTaskQuery(ctx, tenantID, taskID)
}

// QueryRerunPreview is what a re-run would add.
type QueryRerunPreview struct {
	Query     string
	New       int
	Truncated bool
	Room      int
	Stats     *remediationdom.QueryPreviewStats
}

// queryForChange loads a task the caller may change and its query, and
// refuses a closed task.
func (s *TaskService) queryForChange(ctx context.Context, tenantID, taskID shared.ID) (*remediationdom.Task, *remediationdom.TaskQuery, error) {
	if s.queries == nil || s.matcher == nil {
		return nil, nil, errQueryTasksOff
	}
	t, err := s.writableTask(ctx, tenantID, taskID)
	if err != nil {
		return nil, nil, err
	}
	q, err := s.queries.GetTaskQuery(ctx, tenantID, taskID)
	if err != nil {
		return nil, nil, err
	}
	return t, q, nil
}

// PreviewQueryRerun runs a task's stored query as the caller and returns the
// new matches no active task holds. Read-only.
func (s *TaskService) PreviewQueryRerun(ctx context.Context, tenantID, taskID shared.ID, c queryapp.Caller) (*QueryRerunPreview, error) {
	if err := checkQueryCaller(tenantID, c); err != nil {
		return nil, err
	}
	t, q, err := s.queryForChange(ctx, tenantID, taskID)
	if err != nil {
		return nil, err
	}
	room := q.Cap - t.Counts.Total
	if room < 0 {
		room = 0
	}
	m, err := s.matcher.MatchFindings(ctx, c, q.Text, queryMatchOptions(remediationdom.MaxFindingsPerQueryTask, true))
	if err != nil {
		return nil, err
	}
	p := &QueryRerunPreview{Query: m.Query, New: m.Total, Truncated: m.Truncated, Room: room}
	if p.Stats, err = s.queries.QueryPreviewStats(ctx, tenantID, m.IDs, remediationdom.QueryPreviewSample); err != nil {
		return nil, err
	}
	return p, nil
}

// RerunQueryInput confirms adding a re-run's new matches.
type RerunQueryInput struct {
	TenantID shared.ID
	TaskID   shared.ID
	Caller   queryapp.Caller
	ActorID  *shared.ID
}

// RerunQuery runs a task's stored query as the caller and adds the new
// matches no active task holds, up to the task's cap (the person confirmed
// after a preview).
func (s *TaskService) RerunQuery(ctx context.Context, in RerunQueryInput, actx auditapp.AuditContext) (*remediationdom.QueryClaimResult, *remediationdom.Task, error) {
	if err := checkQueryCaller(in.TenantID, in.Caller); err != nil {
		return nil, nil, err
	}
	t, q, err := s.queryForChange(ctx, in.TenantID, in.TaskID)
	if err != nil {
		return nil, nil, err
	}
	if t.State.IsTerminal() {
		return nil, nil, remediationdom.ErrTaskTerminal
	}
	m, err := s.matcher.MatchFindings(ctx, in.Caller, q.Text, queryMatchOptions(remediationdom.MaxFindingsPerQueryTask, true))
	if err != nil {
		return nil, nil, err
	}
	res, err := s.queries.ClaimQueryFindings(ctx, remediationdom.QueryClaim{TenantID: in.TenantID, TaskID: in.TaskID,
		IDs: m.IDs, Cap: q.Cap, ActorID: in.ActorID})
	if err != nil {
		return nil, nil, err
	}
	if err := s.queries.RecordQueryRun(ctx, in.TenantID, in.TaskID, len(res.Added), time.Now()); err != nil {
		s.logger.Warn("record query run failed", "task_id", in.TaskID.String(), "error", logger.SanitizeError(err))
	}
	s.logAudit(ctx, actx, auditapp.NewSuccessEvent(auditdom.ActionRemediationTaskQueryRerun, auditdom.ResourceTypeRemediationTask, in.TaskID.String()).
		WithResourceName(t.Title).
		WithMessage(fmt.Sprintf("Query of remediation task %q re-run: %d finding(s) added", t.Title, len(res.Added))).
		WithMetadata("query", q.Text).WithMetadata("added", len(res.Added)).WithMetadata("skipped", len(res.Skipped)).
		WithMetadata("capped", len(res.Capped)))
	nt, err := s.repo.GetTask(ctx, in.TenantID, in.TaskID)
	if err != nil {
		return nil, nil, err
	}
	return res, nt, nil
}

// SetQueryAutoStateInput pauses or resumes auto mode.
type SetQueryAutoStateInput struct {
	TenantID shared.ID
	TaskID   shared.ID
	ActorID  *shared.ID
	// Paused true pauses, false resumes.
	Paused bool
}

// SetQueryAutoState pauses or resumes auto mode. A suspended task resumes
// only when its owner is again an active member with the access a run
// needs; a task whose owner is gone stays suspended (the query never runs
// ownerless, and a resume never changes whose access it runs with).
func (s *TaskService) SetQueryAutoState(ctx context.Context, in SetQueryAutoStateInput, actx auditapp.AuditContext) (*remediationdom.TaskQuery, error) {
	t, q, err := s.queryForChange(ctx, in.TenantID, in.TaskID)
	if err != nil {
		return nil, err
	}
	if q.Mode != remediationdom.QueryModeAuto || q.AutoState == nil {
		return nil, remediationdom.ErrNotAutoMode
	}
	target := remediationdom.AutoStateActive
	if in.Paused {
		target = remediationdom.AutoStatePaused
	}
	if !in.Paused {
		if t.State.IsTerminal() {
			return nil, remediationdom.ErrTaskTerminal
		}
		if *q.AutoState == remediationdom.AutoStateSuspended {
			// Resume only once the owner may run it again.
			if q.OwnerUserID == nil {
				return nil, remediationdom.ErrAutoSuspended
			}
			if _, reason, oerr := s.ownerCaller(ctx, in.TenantID, *q.OwnerUserID); oerr != nil || reason != nil {
				return nil, remediationdom.ErrAutoSuspended
			}
		}
	}
	if *q.AutoState == target {
		return q, nil
	}
	if err := s.queries.SetAutoState(ctx, in.TenantID, in.TaskID, target, nil); err != nil {
		return nil, err
	}
	s.logAudit(ctx, actx, auditapp.NewSuccessEvent(auditdom.ActionRemediationTaskQueryAutoStateChanged, auditdom.ResourceTypeRemediationTask, in.TaskID.String()).
		WithResourceName(t.Title).
		WithMessage(fmt.Sprintf("Auto include of remediation task %q %s", t.Title, map[bool]string{true: "paused", false: "resumed"}[in.Paused])).
		WithMetadata("from", string(*q.AutoState)).WithMetadata("to", string(target)))
	return s.queries.GetTaskQuery(ctx, in.TenantID, in.TaskID)
}

// ownerCaller resolves the owner of an auto task as a query caller, with
// their current role and permissions. A nil reason means the owner may run
// the query; otherwise the reason the task must be suspended.
func (s *TaskService) ownerCaller(ctx context.Context, tenantID, ownerID shared.ID) (queryapp.Caller, *remediationdom.AutoReason, error) {
	c := queryapp.Caller{TenantID: tenantID.String(), UserID: ownerID.String()}
	if s.owners == nil {
		return c, nil, errors.New("query owner directory not configured")
	}
	removed := remediationdom.AutoReasonOwnerRemoved
	lost := remediationdom.AutoReasonOwnerLostAccess
	active, err := s.owners.IsActiveTenantMember(ctx, tenantID, ownerID)
	if err != nil {
		return c, nil, fmt.Errorf("check query owner: %w", err)
	}
	if !active {
		return c, &removed, nil
	}
	mem, err := s.owners.GetMembership(ctx, ownerID, tenantID)
	if err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			return c, &removed, nil
		}
		return c, nil, fmt.Errorf("read query owner: %w", err)
	}
	if mem.IsOwner() || mem.IsAdmin() {
		c.IsAdmin, c.Owner = true, mem.IsOwner()
		c.Has = func(string) bool { return true }
		return c, nil, nil
	}
	perms, err := s.owners.GetUserPermissions(ctx, tenantID.String(), ownerID.String())
	if err != nil {
		return c, nil, fmt.Errorf("read query owner permissions: %w", err)
	}
	c.Has = func(p string) bool { return slices.Contains(perms, p) }
	if !c.Has(permission.FindingsRead.String()) || !c.Has(permission.RemediationWrite.String()) {
		return c, &lost, nil
	}
	return c, nil, nil
}

// AutoIncludeBatch bounds one auto-include pass; AutoIncludeEvery is how
// long a task waits between runs.
const (
	AutoIncludeBatch = 50
	AutoIncludeEvery = 15 * time.Minute
)

// AutoInclude runs the due auto-mode task queries, each as its owner with
// the owner's current access, and adds new matches no active task holds,
// up to the task's cap. A task whose owner left or lost access, whose task
// closed, or whose query no longer compiles is suspended (audited, visible
// on the task) and never runs ownerless.
func (s *TaskService) AutoInclude(ctx context.Context) (int, error) {
	if s.queries == nil || s.matcher == nil {
		return 0, nil
	}
	due, err := s.queries.DueAutoQueryTasksForPlatform(ctx, time.Now().Add(-AutoIncludeEvery), AutoIncludeBatch)
	if err != nil {
		return 0, err
	}
	added := 0
	for _, d := range due {
		if s.modules != nil && s.modules.TenantDisabledModules(ctx, d.TenantID.String())[moduledom.ModuleRemediation] {
			continue
		}
		n, err := s.autoIncludeOne(ctx, d)
		if err != nil {
			s.logger.Warn("query task auto include failed", "tenant", d.TenantID.String(), "task_id", d.TaskID.String(),
				"error", logger.SanitizeError(err))
			continue
		}
		added += n
	}
	return added, nil
}

func (s *TaskService) autoIncludeOne(ctx context.Context, d remediationdom.DueQueryTask) (int, error) {
	q, err := s.queries.GetTaskQuery(ctx, d.TenantID, d.TaskID)
	if err != nil {
		return 0, err
	}
	if q.Mode != remediationdom.QueryModeAuto || q.AutoState == nil || *q.AutoState != remediationdom.AutoStateActive {
		return 0, nil
	}
	t, err := s.repo.GetTask(ctx, d.TenantID, d.TaskID)
	if err != nil {
		return 0, err
	}
	if t.State.IsTerminal() {
		return 0, s.suspend(ctx, t, q, remediationdom.AutoReasonTaskClosed)
	}
	if q.OwnerUserID == nil {
		return 0, s.suspend(ctx, t, q, remediationdom.AutoReasonOwnerRemoved)
	}
	c, reason, err := s.ownerCaller(ctx, d.TenantID, *q.OwnerUserID)
	if err != nil {
		return 0, err
	}
	if reason != nil {
		return 0, s.suspend(ctx, t, q, *reason)
	}
	m, err := s.matcher.MatchFindings(ctx, c, q.Text, queryMatchOptions(remediationdom.MaxFindingsPerQueryTask, true))
	if err != nil {
		if errors.Is(err, queryapp.ErrBusy) {
			return 0, nil // the next pass retries
		}
		var de *shared.DomainError
		if errors.As(err, &de) || errors.Is(err, shared.ErrValidation) || errors.Is(err, shared.ErrForbidden) {
			return 0, s.suspend(ctx, t, q, remediationdom.AutoReasonQueryInvalid)
		}
		return 0, err
	}
	res := &remediationdom.QueryClaimResult{}
	if len(m.IDs) > 0 {
		owner := *q.OwnerUserID
		if res, err = s.queries.ClaimQueryFindings(ctx, remediationdom.QueryClaim{TenantID: d.TenantID, TaskID: d.TaskID,
			IDs: m.IDs, Cap: q.Cap, ActorID: &owner, Auto: true}); err != nil {
			if errors.Is(err, remediationdom.ErrTaskTerminal) {
				return 0, s.suspend(ctx, t, q, remediationdom.AutoReasonTaskClosed)
			}
			return 0, err
		}
	}
	if err := s.queries.RecordQueryRun(ctx, d.TenantID, d.TaskID, len(res.Added), time.Now()); err != nil {
		return 0, err
	}
	if len(res.Added) > 0 {
		// The platform acts, on behalf of the owner (named in the metadata).
		actx := auditapp.AuditContext{TenantID: d.TenantID.String()}
		s.logAudit(ctx, actx, auditapp.NewSuccessEvent(auditdom.ActionRemediationTaskQueryAutoAdded, auditdom.ResourceTypeRemediationTask, d.TaskID.String()).
			WithResourceName(t.Title).
			WithMessage(fmt.Sprintf("Auto include added %d finding(s) to remediation task %q", len(res.Added), t.Title)).
			WithMetadata("query", q.Text).WithMetadata("added", len(res.Added)).WithMetadata("skipped", len(res.Skipped)).
			WithMetadata("capped", len(res.Capped)).WithMetadata("on_behalf_of", q.OwnerUserID.String()))
		s.notifyQueryOwner(ctx, t, q, fmt.Sprintf("%d new finding(s) matched the query of task '%s' and were added to it.", len(res.Added), t.Title))
	}
	return len(res.Added), nil
}

// suspend stops auto mode for a reason, once: audited, a timeline-visible
// state on the task's query, and the owner (when still a member) is told.
func (s *TaskService) suspend(ctx context.Context, t *remediationdom.Task, q *remediationdom.TaskQuery, reason remediationdom.AutoReason) error {
	if err := s.queries.SetAutoState(ctx, t.TenantID, t.ID, remediationdom.AutoStateSuspended, &reason); err != nil {
		if errors.Is(err, remediationdom.ErrNotAutoMode) {
			// No longer active (another pass suspended it, or a person paused
			// it): audited and notified once, by whoever changed it.
			return nil
		}
		return err
	}
	actx := auditapp.AuditContext{TenantID: t.TenantID.String()}
	s.logAudit(ctx, actx, auditapp.NewSuccessEvent(auditdom.ActionRemediationTaskQueryAutoStateChanged, auditdom.ResourceTypeRemediationTask, t.ID.String()).
		WithResourceName(t.Title).
		WithMessage(fmt.Sprintf("Auto include of remediation task %q suspended: %s", t.Title, reason)).
		WithMetadata("from", string(remediationdom.AutoStateActive)).WithMetadata("to", string(remediationdom.AutoStateSuspended)).
		WithMetadata("reason", string(reason)))
	if reason != remediationdom.AutoReasonOwnerRemoved {
		s.notifyQueryOwner(ctx, t, q, fmt.Sprintf("Auto include of task '%s' was suspended (%s). Open the task to resume it.", t.Title, reason))
	}
	return nil
}

func (s *TaskService) notifyQueryOwner(ctx context.Context, t *remediationdom.Task, q *remediationdom.TaskQuery, body string) {
	if s.queryNotifier == nil || q.OwnerUserID == nil {
		return
	}
	uid, tid := *q.OwnerUserID, t.ID
	if err := s.queryNotifier.Notify(ctx, notificationdom.NotificationParams{
		TenantID: t.TenantID, Audience: notificationdom.AudienceUser, AudienceID: &uid,
		NotificationType: notificationdom.TypeRemediationTask, Title: "Remediation task query", Body: body,
		Severity: "info", ResourceType: string(auditdom.ResourceTypeRemediationTask), ResourceID: &tid,
		URL: "/remediation/tasks/" + t.ID.String(),
	}); err != nil {
		s.logger.Warn("notify query task owner failed", "task_id", t.ID.String(), "error", logger.SanitizeError(err))
	}
}
