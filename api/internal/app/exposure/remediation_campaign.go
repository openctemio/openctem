package exposure

// Remediation campaigns: programs of remediation tasks
// (docs/architecture/remediation-campaigns.md, RFC-098). A campaign holds
// tasks (remediation_tasks.campaign_id), never findings: a finding is in at
// most one active work unit, the primary membership of a task. What a
// campaign covers and how far along it is are derived from its tasks.
//
// Data scope: a restricted caller sees a campaign they created or own
// (assigned_to), or one with a task that has a finding in their scope; they
// change it only when no task of it has a finding outside their scope. Out of
// scope tasks appear as a count only.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/internal/app/datascope"
	"github.com/openctemio/openctem/api/pkg/brand"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	moduledom "github.com/openctemio/openctem/api/pkg/domain/module"
	"github.com/openctemio/openctem/api/pkg/domain/remediation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// CampaignEpicCreator creates and moves the Jira epic of a campaign.
type CampaignEpicCreator interface {
	CreateEpic(ctx context.Context, tenantID shared.ID, projectKey, summary, description string, labels []string) (issueKey, issueURL string, err error)
	// TransitionEpic moves the linked epic to a target status name (echo-safe,
	// comment fallback). Best-effort outbound campaign→epic status sync.
	TransitionEpic(ctx context.Context, tenantID shared.ID, issueKey, targetStatus, comment string) error
}

const epicDoneStatus = "Done"

// CampaignTasks is the slice of the remediation task service a campaign
// needs (wired at the composition root, so this package does not import it).
type CampaignTasks interface {
	// CheckTaskWritable refuses a task the caller may not change (not found
	// for them, or with a finding outside their scope).
	CheckTaskWritable(ctx context.Context, tenantID, taskID shared.ID) error
	// RecomputeTasks re-derives the tasks' deadlines after their campaign
	// (and so its due date) changed.
	RecomputeTasks(ctx context.Context, tenantID shared.ID, taskIDs []shared.ID) error
	// CampaignTaskIDs lists the live tasks of a campaign.
	CampaignTaskIDs(ctx context.Context, tenantID, campaignID shared.ID) ([]shared.ID, error)
	// ClaimTaskFixed marks a task's open findings fixed (a fix claim each
	// finding then verifies on its own), as the platform. Returns the
	// refusals, one line per finding.
	ClaimTaskFixed(ctx context.Context, tenantID, taskID shared.ID, note string) (refusals []string, err error)
}

// CampaignModuleGuard reports the modules a tenant has off
// (*module.ModuleService). The background reconcile skips the campaigns of a
// tenant with the remediation module off.
type CampaignModuleGuard interface {
	TenantDisabledModules(ctx context.Context, tenantID string) map[string]bool
}

// CampaignAssigneeChecker decides whether a user may own a campaign in a
// tenant (an active member with an active account) and whether a group is
// the tenant's. postgres.AccessControlRepository implements it.
type CampaignAssigneeChecker interface {
	IsActiveTenantMember(ctx context.Context, tenantID, userID shared.ID) (bool, error)
	IsGroupInTenant(ctx context.Context, tenantID, groupID shared.ID) (bool, error)
}

// CampaignAuditLogger writes audit-log events. *auditapp.AuditService
// implements it.
type CampaignAuditLogger interface {
	LogEvent(ctx context.Context, actx auditapp.AuditContext, event auditapp.AuditEvent) error
}

// campaignAuditSystemActor names the actor of a change no user made.
const campaignAuditSystemActor = "system"

// MaxCampaignTasksPerRequest bounds one add.
const MaxCampaignTasksPerRequest = 200

// Errors answered to callers.
var (
	// ErrInvalidCampaignAssignee is the one answer for an owner who is not an
	// active member of the organization, so the endpoint is no oracle for
	// user ids elsewhere.
	ErrInvalidCampaignAssignee = fmt.Errorf("%w: the assignee must be an active member of this organization", shared.ErrValidation)
	// ErrInvalidCampaignTeam is the one answer for a team that is not a
	// group of the campaign's organization.
	ErrInvalidCampaignTeam = fmt.Errorf("%w: the team must be a group of this organization", shared.ErrValidation)
	// ErrCampaignOutsideScope refuses a change to a campaign the caller can
	// see but with a task that has a finding outside their scope.
	ErrCampaignOutsideScope = fmt.Errorf("%w: a task of this campaign has findings outside your data scope; only someone who can see all of them may change it", shared.ErrForbidden)
	// ErrTicketingNotConfigured: no Jira wiring.
	ErrTicketingNotConfigured = fmt.Errorf("%w: campaign ticketing is not configured", shared.ErrValidation)
	// ErrCampaignTaskNotFound is the one answer for a task of another
	// organization, of none, or one the caller may not change.
	ErrCampaignTaskNotFound = fmt.Errorf("%w: one or more tasks were not found", shared.ErrNotFound)
	// ErrCampaignTaskNotInCampaign: removing a task the campaign does not hold.
	ErrCampaignTaskNotInCampaign = fmt.Errorf("%w: the task is not in this campaign", shared.ErrValidation)
)

// CampaignTaskConflict is a task that is already in another campaign.
type CampaignTaskConflict struct {
	TaskID       string  `json:"task_id"`
	CampaignID   string  `json:"campaign_id"`
	CampaignName *string `json:"campaign_name"` // nil when the caller cannot see that campaign
	CanMove      bool    `json:"can_move"`
}

// TasksInOtherCampaignError refuses adding tasks that are in another campaign
// unless the request asks to move them (409 TASKS_IN_OTHER_CAMPAIGN).
type TasksInOtherCampaignError struct {
	Conflicts []CampaignTaskConflict
}

func (e *TasksInOtherCampaignError) Error() string {
	return fmt.Sprintf("%d task(s) are in another campaign; set move to move them", len(e.Conflicts))
}

func (e *TasksInOtherCampaignError) Unwrap() error { return shared.ErrConflict }

// CampaignView is a campaign as one caller sees it.
type CampaignView struct {
	Campaign *remediation.Campaign
	Summary  remediation.CampaignSummary
	// CanEdit: the caller may change it (data scope; the route checks the
	// permission).
	CanEdit bool
}

// RemediationCampaignService manages remediation campaigns.
type RemediationCampaignService struct {
	repo        remediation.CampaignRepository
	dataScope   *datascope.Enforcer // nil = every caller unrestricted (tests, jobs)
	tasks       CampaignTasks
	ticketRepo  remediation.CampaignTicketRepository // nil → ticketing disabled
	epicCreator CampaignEpicCreator                  // nil → ticketing disabled
	audit       CampaignAuditLogger                  // nil → no audit trail (tests)
	assignees   CampaignAssigneeChecker              // nil → naming an assignee is refused
	modules     CampaignModuleGuard                  // nil → reconcile every tenant
	logger      *logger.Logger
}

// NewRemediationCampaignService creates a new service.
func NewRemediationCampaignService(repo remediation.CampaignRepository, log *logger.Logger) *RemediationCampaignService {
	return &RemediationCampaignService{repo: repo, logger: log}
}

// SetDataScope wires the data-scope enforcer.
func (s *RemediationCampaignService) SetDataScope(e *datascope.Enforcer) { s.dataScope = e }

// SetTasks wires the remediation task service.
func (s *RemediationCampaignService) SetTasks(t CampaignTasks) { s.tasks = t }

// SetAuditLogger wires the audit log.
func (s *RemediationCampaignService) SetAuditLogger(a CampaignAuditLogger) { s.audit = a }

// SetAssigneeChecker wires the owner and team checks (fail closed without).
func (s *RemediationCampaignService) SetAssigneeChecker(c CampaignAssigneeChecker) { s.assignees = c }

// SetModuleGuard wires the tenant module state into the reconcile.
func (s *RemediationCampaignService) SetModuleGuard(g CampaignModuleGuard) { s.modules = g }

// SetTicketing wires the campaign→Jira epic link.
func (s *RemediationCampaignService) SetTicketing(ticketRepo remediation.CampaignTicketRepository, epic CampaignEpicCreator) {
	s.ticketRepo = ticketRepo
	s.epicCreator = epic
}

// viewer resolves who reads: the caller's scope and user id.
func (s *RemediationCampaignService) viewer(ctx context.Context, tenantID shared.ID) (remediation.CampaignViewer, error) {
	if s.dataScope == nil {
		return remediation.CampaignViewer{}, nil
	}
	scope, err := s.dataScope.Resolve(ctx, tenantID)
	if err != nil {
		return remediation.CampaignViewer{}, fmt.Errorf("resolve data scope: %w", err)
	}
	v := remediation.CampaignViewer{Scope: scope}
	if uid, err := shared.IDFromString(s.dataScope.CallerUserID(ctx)); err == nil {
		v.UserID = &uid
	}
	return v, nil
}

func isOwnCampaign(c *remediation.Campaign, v remediation.CampaignViewer) bool {
	return v.UserID != nil && c.AssignedTo() != nil && *c.AssignedTo() == *v.UserID
}

// getVisible loads a campaign the caller may see; any other answers not found.
func (s *RemediationCampaignService) getVisible(ctx context.Context, tenantID, id shared.ID) (*remediation.Campaign, remediation.CampaignViewer, error) {
	c, err := s.repo.GetByID(ctx, tenantID, id)
	if err != nil {
		return nil, remediation.CampaignViewer{}, err
	}
	v, err := s.viewer(ctx, tenantID)
	if err != nil {
		return nil, v, err
	}
	if v.Restricted() {
		ok, err := s.repo.Visible(ctx, tenantID, id, v)
		if err != nil {
			return nil, v, err
		}
		if !ok {
			return nil, v, remediation.ErrCampaignNotFound
		}
	}
	return c, v, nil
}

// canEdit: a caller who is not restricted may change every campaign; a
// restricted one only a campaign none of whose tasks has a finding outside
// their scope.
func (s *RemediationCampaignService) canEdit(ctx context.Context, c *remediation.Campaign, v remediation.CampaignViewer) (bool, error) {
	if !v.Restricted() {
		return true, nil
	}
	outside, err := s.repo.HasTaskOutsideScope(ctx, c.TenantID(), c.ID(), v.Scope)
	if err != nil {
		return false, err
	}
	return !outside, nil
}

// getWritable loads a campaign the caller may change.
func (s *RemediationCampaignService) getWritable(ctx context.Context, tenantID, id shared.ID) (*remediation.Campaign, remediation.CampaignViewer, error) {
	c, v, err := s.getVisible(ctx, tenantID, id)
	if err != nil {
		return nil, v, err
	}
	ok, err := s.canEdit(ctx, c, v)
	if err != nil {
		return nil, v, err
	}
	if !ok {
		return nil, v, ErrCampaignOutsideScope
	}
	return c, v, nil
}

// views builds what the caller sees of each campaign: the summary over their
// scope (the campaign's owner sees the whole campaign's counts: assignment
// grants view of the program) and whether they may change it.
func (s *RemediationCampaignService) views(ctx context.Context, campaigns []*remediation.Campaign, v remediation.CampaignViewer) ([]CampaignView, error) {
	out := make([]CampaignView, len(campaigns))
	if len(campaigns) == 0 {
		return out, nil
	}
	tenantID := campaigns[0].TenantID()
	var mine, others []shared.ID
	for _, c := range campaigns {
		if v.Restricted() && isOwnCampaign(c, v) {
			mine = append(mine, c.ID())
		} else {
			others = append(others, c.ID())
		}
	}
	sums, err := s.repo.Summaries(ctx, tenantID, others, v.Scope)
	if err != nil {
		return nil, err
	}
	if len(mine) > 0 {
		whole := &shared.DataScope{TenantID: tenantID, UserID: v.Scope.UserID, Unrestricted: true}
		own, err := s.repo.Summaries(ctx, tenantID, mine, whole)
		if err != nil {
			return nil, err
		}
		for id, sum := range own {
			sums[id] = sum
		}
	}
	for i, c := range campaigns {
		edit, err := s.canEdit(ctx, c, v)
		if err != nil {
			return nil, err
		}
		out[i] = CampaignView{Campaign: c, Summary: sums[c.ID()], CanEdit: edit}
	}
	return out, nil
}

func (s *RemediationCampaignService) view(ctx context.Context, c *remediation.Campaign, v remediation.CampaignViewer) (*CampaignView, error) {
	vs, err := s.views(ctx, []*remediation.Campaign{c}, v)
	if err != nil {
		return nil, err
	}
	return &vs[0], nil
}

func parseIDs(tenantID, campaignID string) (shared.ID, shared.ID, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return shared.ID{}, shared.ID{}, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	cid, err := shared.IDFromString(campaignID)
	if err != nil {
		return shared.ID{}, shared.ID{}, remediation.ErrCampaignNotFound
	}
	return tid, cid, nil
}

// ListCampaigns lists the campaigns the caller may see, with their summaries.
func (s *RemediationCampaignService) ListCampaigns(ctx context.Context, tenantID string, filter remediation.CampaignFilter, page pagination.Pagination) (pagination.Result[CampaignView], error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return pagination.Result[CampaignView]{}, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	v, err := s.viewer(ctx, tid)
	if err != nil {
		return pagination.Result[CampaignView]{}, err
	}
	filter.TenantID, filter.Viewer = &tid, v
	res, err := s.repo.List(ctx, filter, page)
	if err != nil {
		return pagination.Result[CampaignView]{}, err
	}
	vs, err := s.views(ctx, res.Data, v)
	if err != nil {
		return pagination.Result[CampaignView]{}, err
	}
	return pagination.NewResult(vs, res.Total, page), nil
}

// CountCampaignsByStatus counts the campaigns the caller may see, per status.
func (s *RemediationCampaignService) CountCampaignsByStatus(ctx context.Context, tenantID string) (map[remediation.CampaignStatus]int, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	v, err := s.viewer(ctx, tid)
	if err != nil {
		return nil, err
	}
	return s.repo.CountByStatus(ctx, tid, v)
}

// GetCampaign returns a campaign the caller may see.
func (s *RemediationCampaignService) GetCampaign(ctx context.Context, tenantID, campaignID string) (*CampaignView, error) {
	tid, cid, err := parseIDs(tenantID, campaignID)
	if err != nil {
		return nil, err
	}
	c, v, err := s.getVisible(ctx, tid, cid)
	if err != nil {
		return nil, err
	}
	return s.view(ctx, c, v)
}

// CreateRemediationCampaignInput creates a campaign, optionally with tasks.
type CreateRemediationCampaignInput struct {
	TenantID     string
	Name         string
	Description  string
	Priority     string
	AssignedTo   string
	AssignedTeam string
	StartDate    string
	DueDate      string
	Tags         []string
	TaskIDs      []string
	MoveTasks    bool
	ActorID      string
}

// CreateCampaign creates a draft campaign and adds the tasks, if any.
func (s *RemediationCampaignService) CreateCampaign(ctx context.Context, input CreateRemediationCampaignInput, actx auditapp.AuditContext) (*CampaignView, error) {
	tid, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	priority := remediation.CampaignPriorityMedium
	if input.Priority != "" {
		if priority, err = remediation.ParseCampaignPriority(input.Priority); err != nil {
			return nil, err
		}
	}
	name := strings.TrimSpace(input.Name)
	campaign, err := remediation.NewCampaign(tid, name, priority)
	if err != nil {
		return nil, err
	}
	campaign.Update(name, input.Description, priority)
	if input.Tags != nil {
		campaign.SetTags(input.Tags)
	}
	var actor *shared.ID
	if id, aerr := shared.IDFromString(input.ActorID); aerr == nil {
		campaign.SetCreatedBy(id)
		actor = &id
	}
	to, err := s.optionalAssignee(ctx, tid, input.AssignedTo)
	if err != nil {
		return nil, err
	}
	team, err := s.optionalTeam(ctx, tid, input.AssignedTeam)
	if err != nil {
		return nil, err
	}
	campaign.SetAssignment(to, team)
	start, err := optionalCampaignDateStr("start_date", input.StartDate, false)
	if err != nil {
		return nil, err
	}
	due, err := optionalCampaignDateStr("due_date", input.DueDate, true)
	if err != nil {
		return nil, err
	}
	campaign.SetTimeline(start, due)

	taskIDs, err := parseTaskIDs(input.TaskIDs)
	if err != nil {
		return nil, err
	}
	// Check the tasks before anything is stored.
	if _, err := s.checkTasksToAdd(ctx, tid, nil, taskIDs, input.MoveTasks); err != nil {
		return nil, err
	}
	if err := s.repo.Create(ctx, campaign); err != nil {
		return nil, fmt.Errorf("failed to create remediation campaign: %w", err)
	}
	s.logAudit(ctx, tid, actx,
		auditapp.NewSuccessEvent(auditdom.ActionRemediationCampaignCreated, auditdom.ResourceTypeRemediationCampaign, campaign.ID().String()).
			WithResourceName(campaign.Name()).
			WithMessage(fmt.Sprintf("Remediation campaign '%s' created", campaign.Name())).
			WithMetadata("priority", string(campaign.Priority())).
			WithMetadata("tasks", len(taskIDs)).
			WithSeverity(auditdom.SeverityLow))
	if len(taskIDs) > 0 {
		if err := s.putTasks(ctx, campaign, taskIDs, actor, actx); err != nil {
			return nil, err
		}
	}
	v, err := s.viewer(ctx, tid)
	if err != nil {
		return nil, err
	}
	return s.view(ctx, campaign, v)
}

func parseTaskIDs(raw []string) ([]shared.ID, error) {
	seen := make(map[shared.ID]bool, len(raw))
	out := make([]shared.ID, 0, len(raw))
	for _, r := range raw {
		id, err := shared.IDFromString(strings.TrimSpace(r))
		if err != nil {
			return nil, ErrCampaignTaskNotFound
		}
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	if len(out) > MaxCampaignTasksPerRequest {
		return nil, fmt.Errorf("%w: at most %d tasks per request", shared.ErrValidation, MaxCampaignTasksPerRequest)
	}
	return out, nil
}

// checkTasksToAdd refuses tasks the caller may not change and, unless move
// is set, tasks that are in another campaign; with move, the caller must be
// able to change each source campaign. Returns the tasks not already in the
// target campaign.
func (s *RemediationCampaignService) checkTasksToAdd(ctx context.Context, tenantID shared.ID, target *shared.ID, taskIDs []shared.ID, move bool) ([]shared.ID, error) {
	if len(taskIDs) == 0 {
		return nil, nil
	}
	if s.tasks == nil {
		return nil, ErrCampaignTaskNotFound
	}
	refs, err := s.repo.TaskRefs(ctx, tenantID, taskIDs)
	if err != nil {
		return nil, err
	}
	if len(refs) != len(taskIDs) {
		return nil, ErrCampaignTaskNotFound
	}
	for _, id := range taskIDs {
		if err := s.tasks.CheckTaskWritable(ctx, tenantID, id); err != nil {
			if errors.Is(err, shared.ErrNotFound) || errors.Is(err, shared.ErrForbidden) {
				return nil, ErrCampaignTaskNotFound
			}
			return nil, err
		}
	}
	conflicts := make([]CampaignTaskConflict, 0, len(refs))
	add := make([]shared.ID, 0, len(refs))
	for _, ref := range refs {
		if ref.CampaignID != nil && target != nil && *ref.CampaignID == *target {
			continue
		}
		add = append(add, ref.TaskID)
		if ref.CampaignID == nil {
			continue
		}
		c := CampaignTaskConflict{TaskID: ref.TaskID.String(), CampaignID: ref.CampaignID.String()}
		if src, _, verr := s.getVisible(ctx, tenantID, *ref.CampaignID); verr == nil {
			name := src.Name()
			c.CampaignName = &name
			_, _, werr := s.getWritable(ctx, tenantID, *ref.CampaignID)
			c.CanMove = werr == nil
		}
		conflicts = append(conflicts, c)
	}
	if len(conflicts) > 0 {
		if !move {
			return nil, &TasksInOtherCampaignError{Conflicts: conflicts}
		}
		for _, c := range conflicts {
			if !c.CanMove {
				return nil, ErrCampaignOutsideScope
			}
		}
	}
	return add, nil
}

// putTasks moves the tasks into the campaign, re-derives their deadlines and
// audits the change.
func (s *RemediationCampaignService) putTasks(ctx context.Context, c *remediation.Campaign, taskIDs []shared.ID, actor *shared.ID, actx auditapp.AuditContext) error {
	cid := c.ID()
	changed, err := s.repo.SetTasksCampaign(ctx, c.TenantID(), taskIDs, &cid, actor)
	if err != nil {
		return err
	}
	s.recompute(ctx, c.TenantID(), changed)
	if len(changed) > 0 {
		s.logAudit(ctx, c.TenantID(), actx,
			auditapp.NewSuccessEvent(auditdom.ActionRemediationCampaignUpdated, auditdom.ResourceTypeRemediationCampaign, cid.String()).
				WithResourceName(c.Name()).
				WithMessage(fmt.Sprintf("%d task(s) added to remediation campaign '%s'", len(changed), c.Name())).
				WithMetadata("tasks_added", idStrings(changed)).
				WithSeverity(auditdom.SeverityLow))
	}
	return nil
}

func (s *RemediationCampaignService) recompute(ctx context.Context, tenantID shared.ID, ids []shared.ID) {
	if s.tasks == nil || len(ids) == 0 {
		return
	}
	if err := s.tasks.RecomputeTasks(ctx, tenantID, ids); err != nil {
		// The remediation-tasks controller re-derives them on its next pass.
		s.logger.Warn("recompute tasks after a campaign change failed", "error", logger.SanitizeError(err))
	}
}

// AddCampaignTasks adds tasks to a draft or active campaign.
func (s *RemediationCampaignService) AddCampaignTasks(ctx context.Context, tenantID, campaignID string, rawTaskIDs []string, move bool, actorID string, actx auditapp.AuditContext) (*CampaignView, error) {
	tid, cid, err := parseIDs(tenantID, campaignID)
	if err != nil {
		return nil, err
	}
	c, v, err := s.getWritable(ctx, tid, cid)
	if err != nil {
		return nil, err
	}
	if !c.TakesTasks() {
		return nil, remediation.ErrCampaignTakesNoTasks
	}
	taskIDs, err := parseTaskIDs(rawTaskIDs)
	if err != nil {
		return nil, err
	}
	if len(taskIDs) == 0 {
		return nil, fmt.Errorf("%w: task_ids is required", shared.ErrValidation)
	}
	add, err := s.checkTasksToAdd(ctx, tid, &cid, taskIDs, move)
	if err != nil {
		return nil, err
	}
	if err := s.putTasks(ctx, c, add, optionalID(actorID), actx); err != nil {
		return nil, err
	}
	return s.view(ctx, c, v)
}

// RemoveCampaignTask takes a task out of the campaign (the task stays).
func (s *RemediationCampaignService) RemoveCampaignTask(ctx context.Context, tenantID, campaignID, taskID, actorID string, actx auditapp.AuditContext) (*CampaignView, error) {
	tid, cid, err := parseIDs(tenantID, campaignID)
	if err != nil {
		return nil, err
	}
	c, v, err := s.getWritable(ctx, tid, cid)
	if err != nil {
		return nil, err
	}
	tk, err := shared.IDFromString(taskID)
	if err != nil {
		return nil, ErrCampaignTaskNotFound
	}
	refs, err := s.repo.TaskRefs(ctx, tid, []shared.ID{tk})
	if err != nil {
		return nil, err
	}
	if len(refs) != 1 || refs[0].CampaignID == nil || *refs[0].CampaignID != cid {
		return nil, ErrCampaignTaskNotInCampaign
	}
	changed, err := s.repo.SetTasksCampaign(ctx, tid, []shared.ID{tk}, nil, optionalID(actorID))
	if err != nil {
		return nil, err
	}
	s.recompute(ctx, tid, changed)
	s.logAudit(ctx, tid, actx,
		auditapp.NewSuccessEvent(auditdom.ActionRemediationCampaignUpdated, auditdom.ResourceTypeRemediationCampaign, cid.String()).
			WithResourceName(c.Name()).
			WithMessage(fmt.Sprintf("A task left remediation campaign '%s'", c.Name())).
			WithMetadata("tasks_removed", []string{tk.String()}).
			WithSeverity(auditdom.SeverityLow))
	return s.view(ctx, c, v)
}

// CheckTaskCampaignChange is the campaign side of moving one task between
// campaigns through the task itself (PATCH task campaign_id): the target
// must be a draft or active campaign the caller may change, and so must the
// task's current campaign when it leaves one. from/to nil = no campaign.
func (s *RemediationCampaignService) CheckTaskCampaignChange(ctx context.Context, tenantID shared.ID, from, to *shared.ID) error {
	if to != nil {
		c, _, err := s.getWritable(ctx, tenantID, *to)
		if err != nil {
			if errors.Is(err, shared.ErrNotFound) {
				return fmt.Errorf("%w: the campaign was not found", shared.ErrValidation)
			}
			return err
		}
		if !c.TakesTasks() {
			return remediation.ErrCampaignTakesNoTasks
		}
	}
	if from != nil && (to == nil || *from != *to) {
		if _, _, err := s.getWritable(ctx, tenantID, *from); err != nil && !errors.Is(err, shared.ErrNotFound) {
			return err
		}
	}
	return nil
}

func optionalID(s string) *shared.ID {
	id, err := shared.IDFromString(s)
	if err != nil {
		return nil
	}
	return &id
}

func idStrings(ids []shared.ID) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = id.String()
	}
	return out
}

func parseCampaignDate(field, s string, endOfDay bool) (*time.Time, error) {
	s = strings.TrimSpace(s)
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return &t, nil
	}
	if d, err := time.Parse(time.DateOnly, s); err == nil {
		if endOfDay {
			d = d.Add(24*time.Hour - time.Second)
		}
		return &d, nil
	}
	return nil, fmt.Errorf("%w: %s must be an RFC 3339 timestamp or a date (YYYY-MM-DD)", shared.ErrValidation, field)
}

func optionalCampaignDateStr(field, s string, endOfDay bool) (*time.Time, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	return parseCampaignDate(field, s, endOfDay)
}

func (s *RemediationCampaignService) optionalAssignee(ctx context.Context, tenantID shared.ID, raw string) (*shared.ID, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	id, err := shared.IDFromString(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid assigned_to id", shared.ErrValidation)
	}
	return &id, s.assertAssignee(ctx, tenantID, &id)
}

func (s *RemediationCampaignService) optionalTeam(ctx context.Context, tenantID shared.ID, raw string) (*shared.ID, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	id, err := shared.IDFromString(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid assigned_team id", shared.ErrValidation)
	}
	return &id, s.assertTeam(ctx, tenantID, &id)
}

func (s *RemediationCampaignService) assertTeam(ctx context.Context, tenantID shared.ID, groupID *shared.ID) error {
	if groupID == nil {
		return nil
	}
	if s.assignees == nil {
		return ErrInvalidCampaignTeam
	}
	ok, err := s.assignees.IsGroupInTenant(ctx, tenantID, *groupID)
	if err != nil {
		return fmt.Errorf("check campaign team: %w", err)
	}
	if !ok {
		return ErrInvalidCampaignTeam
	}
	return nil
}

func (s *RemediationCampaignService) assertAssignee(ctx context.Context, tenantID shared.ID, userID *shared.ID) error {
	if userID == nil {
		return nil
	}
	if s.assignees == nil {
		return ErrInvalidCampaignAssignee
	}
	ok, err := s.assignees.IsActiveTenantMember(ctx, tenantID, *userID)
	if err != nil {
		return fmt.Errorf("check campaign assignee: %w", err)
	}
	if !ok {
		return ErrInvalidCampaignAssignee
	}
	return nil
}

// UpdateRemediationCampaignInput: nil leaves a field; "" clears an optional
// one (dates, assignee, team).
type UpdateRemediationCampaignInput struct {
	Name         *string
	Description  *string
	Priority     *string
	Tags         []string
	StartDate    *string
	DueDate      *string
	AssignedTo   *string
	AssignedTeam *string
	Version      *int
}

// deadlineOnlyTightens refuses moving a campaign's due date later or
// clearing it once set.
func deadlineOnlyTightens(current, next *time.Time) error {
	if current == nil {
		return nil
	}
	if next == nil || remediation.DueDayEnd(*next).After(remediation.DueDayEnd(*current)) {
		return remediation.ErrCampaignDeadlineOnlyTightens
	}
	return nil
}

func checkVersion(campaign *remediation.Campaign, expected *int) error {
	if expected != nil && *expected != campaign.Version() {
		return remediation.ErrCampaignVersionConflict
	}
	return nil
}

// UpdateCampaign changes a campaign's fields.
func (s *RemediationCampaignService) UpdateCampaign(ctx context.Context, tenantID, campaignID string, input UpdateRemediationCampaignInput, actx auditapp.AuditContext) (*CampaignView, error) {
	tid, cid, err := parseIDs(tenantID, campaignID)
	if err != nil {
		return nil, err
	}
	campaign, v, err := s.getWritable(ctx, tid, cid)
	if err != nil {
		return nil, err
	}
	if err := checkVersion(campaign, input.Version); err != nil {
		return nil, err
	}
	before := snapshotCampaign(campaign)
	dueChanged := false
	if input.Name != nil {
		name := strings.TrimSpace(*input.Name)
		if name == "" {
			return nil, fmt.Errorf("%w: name is required", shared.ErrValidation)
		}
		campaign.SetName(name)
	}
	if input.Description != nil {
		campaign.SetDescription(*input.Description)
	}
	if input.Priority != nil {
		p, perr := remediation.ParseCampaignPriority(*input.Priority)
		if perr != nil {
			return nil, perr
		}
		campaign.SetPriority(p)
	}
	if input.Tags != nil {
		campaign.SetTags(input.Tags)
	}
	if input.StartDate != nil {
		start, derr := optionalCampaignDateStr("start_date", *input.StartDate, false)
		if derr != nil {
			return nil, derr
		}
		campaign.SetStartDate(start)
	}
	if input.DueDate != nil {
		due, derr := optionalCampaignDateStr("due_date", *input.DueDate, true)
		if derr != nil {
			return nil, derr
		}
		if err := deadlineOnlyTightens(campaign.DueDate(), due); err != nil {
			return nil, err
		}
		campaign.SetDueDate(due)
		dueChanged = true
	}
	if input.AssignedTo != nil || input.AssignedTeam != nil {
		to, team := campaign.AssignedTo(), campaign.AssignedTeam()
		if input.AssignedTo != nil {
			if to, err = s.optionalAssignee(ctx, tid, *input.AssignedTo); err != nil {
				return nil, err
			}
		}
		if input.AssignedTeam != nil {
			if team, err = s.optionalTeam(ctx, tid, *input.AssignedTeam); err != nil {
				return nil, err
			}
		}
		campaign.SetAssignment(to, team)
	}
	if err := s.repo.Update(ctx, campaign); err != nil {
		if errors.Is(err, shared.ErrConflict) || errors.Is(err, shared.ErrNotFound) {
			return nil, err
		}
		return nil, fmt.Errorf("failed to update campaign: %w", err)
	}
	if dueChanged && s.tasks != nil {
		// The due date bounds every live task of the campaign.
		if ids, lerr := s.tasks.CampaignTaskIDs(ctx, tid, cid); lerr == nil {
			s.recompute(ctx, tid, ids)
		}
	}
	if changes := diffCampaign(before, snapshotCampaign(campaign)); !changes.IsEmpty() {
		s.logAudit(ctx, tid, actx,
			auditapp.NewSuccessEvent(auditdom.ActionRemediationCampaignUpdated, auditdom.ResourceTypeRemediationCampaign, cid.String()).
				WithResourceName(campaign.Name()).
				WithChanges(changes).
				WithMessage(fmt.Sprintf("Remediation campaign '%s' updated", campaign.Name())).
				WithSeverity(auditdom.SeverityLow))
	}
	return s.view(ctx, campaign, v)
}

// UpdateCampaignStatus moves a campaign: active (start a draft, reopen a
// completed one), completed (only when done: every task closed and one done),
// canceled (from draft or active). Its tasks are not changed.
func (s *RemediationCampaignService) UpdateCampaignStatus(ctx context.Context, tenantID, campaignID, newStatus string, expectedVersion *int, actx auditapp.AuditContext) (*CampaignView, error) {
	tid, cid, err := parseIDs(tenantID, campaignID)
	if err != nil {
		return nil, err
	}
	campaign, v, err := s.getWritable(ctx, tid, cid)
	if err != nil {
		return nil, err
	}
	if err := checkVersion(campaign, expectedVersion); err != nil {
		return nil, err
	}
	from := campaign.Status()
	switch remediation.CampaignStatus(newStatus) {
	case remediation.CampaignStatusActive:
		if from == remediation.CampaignStatusCompleted {
			err = campaign.Reopen()
		} else {
			err = campaign.Activate()
		}
	case remediation.CampaignStatusCompleted:
		whole, serr := s.wholeSummary(ctx, campaign)
		if serr != nil {
			return nil, serr
		}
		if !whole.IsDone() {
			return nil, remediation.ErrCampaignNotDone
		}
		err = campaign.Complete()
	case remediation.CampaignStatusCanceled:
		err = campaign.Cancel()
	default:
		return nil, fmt.Errorf("%w: status must be active, completed or canceled", shared.ErrValidation)
	}
	if err != nil {
		return nil, err
	}
	if err := s.repo.Update(ctx, campaign); err != nil {
		if errors.Is(err, shared.ErrConflict) || errors.Is(err, shared.ErrNotFound) {
			return nil, err
		}
		return nil, fmt.Errorf("failed to update campaign status: %w", err)
	}
	if campaign.Status() == remediation.CampaignStatusCompleted {
		s.syncEpicOnCompletion(ctx, tid, cid, campaign.Name())
	}
	if campaign.Status() == remediation.CampaignStatusCanceled && s.tasks != nil {
		// A canceled campaign's due date no longer bounds its tasks.
		if ids, lerr := s.tasks.CampaignTaskIDs(ctx, tid, cid); lerr == nil {
			s.recompute(ctx, tid, ids)
		}
	}
	s.auditStatusChange(ctx, campaign, from, actx, "manual")
	return s.view(ctx, campaign, v)
}

// wholeSummary is the campaign's summary over every task (what completion
// and the reconcile decide on).
func (s *RemediationCampaignService) wholeSummary(ctx context.Context, c *remediation.Campaign) (remediation.CampaignSummary, error) {
	sums, err := s.repo.Summaries(ctx, c.TenantID(), []shared.ID{c.ID()}, nil)
	if err != nil {
		return remediation.CampaignSummary{}, err
	}
	return sums[c.ID()], nil
}

// DeleteCampaign deletes a campaign; its tasks stay and leave it.
func (s *RemediationCampaignService) DeleteCampaign(ctx context.Context, tenantID, campaignID string, actx auditapp.AuditContext) error {
	tid, cid, err := parseIDs(tenantID, campaignID)
	if err != nil {
		return err
	}
	campaign, _, err := s.getWritable(ctx, tid, cid)
	if err != nil {
		return err
	}
	var ids []shared.ID
	if s.tasks != nil {
		ids, _ = s.tasks.CampaignTaskIDs(ctx, tid, cid)
	}
	if err := s.repo.Delete(ctx, tid, cid); err != nil {
		return err
	}
	s.recompute(ctx, tid, ids)
	s.logAudit(ctx, tid, actx,
		auditapp.NewSuccessEvent(auditdom.ActionRemediationCampaignDeleted, auditdom.ResourceTypeRemediationCampaign, cid.String()).
			WithResourceName(campaign.Name()).
			WithMessage(fmt.Sprintf("Remediation campaign '%s' deleted; its tasks stay", campaign.Name())).
			WithMetadata("status", string(campaign.Status())).
			WithMetadata("live_tasks", len(ids)).
			WithSeverity(auditdom.SeverityMedium))
	return nil
}

// ReconcileProgress completes active campaigns whose tasks are done and
// reopens completed ones with a live task again (the remediation progress
// controller). Returns how many campaigns changed.
func (s *RemediationCampaignService) ReconcileProgress(ctx context.Context) (int, error) {
	campaigns, err := s.repo.ListForReconcile(ctx, 0)
	if err != nil {
		return 0, fmt.Errorf("failed to list campaigns for reconcile: %w", err)
	}
	changed := 0
	disabled := make(map[shared.ID]bool)
	for _, c := range campaigns {
		if s.modules != nil {
			off, seen := disabled[c.TenantID()]
			if !seen {
				off = s.modules.TenantDisabledModules(ctx, c.TenantID().String())[moduledom.ModuleRemediation]
				disabled[c.TenantID()] = off
			}
			if off {
				continue
			}
		}
		sum, serr := s.wholeSummary(ctx, c)
		if serr != nil {
			s.logger.Warn("campaign reconcile failed", "id", c.ID().String(), "error", serr)
			continue
		}
		from := c.Status()
		trigger := ""
		switch {
		case c.TryAutoComplete(sum):
			trigger = "auto_complete"
		case c.TryAutoReopen(sum):
			trigger = "auto_reopen"
		default:
			continue
		}
		if uerr := s.repo.Update(ctx, c); uerr != nil {
			s.logger.Info("campaign reconcile skipped: changed since read", "id", c.ID().String(), "error", uerr)
			continue
		}
		if c.Status() == remediation.CampaignStatusCompleted {
			s.syncEpicOnCompletion(ctx, c.TenantID(), c.ID(), c.Name())
		}
		s.auditStatusChange(ctx, c, from, auditapp.AuditContext{ActorEmail: campaignAuditSystemActor}, trigger)
		changed++
	}
	return changed, nil
}

func (s *RemediationCampaignService) syncEpicOnCompletion(ctx context.Context, tenantID, campaignID shared.ID, campaignName string) {
	if s.ticketRepo == nil || s.epicCreator == nil {
		return
	}
	link, err := s.ticketRepo.GetByCampaignAndProvider(ctx, tenantID, campaignID, "jira")
	if err != nil {
		return // not linked (or lookup failed): nothing to sync
	}
	comment := fmt.Sprintf("%s marked remediation campaign %q complete.", brand.Name(), campaignName)
	if terr := s.epicCreator.TransitionEpic(ctx, tenantID, link.IssueKey(), epicDoneStatus, comment); terr != nil {
		s.logger.Warn("failed to sync campaign completion to epic",
			"campaign_id", campaignID.String(), "issue_key", link.IssueKey(), "error", terr)
	}
}

// HandleEpicStatusChange reacts to a campaign's Jira epic moving to a done
// status: every live task of the campaign is marked fixed (a fix claim on
// each open finding, which each finding then verifies on its own; never a
// close). Returns the refusals, whether the issue was a campaign epic, and
// an error.
func (s *RemediationCampaignService) HandleEpicStatusChange(ctx context.Context, tenantID shared.ID, issueKey, jiraStatus, jiraAccount string) ([]string, bool, error) {
	if s.ticketRepo == nil {
		return nil, false, nil
	}
	link, err := s.ticketRepo.GetByIssueKey(ctx, tenantID, "jira", issueKey)
	if err != nil {
		if errors.Is(err, remediation.ErrCampaignTicketNotFound) {
			return nil, false, nil // not a campaign epic
		}
		return nil, false, fmt.Errorf("lookup campaign by issue key: %w", err)
	}
	if !isJiraDoneStatus(jiraStatus) || s.tasks == nil {
		return nil, true, nil
	}
	ids, err := s.tasks.CampaignTaskIDs(ctx, tenantID, link.CampaignID())
	if err != nil {
		return []string{campaignEpicClaimFailed}, true, fmt.Errorf("list campaign tasks: %w", err)
	}
	note := campaignEpicNote(issueKey, jiraStatus, jiraAccount)
	var refusals []string
	for _, id := range ids {
		r, cerr := s.tasks.ClaimTaskFixed(ctx, tenantID, id, note)
		if cerr != nil {
			refusals = append(refusals, id.String()+": "+campaignEpicClaimFailed)
			s.logger.Warn("mark campaign task fixed from epic failed", "task_id", id.String(), "error", logger.SanitizeError(cerr))
			continue
		}
		refusals = append(refusals, r...)
	}
	s.logger.Info("campaign tasks marked fixed from inbound jira epic",
		"campaign_id", link.CampaignID().String(), "tasks", len(ids), "refusals", len(refusals))
	return refusals, true, nil
}

const campaignEpicClaimFailed = "the campaign's task could not be marked fixed; see the campaign in OpenCTEM"

func campaignEpicNote(issueKey, jiraStatus, account string) string {
	note := fmt.Sprintf("jira %s (campaign epic) moved to %s", issueKey, jiraStatus)
	if account != "" {
		note += " by jira account " + account
	}
	return note
}

func isJiraDoneStatus(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "done", "resolved", "closed", "complete", "completed":
		return true
	}
	return false
}

// CampaignTicketInfo describes a campaign's external tracker link.
type CampaignTicketInfo struct {
	CampaignID     string `json:"campaign_id"`
	Provider       string `json:"provider"`
	IssueKey       string `json:"issue_key"`
	IssueURL       string `json:"issue_url"`
	AlreadyExisted bool   `json:"already_existed"`
}

// CreateTicket creates a Jira epic for a campaign and links it. Idempotent.
func (s *RemediationCampaignService) CreateTicket(ctx context.Context, tenantID, campaignID, projectKey string) (*CampaignTicketInfo, error) {
	if s.ticketRepo == nil || s.epicCreator == nil {
		return nil, ErrTicketingNotConfigured
	}
	if projectKey == "" {
		return nil, fmt.Errorf("%w: project_key is required", shared.ErrValidation)
	}
	tid, cid, err := parseIDs(tenantID, campaignID)
	if err != nil {
		return nil, err
	}
	campaign, _, err := s.getWritable(ctx, tid, cid)
	if err != nil {
		return nil, err
	}
	const provider = "jira"
	if existing, gerr := s.ticketRepo.GetByCampaignAndProvider(ctx, tid, cid, provider); gerr == nil {
		return &CampaignTicketInfo{
			CampaignID: campaignID, Provider: provider,
			IssueKey: existing.IssueKey(), IssueURL: existing.IssueURL(),
			AlreadyExisted: true,
		}, nil
	} else if !errors.Is(gerr, remediation.ErrCampaignTicketNotFound) {
		return nil, fmt.Errorf("check existing campaign ticket: %w", gerr)
	}
	whole, err := s.wholeSummary(ctx, campaign)
	if err != nil {
		return nil, err
	}
	summary := fmt.Sprintf("[Remediation] %s", campaign.Name())
	key, url, err := s.epicCreator.CreateEpic(ctx, tid, projectKey, summary, buildEpicDescription(campaign, whole),
		[]string{"openctem", "remediation-campaign"})
	if err != nil {
		return nil, fmt.Errorf("create campaign epic: %w", err)
	}
	link, err := remediation.NewCampaignTicket(tid, cid, provider, key, url)
	if err != nil {
		return nil, err
	}
	if err := s.ticketRepo.Create(ctx, link); err != nil {
		s.logger.Error("created jira epic but failed to persist campaign link",
			"campaign_id", cid.String(), "issue_key", key, "error", err)
		return nil, fmt.Errorf("persist campaign ticket link: %w", err)
	}
	return &CampaignTicketInfo{CampaignID: cid.String(), Provider: provider, IssueKey: key, IssueURL: url}, nil
}

// CampaignTicketLink is the linked tracker issue a campaign response shows.
type CampaignTicketLink struct {
	Provider string `json:"provider"`
	IssueKey string `json:"issue_key"`
	IssueURL string `json:"issue_url"`
}

// CampaignTicketFor returns the campaign's Jira epic link, or nil.
func (s *RemediationCampaignService) CampaignTicketFor(ctx context.Context, tenantID, campaignID shared.ID) (*CampaignTicketLink, error) {
	if s.ticketRepo == nil {
		return nil, nil
	}
	link, err := s.ticketRepo.GetByCampaignAndProvider(ctx, tenantID, campaignID, "jira")
	if err != nil {
		if errors.Is(err, remediation.ErrCampaignTicketNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &CampaignTicketLink{Provider: link.Provider(), IssueKey: link.IssueKey(), IssueURL: link.IssueURL()}, nil
}

// CampaignTicketsFor batch-loads the epic links of campaigns.
func (s *RemediationCampaignService) CampaignTicketsFor(ctx context.Context, tenantID shared.ID, campaignIDs []shared.ID) (map[string]*CampaignTicketLink, error) {
	out := make(map[string]*CampaignTicketLink, len(campaignIDs))
	if s.ticketRepo == nil || len(campaignIDs) == 0 {
		return out, nil
	}
	links, err := s.ticketRepo.ListByCampaignIDs(ctx, tenantID, campaignIDs)
	if err != nil {
		return nil, err
	}
	for cid, link := range links {
		out[cid] = &CampaignTicketLink{Provider: link.Provider(), IssueKey: link.IssueKey(), IssueURL: link.IssueURL()}
	}
	return out, nil
}

func buildEpicDescription(c *remediation.Campaign, sum remediation.CampaignSummary) string {
	desc := c.Description()
	if desc == "" {
		desc = "(no description)"
	}
	body := fmt.Sprintf("Remediation campaign tracked by %s.\n\n%s\n\nProgress: %d tasks, %d of %d findings closed (%.0f%%).",
		brand.Name(), desc, sum.Tasks, sum.ClosedFindings, sum.Findings, sum.Progress())
	if due := c.DueDate(); due != nil {
		body += fmt.Sprintf("\nDue: %s", due.Format("2006-01-02"))
	}
	return body
}

func (s *RemediationCampaignService) logAudit(ctx context.Context, tenantID shared.ID, actx auditapp.AuditContext, ev auditapp.AuditEvent) {
	if s.audit == nil {
		return
	}
	actx.TenantID = tenantID.String()
	if err := s.audit.LogEvent(ctx, actx, ev); err != nil {
		s.logger.Warn("failed to write remediation campaign audit event", "action", string(ev.Action), "error", logger.SanitizeError(err))
	}
}

func (s *RemediationCampaignService) auditStatusChange(ctx context.Context, c *remediation.Campaign, from remediation.CampaignStatus, actx auditapp.AuditContext, trigger string) {
	to := c.Status()
	ev := auditapp.NewSuccessEvent(auditdom.ActionRemediationCampaignStatusChanged, auditdom.ResourceTypeRemediationCampaign, c.ID().String()).
		WithResourceName(c.Name()).
		WithChanges(auditdom.NewChanges().Set("status", string(from), string(to))).
		WithMessage(fmt.Sprintf("Remediation campaign '%s' status changed from %s to %s", c.Name(), from, to)).
		WithMetadata("trigger", trigger).
		WithSeverity(auditdom.SeverityLow)
	if to == remediation.CampaignStatusCanceled {
		ev = ev.WithSeverity(auditdom.SeverityMedium)
	}
	s.logAudit(ctx, c.TenantID(), actx, ev)
}

type campaignSnapshot struct {
	name, description, priority string
	assignedTo, assignedTeam    string
	startDate, dueDate          string
	tags                        []string
}

func snapshotCampaign(c *remediation.Campaign) campaignSnapshot {
	return campaignSnapshot{
		name:         c.Name(),
		description:  c.Description(),
		priority:     string(c.Priority()),
		assignedTo:   idString(c.AssignedTo()),
		assignedTeam: idString(c.AssignedTeam()),
		startDate:    dateString(c.StartDate()),
		dueDate:      dateString(c.DueDate()),
		tags:         append([]string(nil), c.Tags()...),
	}
}

func diffCampaign(before, after campaignSnapshot) *auditdom.Changes {
	ch := auditdom.NewChanges()
	setIf := func(key, b, a string) {
		if b != a {
			ch.Set(key, b, a)
		}
	}
	setIf("name", before.name, after.name)
	setIf("priority", before.priority, after.priority)
	setIf("assigned_to", before.assignedTo, after.assignedTo)
	setIf("assigned_team", before.assignedTeam, after.assignedTeam)
	setIf("start_date", before.startDate, after.startDate)
	setIf("due_date", before.dueDate, after.dueDate)
	setIf("description", before.description, after.description)
	if strings.Join(before.tags, "\x00") != strings.Join(after.tags, "\x00") {
		ch.Set("tags", before.tags, after.tags)
	}
	return ch
}

func idString(id *shared.ID) string {
	if id == nil {
		return ""
	}
	return id.String()
}

func dateString(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}
