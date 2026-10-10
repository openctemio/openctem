package exposure

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/internal/app/datascope"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	moduledom "github.com/openctemio/openctem/api/pkg/domain/module"
	"github.com/openctemio/openctem/api/pkg/domain/remediation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// FindingCounter is the narrow slice of the finding repository the campaign
// service needs to compute progress: how many findings match a filter.
// Satisfied by *postgres.FindingRepository.
type FindingCounter interface {
	Count(ctx context.Context, filter vulnerability.FindingFilter) (int64, error)
}

// FindingLister lists the findings a filter selects, one page at a time.
// Satisfied by *postgres.FindingRepository.
type FindingLister interface {
	List(ctx context.Context, filter vulnerability.FindingFilter, opts vulnerability.FindingListOptions, page pagination.Pagination) (pagination.Result[*vulnerability.Finding], error)
}

// CampaignEpicCreator creates and transitions an external tracker epic for a
// tenant. Implemented by *jira.SyncService. Declared here with primitive types
// so this package needs no dependency on the jira package.
type CampaignEpicCreator interface {
	CreateEpic(ctx context.Context, tenantID shared.ID, projectKey, summary, description string, labels []string) (issueKey, issueURL string, err error)
	// TransitionEpic moves the linked epic to a target status name (echo-safe,
	// comment fallback). Best-effort outbound campaign→epic status sync.
	TransitionEpic(ctx context.Context, tenantID shared.ID, issueKey, targetStatus, comment string) error
}

// epicDoneStatus is the Jira status a campaign's epic is moved to on completion.
// Jira's default done state; per-tenant override is a documented follow-up.
const epicDoneStatus = "Done"

// CampaignFindingResolver bulk-resolves the OPEN findings matching a filter,
// turning a campaign from a passive progress tracker into an active closer
// (RFC-015 Phase 3). Nil → the resolve action is unavailable. Implemented by an
// adapter over the finding bulk-status path + its abuse guard.
type CampaignFindingResolver interface {
	ResolveOpenByFilter(ctx context.Context, tenantID string, filter vulnerability.FindingFilter, in CampaignResolveInput) (resolvedCount int, err error)
}

// CampaignKeyResolver serves campaigns scoped to a remediation-group key (a
// "solution family" — every finding one fix resolves). Progress and resolution
// for such a campaign are computed from the remediation side-table, NOT from a
// generic FindingFilter (the key isn't expressible as one). Nil → keyed
// campaigns cannot compute progress or resolve. Implemented by an adapter over
// the remediation key repository + group resolver at the composition root.
type CampaignKeyResolver interface {
	// CountByKey returns (total, resolved) findings sharing the remediation key.
	// A non-nil scope counts only findings on the scope's assets.
	CountByKey(ctx context.Context, tenantID shared.ID, key string, scope *shared.DataScope) (total, resolved int64, err error)
	// ResolveGroupByKey bulk-resolves the OPEN findings under the key, reusing
	// the same guarded bulk-status path as the standalone group resolve.
	ResolveGroupByKey(ctx context.Context, tenantID string, key string, in CampaignResolveInput) (resolvedCount int, err error)
}

// CampaignResolveInput parameterizes a campaign resolve.
type CampaignResolveInput struct {
	Status              string // fix_applied (default) or resolved
	Resolution          string
	ActorID             string
	HasVerifyPermission bool
	Approved            bool
}

// RemediationCampaignService manages remediation campaigns.
type RemediationCampaignService struct {
	dataScope   *datascope.Enforcer // Layer 2: a restricted reader's progress counts (nil = unrestricted)
	repo        remediation.CampaignRepository
	finding     FindingCounter                       // nil → progress stays zero
	lister      FindingLister                        // nil → a campaign lists no findings
	resolver    CampaignFindingResolver              // nil → resolve action disabled
	keyResolver CampaignKeyResolver                  // nil → keyed campaigns can't count/resolve
	ticketRepo  remediation.CampaignTicketRepository // nil → ticketing disabled
	epicCreator CampaignEpicCreator                  // nil → ticketing disabled
	audit       CampaignAuditLogger                  // nil → no audit trail (tests)
	assignees   CampaignAssigneeChecker              // nil → naming an assignee is refused
	modules     CampaignModuleGuard                  // nil → progress reconciles for every tenant
	logger      *logger.Logger
}

// CampaignModuleGuard reports the modules a tenant has off
// (*module.ModuleService). The background progress reconcile skips the
// campaigns of a tenant with the remediation module off: no counts written,
// no auto-complete, no ticket sync. The next pass after the module is turned
// back on catches up.
type CampaignModuleGuard interface {
	TenantDisabledModules(ctx context.Context, tenantID string) map[string]bool
}

// SetModuleGuard wires the tenant module state into the progress reconcile.
func (s *RemediationCampaignService) SetModuleGuard(g CampaignModuleGuard) { s.modules = g }

// CampaignAssigneeChecker decides whether a user may own a campaign in a
// tenant: an active member with an active account.
// postgres.AccessControlRepository.IsActiveTenantMember implements it.
type CampaignAssigneeChecker interface {
	IsActiveTenantMember(ctx context.Context, tenantID, userID shared.ID) (bool, error)
	// IsGroupInTenant reports whether a group (the campaign's validator
	// team) belongs to the tenant.
	IsGroupInTenant(ctx context.Context, tenantID, groupID shared.ID) (bool, error)
}

// SetAssigneeChecker wires the campaign owner membership check. Without it
// naming an owner is refused (fail closed).
func (s *RemediationCampaignService) SetAssigneeChecker(c CampaignAssigneeChecker) {
	s.assignees = c
}

// ErrInvalidCampaignAssignee is the one answer for an owner who is not an
// active member of the organization (unknown, of another organization,
// suspended or deactivated), so the endpoint is no oracle for which user ids
// exist elsewhere (research doc 21b, C2 / L-15).
var ErrInvalidCampaignAssignee = fmt.Errorf("%w: the assignee must be an active member of this organization", shared.ErrValidation)

// ErrInvalidCampaignTeam is the one answer for a validator team that is not a
// group of the campaign's organization (unknown or another organization's),
// so the endpoint is no oracle for group ids elsewhere.
var ErrInvalidCampaignTeam = fmt.Errorf("%w: the team must be a group of this organization", shared.ErrValidation)

// assertTeam refuses a validator team that is not a group of the tenant.
// remediation_campaigns.assigned_team carries no tenant check of its own. A
// nil id (no team, or unassign) needs no check; without a checker naming a
// team is refused (fail closed).
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

// assertAssignee refuses an owner who is not an active member of the tenant.
// A nil id (no owner, or unassign) needs no check.
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

// CampaignAuditLogger writes audit-log events. *auditapp.AuditService
// implements it.
type CampaignAuditLogger interface {
	LogEvent(ctx context.Context, actx auditapp.AuditContext, event auditapp.AuditEvent) error
}

// campaignAuditSystemActor names the actor of a change no user made: the
// background reconcile auto-completing a campaign, or an inbound Jira epic.
const campaignAuditSystemActor = "system"

// NewRemediationCampaignService creates a new service.
func NewRemediationCampaignService(repo remediation.CampaignRepository, log *logger.Logger) *RemediationCampaignService {
	return &RemediationCampaignService{repo: repo, logger: log}
}

// SetAuditLogger wires the audit log. Creates, edits, status changes
// (manual and automatic) and deletes are recorded in audit_logs.
func (s *RemediationCampaignService) SetAuditLogger(a CampaignAuditLogger) {
	s.audit = a
}

// SetFindingCounter wires the finding counter used to compute campaign
// progress. When unset, progress stays at zero (the service still functions as
// plain CRUD). Kept as a setter so the constructor signature is stable and to
// avoid an import cycle at the composition root.
func (s *RemediationCampaignService) SetFindingCounter(c FindingCounter) {
	s.finding = c
}

// SetDataScope wires the Layer 2 data-scope enforcer: a restricted reader
// sees campaign progress over their own in-scope findings (ApplyViewerScope).
func (s *RemediationCampaignService) SetDataScope(e *datascope.Enforcer) {
	s.dataScope = e
}

// SetFindingLister wires the finding list behind ListCampaignFindings.
func (s *RemediationCampaignService) SetFindingLister(l FindingLister) { s.lister = l }

// ListCampaignFindings lists one page of the campaign's findings: the set its
// finding count counts (campaignFindingFilter), on the caller's in-scope
// assets when the caller is restricted. Tenant-scoped: a campaign of another
// tenant is not found.
func (s *RemediationCampaignService) ListCampaignFindings(ctx context.Context, tenantID, campaignID string, page pagination.Pagination) (pagination.Result[*vulnerability.Finding], error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return pagination.Result[*vulnerability.Finding]{}, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	cid, err := shared.IDFromString(campaignID)
	if err != nil {
		return pagination.Result[*vulnerability.Finding]{}, shared.ErrNotFound
	}
	campaign, err := s.repo.GetByID(ctx, tid, cid)
	if err != nil {
		return pagination.Result[*vulnerability.Finding]{}, err
	}
	none := pagination.NewResult([]*vulnerability.Finding{}, 0, page)
	filter, ok := campaignFindingFilter(campaign)
	if !ok || s.lister == nil {
		return none, nil
	}
	if s.dataScope != nil {
		scope, err := s.dataScope.Resolve(ctx, tid)
		if err != nil {
			return pagination.Result[*vulnerability.Finding]{}, fmt.Errorf("resolve data scope: %w", err)
		}
		filter = filter.WithDataScope(scope)
	}
	return s.lister.List(ctx, filter, vulnerability.NewFindingListOptions(), page)
}

// campaignFindingFilter is the set of findings a campaign tracks, whatever
// their status: a keyed campaign's solution family, or its finding filter.
// ok is false for a campaign without scope, which tracks nothing.
func campaignFindingFilter(campaign *remediation.Campaign) (vulnerability.FindingFilter, bool) {
	if key := campaignRemediationKey(campaign.FindingFilter()); key != "" {
		f := vulnerability.NewFindingFilter().WithTenantID(campaign.TenantID())
		f.RemediationKey = &key
		return f, true
	}
	f := campaignFilterToFindingFilter(campaign.TenantID(), campaign.FindingFilter())
	if !findingFilterHasScope(f) {
		return f, false
	}
	// The whole scope regardless of status, so the count stays stable as
	// findings resolve (see recomputeProgress).
	f.Statuses = nil
	return f, true
}

// ApplyViewerScope replaces the campaign's finding and resolved counts, in
// memory only, with the ones over the caller's in-scope findings when the
// caller is restricted (research 24 §5.1, gap L-18). The stored counts stay
// organization-wide: auto-complete and the controller read those, and a
// restricted read never persists its view. Unrestricted callers are left
// unchanged. Errors fail closed (zero counts) rather than show the
// organization's numbers.
func (s *RemediationCampaignService) ApplyViewerScope(ctx context.Context, campaign *remediation.Campaign) {
	if s.dataScope == nil || campaign == nil {
		return
	}
	scope, err := s.dataScope.Resolve(ctx, campaign.TenantID())
	if err != nil {
		s.logger.Warn("campaign viewer scope failed", "id", campaign.ID().String(), "error", err)
		campaign.UpdateProgress(0, 0)
		return
	}
	if scope == nil {
		return
	}
	total, resolved, err := s.scopedProgress(ctx, campaign, scope)
	if err != nil {
		s.logger.Warn("campaign scoped progress failed", "id", campaign.ID().String(), "error", err)
		total, resolved = 0, 0
	}
	campaign.UpdateProgress(int(total), int(resolved))
}

// scopedProgress counts the campaign's findings and closed findings on the
// scope's assets, with the same rules as recomputeProgress.
func (s *RemediationCampaignService) scopedProgress(ctx context.Context, campaign *remediation.Campaign, scope *shared.DataScope) (int64, int64, error) {
	if key := campaignRemediationKey(campaign.FindingFilter()); key != "" {
		if s.keyResolver == nil {
			return 0, 0, nil
		}
		return s.keyResolver.CountByKey(ctx, campaign.TenantID(), key, scope)
	}
	if s.finding == nil {
		return 0, 0, nil
	}
	base := campaignFilterToFindingFilter(campaign.TenantID(), campaign.FindingFilter())
	if !findingFilterHasScope(base) {
		return 0, 0, nil
	}
	base = base.WithDataScope(scope)
	totalFilter := base
	totalFilter.Statuses = nil
	total, err := s.finding.Count(ctx, totalFilter)
	if err != nil {
		return 0, 0, err
	}
	resolvedFilter := base
	resolvedFilter.Statuses = vulnerability.ClosedFindingStatuses()
	resolved, err := s.finding.Count(ctx, resolvedFilter)
	if err != nil {
		return 0, 0, err
	}
	return total, resolved, nil
}

// SetFindingResolver wires the bulk resolver that makes ResolveCampaignFindings
// available (RFC-015 Phase 3). When unset, the resolve action is unavailable.
func (s *RemediationCampaignService) SetFindingResolver(r CampaignFindingResolver) {
	s.resolver = r
}

// SetKeyResolver wires progress + resolution for campaigns scoped to a
// remediation-group key (a solution family). When unset, such campaigns keep
// zero progress and their resolve fails closed (never a tenant-wide resolve).
func (s *RemediationCampaignService) SetKeyResolver(r CampaignKeyResolver) {
	s.keyResolver = r
}

// ResolveCampaignFindings resolves every OPEN finding matching the campaign's
// filter in one action — reusing the finding bulk-status path + abuse guard.
// Defaults to fix_applied ("patched, pending rescan verification"). Returns the
// number of findings transitioned.
func (s *RemediationCampaignService) ResolveCampaignFindings(ctx context.Context, tenantID, campaignID string, in CampaignResolveInput) (int, error) {
	campaign, err := s.GetCampaign(ctx, tenantID, campaignID)
	if err != nil {
		return 0, err
	}

	// A keyed campaign (solution family) MUST resolve through the key path only.
	// Its remediation_key is not expressible as a FindingFilter, so falling
	// through to the generic resolver would map it to a tenant-only filter and
	// close every finding in the tenant. Fail closed if the key path is unwired.
	if key := campaignRemediationKey(campaign.FindingFilter()); key != "" {
		if s.keyResolver == nil {
			return 0, fmt.Errorf("%w: keyed campaign resolve is not configured", shared.ErrValidation)
		}
		n, kerr := s.keyResolver.ResolveGroupByKey(ctx, tenantID, key, in)
		if kerr != nil {
			return 0, kerr
		}
		s.logger.Info("resolved remediation campaign findings by key",
			"tenant", sanitizeLogValue(tenantID), "campaign_id", sanitizeLogValue(campaignID),
			"resolved", n, "status", sanitizeLogValue(in.Status))
		return n, nil
	}

	if s.resolver == nil {
		return 0, fmt.Errorf("%w: campaign resolve is not configured", shared.ErrValidation)
	}
	filter := campaignFilterToFindingFilter(campaign.TenantID(), campaign.FindingFilter())
	// Refuse to resolve an unscoped campaign: an empty filter would map to a
	// tenant-only filter and close every open finding in the tenant.
	if !findingFilterHasScope(filter) {
		return 0, fmt.Errorf("%w: campaign has no scope — refusing tenant-wide resolve", shared.ErrValidation)
	}
	n, err := s.resolver.ResolveOpenByFilter(ctx, tenantID, filter, in)
	if err != nil {
		return 0, err
	}
	s.logger.Info("resolved remediation campaign findings",
		"tenant", sanitizeLogValue(tenantID), "campaign_id", sanitizeLogValue(campaignID),
		"resolved", n, "status", sanitizeLogValue(in.Status))
	return n, nil
}

// sanitizeLogValue strips CR/LF and control characters from a
// user-influenceable value before it is logged, preventing log forging
// (CodeQL go/log-injection). Mirrors the remediation group service's helper —
// the shared logger can emit plain text, where an unescaped newline would let a
// caller forge log lines.
func sanitizeLogValue(s string) string {
	const maxLen = 128
	if len(s) > maxLen {
		s = s[:maxLen]
	}
	// The explicit ReplaceAll pair is the form CodeQL go/log-injection accepts
	// as a barrier; strings.Map below then drops the remaining control chars.
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, "\r", "")
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r < 0x20 {
			return -1
		}
		return r
	}, s)
}

// SetTicketing wires the campaign→Jira-epic integration. Safe to call after
// construction; when either dependency is nil, CreateTicket returns an error
// (the feature degrades off, the rest of the service is unaffected).
func (s *RemediationCampaignService) SetTicketing(ticketRepo remediation.CampaignTicketRepository, epic CampaignEpicCreator) {
	s.ticketRepo = ticketRepo
	s.epicCreator = epic
}

// ErrTicketingNotConfigured is returned by CreateTicket when no epic creator /
// ticket store is wired (e.g. no Jira integration configured).
var ErrTicketingNotConfigured = fmt.Errorf("%w: campaign ticketing is not configured", shared.ErrValidation)

// CreateRemediationCampaignInput holds input for creating a campaign.
type CreateRemediationCampaignInput struct {
	TenantID      string
	Name          string
	Description   string
	Priority      string
	FindingFilter map[string]any
	AssignedTo    string
	AssignedTeam  string
	StartDate     string
	DueDate       string
	Tags          []string
	ActorID       string
}

// CreateCampaign creates a new remediation campaign.
func (s *RemediationCampaignService) CreateCampaign(ctx context.Context, input CreateRemediationCampaignInput, actx auditapp.AuditContext) (*remediation.Campaign, error) {
	tid, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	priority := remediation.CampaignPriority(input.Priority)
	if priority == "" {
		priority = remediation.CampaignPriorityMedium
	}

	campaign, err := remediation.NewCampaign(tid, input.Name, priority)
	if err != nil {
		return nil, err
	}

	campaign.Update(input.Name, input.Description, priority)
	if input.FindingFilter != nil {
		campaign.SetFindingFilter(input.FindingFilter)
	}
	if input.Tags != nil {
		campaign.SetTags(input.Tags)
	}
	if input.ActorID != "" {
		actorID, _ := shared.IDFromString(input.ActorID)
		campaign.SetCreatedBy(actorID)
	}
	if input.AssignedTo != "" || input.AssignedTeam != "" {
		var toPtr, teamPtr *shared.ID
		if input.AssignedTo != "" {
			assignee, aerr := shared.IDFromString(input.AssignedTo)
			if aerr != nil {
				return nil, fmt.Errorf("%w: invalid assigned_to id", shared.ErrValidation)
			}
			if err := s.assertAssignee(ctx, campaign.TenantID(), &assignee); err != nil {
				return nil, err
			}
			toPtr = &assignee
		}
		if input.AssignedTeam != "" {
			team, terr := shared.IDFromString(input.AssignedTeam)
			if terr != nil {
				return nil, fmt.Errorf("%w: invalid assigned_team id", shared.ErrValidation)
			}
			if err := s.assertTeam(ctx, campaign.TenantID(), &team); err != nil {
				return nil, err
			}
			teamPtr = &team
		}
		campaign.SetAssignment(toPtr, teamPtr)
	}
	// Start/due dates: RFC 3339 or a date alone (parseCampaignDate); anything
	// else is refused, never dropped. If no start date is chosen, Activate()
	// auto-stamps it when the task first moves to in-progress.
	if input.StartDate != "" {
		start, derr := parseCampaignDate("start_date", input.StartDate, false)
		if derr != nil {
			return nil, derr
		}
		campaign.SetStartDate(start)
	}
	if input.DueDate != "" {
		due, derr := parseCampaignDate("due_date", input.DueDate, true)
		if derr != nil {
			return nil, derr
		}
		campaign.SetDueDate(due)
	}

	if err := s.repo.Create(ctx, campaign); err != nil {
		return nil, fmt.Errorf("failed to create remediation campaign: %w", err)
	}

	// Seed the initial finding counts so the campaign doesn't read 0/0 until
	// the first reconcile tick. Best-effort: a counting failure must not fail
	// creation — the controller will reconcile it shortly after.
	if changed, err := s.recomputeProgress(ctx, campaign); err != nil {
		s.logger.Warn("initial campaign progress compute failed", "id", campaign.ID().String(), "error", err)
	} else if changed {
		if err := s.repo.Update(ctx, campaign); err != nil {
			s.logger.Warn("failed to persist initial campaign progress", "id", campaign.ID().String(), "error", err)
		}
	}

	s.logAudit(ctx, campaign.TenantID(), actx,
		auditapp.NewSuccessEvent(auditdom.ActionRemediationCampaignCreated, auditdom.ResourceTypeRemediationCampaign, campaign.ID().String()).
			WithResourceName(campaign.Name()).
			WithMessage(fmt.Sprintf("Remediation campaign '%s' created", campaign.Name())).
			WithMetadata("priority", string(campaign.Priority())).
			WithMetadata("status", string(campaign.Status())).
			WithSeverity(auditdom.SeverityLow))

	s.logger.Info("remediation campaign created", "id", campaign.ID().String(), "name", input.Name)
	return campaign, nil
}

// GetCampaign retrieves a campaign, refreshing its finding counts live so the
// detail view always reflects current finding statuses. The recompute is
// best-effort: on any error the last-persisted counts are returned unchanged.
func (s *RemediationCampaignService) GetCampaign(ctx context.Context, tenantID, campaignID string) (*remediation.Campaign, error) {
	tid, _ := shared.IDFromString(tenantID)
	cid, _ := shared.IDFromString(campaignID)
	campaign, err := s.repo.GetByID(ctx, tid, cid)
	if err != nil {
		return nil, err
	}

	if changed, rerr := s.recomputeProgress(ctx, campaign); rerr != nil {
		s.logger.Warn("campaign progress refresh failed", "id", campaignID, "error", rerr)
	} else if changed {
		if uerr := s.repo.Update(ctx, campaign); uerr != nil {
			s.logger.Warn("failed to persist refreshed campaign progress", "id", campaignID, "error", uerr)
		}
	}
	return campaign, nil
}

// parseCampaignDate reads a campaign start or due date: an RFC 3339
// timestamp, or a date alone (YYYY-MM-DD) read in UTC. A date alone is the
// start of that day for a start date and its last second for a due date, so
// a campaign due on a day is overdue only once the day has passed. Anything
// else is a validation error.
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

// optionalCampaignDate is parseCampaignDate where "" clears the date.
func optionalCampaignDate(field, s string, endOfDay bool) (*time.Time, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	return parseCampaignDate(field, s, endOfDay)
}

// ListCampaigns lists campaigns with filtering.
func (s *RemediationCampaignService) ListCampaigns(ctx context.Context, tenantID string, filter remediation.CampaignFilter, page pagination.Pagination) (pagination.Result[*remediation.Campaign], error) {
	tid, _ := shared.IDFromString(tenantID)
	filter.TenantID = &tid
	return s.repo.List(ctx, filter, page)
}

// UpdateRemediationCampaignInput holds fields for partial campaign update.
type UpdateRemediationCampaignInput struct {
	Name        *string
	Description *string
	Priority    *string
	Tags        []string
	// StartDate and DueDate: nil = leave unchanged; ptr to "" = clear;
	// otherwise RFC 3339 or a date alone (parseCampaignDate).
	StartDate *string
	DueDate   *string
	// FindingFilter re-scopes the campaign (e.g. a task's "link to finding").
	// nil = leave the existing scope untouched; non-nil (incl. {}) = replace it.
	FindingFilter map[string]any
	// AssignedTo sets the owner. nil = leave unchanged; ptr to "" = unassign;
	// ptr to a user UUID = assign that user.
	AssignedTo *string
	// AssignedTeam sets the validator (the "who verifies" — segregation from the
	// fixer). Same nil/""/uuid semantics as AssignedTo.
	AssignedTeam *string
}

// UpdateCampaign updates campaign fields (name, description, priority, tags, due_date).
func (s *RemediationCampaignService) UpdateCampaign(ctx context.Context, tenantID, campaignID string, input UpdateRemediationCampaignInput, actx auditapp.AuditContext) (*remediation.Campaign, error) {
	tid, _ := shared.IDFromString(tenantID)
	cid, _ := shared.IDFromString(campaignID)

	campaign, err := s.repo.GetByID(ctx, tid, cid)
	if err != nil {
		return nil, err
	}
	before := snapshotCampaign(campaign)

	if input.Name != nil {
		campaign.SetName(*input.Name)
	}
	if input.Description != nil {
		campaign.SetDescription(*input.Description)
	}
	if input.Priority != nil {
		campaign.SetPriority(remediation.CampaignPriority(*input.Priority))
	}
	if input.Tags != nil {
		campaign.SetTags(input.Tags)
	}
	if input.StartDate != nil {
		start, derr := optionalCampaignDate("start_date", *input.StartDate, false)
		if derr != nil {
			return nil, derr
		}
		campaign.SetStartDate(start)
	}
	if input.DueDate != nil {
		due, derr := optionalCampaignDate("due_date", *input.DueDate, true)
		if derr != nil {
			return nil, derr
		}
		campaign.SetDueDate(due)
	}
	if input.FindingFilter != nil {
		// Re-scoping the campaign (e.g. linking a finding) — apply then recompute
		// the counts immediately so "N findings linked" reflects the new scope
		// without waiting for the reconcile sweep.
		campaign.SetFindingFilter(input.FindingFilter)
		if _, rerr := s.recomputeProgress(ctx, campaign); rerr != nil {
			s.logger.Warn("recompute after re-scope failed", "id", sanitizeLogValue(campaignID), "error", logger.SanitizeError(rerr))
		}
	}
	if input.AssignedTo != nil || input.AssignedTeam != nil {
		toPtr, aerr := resolveAssignee(campaign.AssignedTo(), input.AssignedTo, "assigned_to")
		if aerr != nil {
			return nil, aerr
		}
		// Only a newly named owner is checked; keeping the current one, or
		// unassigning, is not.
		if input.AssignedTo != nil && toPtr != nil {
			if err := s.assertAssignee(ctx, campaign.TenantID(), toPtr); err != nil {
				return nil, err
			}
		}
		teamPtr, terr := resolveAssignee(campaign.AssignedTeam(), input.AssignedTeam, "assigned_team")
		if terr != nil {
			return nil, terr
		}
		// Only a newly named team is checked; keeping it or clearing it is not.
		if input.AssignedTeam != nil && teamPtr != nil {
			if err := s.assertTeam(ctx, campaign.TenantID(), teamPtr); err != nil {
				return nil, err
			}
		}
		campaign.SetAssignment(toPtr, teamPtr)
	}

	if err := s.repo.Update(ctx, campaign); err != nil {
		return nil, fmt.Errorf("failed to update campaign: %w", err)
	}

	if changes := diffCampaign(before, snapshotCampaign(campaign)); !changes.IsEmpty() {
		s.logAudit(ctx, campaign.TenantID(), actx,
			auditapp.NewSuccessEvent(auditdom.ActionRemediationCampaignUpdated, auditdom.ResourceTypeRemediationCampaign, campaign.ID().String()).
				WithResourceName(campaign.Name()).
				WithChanges(changes).
				WithMessage(fmt.Sprintf("Remediation campaign '%s' updated", campaign.Name())).
				WithSeverity(auditdom.SeverityLow))
	}

	s.logger.Info("remediation campaign updated", "id", sanitizeLogValue(campaignID))
	return campaign, nil
}

// UpdateCampaignStatus transitions campaign status.
func (s *RemediationCampaignService) UpdateCampaignStatus(ctx context.Context, tenantID, campaignID, newStatus string, actx auditapp.AuditContext) (*remediation.Campaign, error) {
	tid, _ := shared.IDFromString(tenantID)
	cid, _ := shared.IDFromString(campaignID)

	campaign, err := s.repo.GetByID(ctx, tid, cid)
	if err != nil {
		return nil, err
	}
	fromStatus := campaign.Status()

	// Completing stamps the risk reduction from the finding counts and records
	// how many findings were still open, so both must be live, not whatever
	// the last reconcile persisted. Best-effort: a counting failure keeps the
	// stored counts rather than failing the transition.
	if remediation.CampaignStatus(newStatus) == remediation.CampaignStatusCompleted {
		if _, rerr := s.recomputeProgress(ctx, campaign); rerr != nil {
			s.logger.Warn("recompute before completion failed", "id", sanitizeLogValue(campaignID), "error", logger.SanitizeError(rerr))
		}
	}

	switch remediation.CampaignStatus(newStatus) {
	case remediation.CampaignStatusActive:
		err = campaign.Activate()
	case remediation.CampaignStatusPaused:
		err = campaign.Pause()
	case remediation.CampaignStatusValidating:
		err = campaign.StartValidation()
	case remediation.CampaignStatusCompleted:
		err = campaign.Complete()
		if err == nil {
			s.recordRiskReduction(campaign)
		}
	case remediation.CampaignStatusCanceled:
		err = campaign.Cancel()
	default:
		return nil, fmt.Errorf("%w: invalid status: %s", shared.ErrValidation, newStatus)
	}
	if err != nil {
		return nil, err
	}

	if err := s.repo.Update(ctx, campaign); err != nil {
		return nil, fmt.Errorf("failed to update campaign status: %w", err)
	}

	if campaign.Status() == remediation.CampaignStatusCompleted {
		s.syncEpicOnCompletion(ctx, tid, cid, campaign.Name())
	}

	s.auditStatusChange(ctx, campaign, fromStatus, actx, "manual")

	s.logger.Info("remediation campaign status updated", "id", sanitizeLogValue(campaignID), "status", sanitizeLogValue(newStatus))
	return campaign, nil
}

// syncEpicOnCompletion best-effort transitions a completed campaign's linked
// Jira epic to the done state. No-op when ticketing is unwired or the campaign
// has no linked epic. Errors are logged, never propagated — a Jira hiccup must
// not fail the campaign-completion request. Echo-guarded in TransitionEpic, so
// safe to call from multiple completion paths (manual + auto-complete).
func (s *RemediationCampaignService) syncEpicOnCompletion(ctx context.Context, tenantID, campaignID shared.ID, campaignName string) {
	if s.ticketRepo == nil || s.epicCreator == nil {
		return
	}
	link, err := s.ticketRepo.GetByCampaignAndProvider(ctx, tenantID, campaignID, "jira")
	if err != nil {
		return // not linked (or lookup failed) — nothing to sync
	}
	comment := fmt.Sprintf("OpenCTEM marked remediation campaign %q complete.", campaignName)
	if terr := s.epicCreator.TransitionEpic(ctx, tenantID, link.IssueKey(), epicDoneStatus, comment); terr != nil {
		s.logger.Warn("failed to sync campaign completion to epic",
			"campaign_id", campaignID.String(), "issue_key", link.IssueKey(), "error", terr)
	}
}

// HandleEpicStatusChange is the inbound half of campaign↔epic sync: when a
// Jira webhook reports a campaign's linked epic moved to a done-ish status, the
// campaign is marked completed. No-op when: ticketing is unwired, the status
// isn't a done state, the issue isn't a campaign epic, or the campaign is
// already terminal / not in a completable state. Idempotent and loop-safe — it
// persists via repo.Update directly (not UpdateCampaignStatus), so it does NOT
// re-trigger the outbound epic transition.
func (s *RemediationCampaignService) HandleEpicStatusChange(ctx context.Context, tenantID shared.ID, issueKey, jiraStatus string) error {
	if s.ticketRepo == nil || !isJiraDoneStatus(jiraStatus) {
		return nil
	}

	link, err := s.ticketRepo.GetByIssueKey(ctx, tenantID, "jira", issueKey)
	if err != nil {
		if errors.Is(err, remediation.ErrCampaignTicketNotFound) {
			return nil // not a campaign epic — nothing to do
		}
		return fmt.Errorf("lookup campaign by issue key: %w", err)
	}

	campaign, err := s.repo.GetByID(ctx, tenantID, link.CampaignID())
	if err != nil {
		return fmt.Errorf("load campaign for inbound epic sync: %w", err)
	}
	if campaign.Status() == remediation.CampaignStatusCompleted ||
		campaign.Status() == remediation.CampaignStatusCanceled {
		return nil // already terminal — echo-guard against the outbound loop
	}

	epicFrom := campaign.Status()
	if cerr := campaign.Complete(); cerr != nil {
		// Complete() requires active/validating; a draft/paused campaign can't be
		// auto-completed from an epic move. Log and skip rather than force it.
		s.logger.Warn("inbound epic done but campaign not completable",
			"campaign_id", campaign.ID().String(), "status", campaign.Status(), "error", cerr)
		return nil
	}
	s.recordRiskReduction(campaign)
	if uerr := s.repo.Update(ctx, campaign); uerr != nil {
		return fmt.Errorf("persist campaign completion from epic: %w", uerr)
	}
	s.auditStatusChange(ctx, campaign, epicFrom, auditapp.AuditContext{ActorEmail: campaignAuditSystemActor}, "jira_epic")
	s.logger.Info("remediation campaign completed from inbound jira epic",
		"campaign_id", campaign.ID().String(), "issue_key", issueKey, "jira_status", jiraStatus)
	return nil
}

// isJiraDoneStatus reports whether a Jira status name represents a done state.
func isJiraDoneStatus(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "done", "resolved", "closed", "complete", "completed":
		return true
	}
	return false
}

// DeleteCampaign deletes a campaign.
func (s *RemediationCampaignService) DeleteCampaign(ctx context.Context, tenantID, campaignID string, actx auditapp.AuditContext) error {
	tid, _ := shared.IDFromString(tenantID)
	cid, _ := shared.IDFromString(campaignID)
	// Read first (tenant-scoped) so the audit row can name what was deleted.
	campaign, err := s.repo.GetByID(ctx, tid, cid)
	if err != nil {
		return err
	}
	if err := s.repo.Delete(ctx, tid, cid); err != nil {
		return err
	}
	s.logAudit(ctx, campaign.TenantID(), actx,
		auditapp.NewSuccessEvent(auditdom.ActionRemediationCampaignDeleted, auditdom.ResourceTypeRemediationCampaign, campaign.ID().String()).
			WithResourceName(campaign.Name()).
			WithMessage(fmt.Sprintf("Remediation campaign '%s' deleted", campaign.Name())).
			WithMetadata("status", string(campaign.Status())).
			WithSeverity(auditdom.SeverityMedium))
	return nil
}

// RefreshCampaignProgress recomputes a single campaign's finding counts,
// applies auto-complete when every finding is resolved, and persists the
// result. Returns the up-to-date campaign. This is the on-demand path behind
// the "refresh" endpoint; the controller drives the same logic in bulk.
func (s *RemediationCampaignService) RefreshCampaignProgress(ctx context.Context, tenantID, campaignID string, actx auditapp.AuditContext) (*remediation.Campaign, error) {
	tid, _ := shared.IDFromString(tenantID)
	cid, _ := shared.IDFromString(campaignID)

	campaign, err := s.repo.GetByID(ctx, tid, cid)
	if err != nil {
		return nil, err
	}

	changed, err := s.recomputeProgress(ctx, campaign)
	if err != nil {
		return nil, fmt.Errorf("failed to compute campaign progress: %w", err)
	}
	fromStatus := campaign.Status()
	autoCompleted := false
	if completed, cerr := campaign.TryAutoComplete(); cerr != nil {
		s.logger.Warn("campaign auto-complete failed", "id", campaignID, "error", cerr)
	} else if completed {
		changed = true
		autoCompleted = true
		s.recordRiskReduction(campaign)
	}

	if changed {
		if err := s.repo.Update(ctx, campaign); err != nil {
			return nil, fmt.Errorf("failed to persist campaign progress: %w", err)
		}
	}
	if autoCompleted {
		s.auditStatusChange(ctx, campaign, fromStatus, actx, "auto_complete")
	}
	if campaign.Status() == remediation.CampaignStatusCompleted {
		s.syncEpicOnCompletion(ctx, tid, cid, campaign.Name())
	}
	return campaign, nil
}

// ReconcileProgress refreshes finding counts for every non-terminal campaign
// across all tenants, auto-completing any whose findings are all resolved.
// Returns the number of campaigns whose persisted state changed. Driven by the
// remediation-progress controller. A failure on one campaign is logged and does
// not abort the sweep.
func (s *RemediationCampaignService) ReconcileProgress(ctx context.Context) (int, error) {
	if s.finding == nil {
		return 0, nil // no counter wired — nothing to reconcile
	}

	campaigns, err := s.repo.ListNonTerminal(ctx, 0)
	if err != nil {
		return 0, fmt.Errorf("failed to list campaigns for reconcile: %w", err)
	}

	updated := 0
	disabled := make(map[shared.ID]bool)
	for _, campaign := range campaigns {
		if s.modules != nil {
			off, seen := disabled[campaign.TenantID()]
			if !seen {
				off = s.modules.TenantDisabledModules(ctx, campaign.TenantID().String())[moduledom.ModuleRemediation]
				disabled[campaign.TenantID()] = off
			}
			if off {
				continue
			}
		}
		changed, rerr := s.recomputeProgress(ctx, campaign)
		if rerr != nil {
			s.logger.Warn("campaign progress reconcile failed", "id", campaign.ID().String(), "error", rerr)
			continue
		}
		fromStatus := campaign.Status()
		autoCompleted := false
		if completed, cerr := campaign.TryAutoComplete(); cerr != nil {
			s.logger.Warn("campaign auto-complete failed", "id", campaign.ID().String(), "error", cerr)
		} else if completed {
			changed = true
			autoCompleted = true
			s.recordRiskReduction(campaign)
			s.logger.Info("remediation campaign auto-completed", "id", campaign.ID().String())
		}
		if !changed {
			continue
		}
		if uerr := s.repo.Update(ctx, campaign); uerr != nil {
			s.logger.Warn("failed to persist reconciled campaign", "id", campaign.ID().String(), "error", uerr)
			continue
		}
		if campaign.Status() == remediation.CampaignStatusCompleted {
			s.syncEpicOnCompletion(ctx, campaign.TenantID(), campaign.ID(), campaign.Name())
		}
		if autoCompleted {
			s.auditStatusChange(ctx, campaign, fromStatus, auditapp.AuditContext{ActorEmail: campaignAuditSystemActor}, "auto_complete")
		}
		updated++
	}
	return updated, nil
}

// recomputeProgress evaluates the campaign's finding filter against the
// findings table and updates the in-memory finding/resolved counts. Returns
// true when either count changed (so the caller knows whether to persist).
// No-op (false, nil) when no finding counter is wired.
func (s *RemediationCampaignService) recomputeProgress(ctx context.Context, campaign *remediation.Campaign) (bool, error) {
	// Keyed campaigns (solution families) count from the remediation side-table:
	// the remediation_key can't be expressed as a FindingFilter, so the generic
	// counter would count the wrong (tenant-wide) set.
	if key := campaignRemediationKey(campaign.FindingFilter()); key != "" {
		if s.keyResolver == nil {
			return false, nil
		}
		total, resolved, err := s.keyResolver.CountByKey(ctx, campaign.TenantID(), key, nil)
		if err != nil {
			return false, fmt.Errorf("count campaign findings by key: %w", err)
		}
		prevFindings, prevResolved := campaign.FindingCount(), campaign.ResolvedCount()
		campaign.UpdateProgress(int(total), int(resolved))
		return prevFindings != campaign.FindingCount() || prevResolved != campaign.ResolvedCount(), nil
	}

	if s.finding == nil {
		return false, nil
	}

	base := campaignFilterToFindingFilter(campaign.TenantID(), campaign.FindingFilter())

	// An unscoped campaign ({} filter) maps to a tenant-only filter that matches
	// every finding — so all such campaigns would report the same tenant-wide
	// count. Treat "no scope" as "tracks nothing" until it is given a filter/key.
	if !findingFilterHasScope(base) {
		prevFindings, prevResolved := campaign.FindingCount(), campaign.ResolvedCount()
		campaign.UpdateProgress(0, 0)
		return prevFindings != 0 || prevResolved != 0, nil
	}

	// The denominator must be the WHOLE campaign scope regardless of status, so
	// it stays stable as findings resolve. If the campaign filter pinned a
	// status (e.g. status=open), counting `total` against it while counting
	// `resolved` against the closed statuses made the two sets DISJOINT — as
	// findings moved open→closed, total shrank while resolved grew, so
	// resolved/total exceeded 100% and TryAutoComplete could fire prematurely.
	totalFilter := base
	totalFilter.Statuses = nil
	total, err := s.finding.Count(ctx, totalFilter)
	if err != nil {
		return false, fmt.Errorf("count campaign findings: %w", err)
	}

	resolvedFilter := base
	resolvedFilter.Statuses = vulnerability.ClosedFindingStatuses()
	resolved, err := s.finding.Count(ctx, resolvedFilter)
	if err != nil {
		return false, fmt.Errorf("count resolved campaign findings: %w", err)
	}

	prevFindings, prevResolved := campaign.FindingCount(), campaign.ResolvedCount()
	campaign.UpdateProgress(int(total), int(resolved))
	changed := prevFindings != campaign.FindingCount() || prevResolved != campaign.ResolvedCount()
	return changed, nil
}

// recordRiskReduction stamps a simple resolved/total risk-reduction metric on a
// completed campaign, matching the manual Complete path.
func (s *RemediationCampaignService) recordRiskReduction(campaign *remediation.Campaign) {
	if campaign.FindingCount() <= 0 {
		return
	}
	before := float64(campaign.FindingCount())
	after := float64(campaign.FindingCount() - campaign.ResolvedCount())
	campaign.RecordRiskReduction(before, after)
}

// campaignRemediationKey returns the remediation-group key a campaign is scoped
// to, or "" when the campaign is a plain filter-based campaign. A non-empty key
// means the campaign tracks a solution family and must use the key path for
// both progress and resolution (never the generic finding filter).
func campaignRemediationKey(raw map[string]any) string {
	return firstString(raw, "remediation_key")
}

// campaignFilterToFindingFilter maps a campaign's JSONB finding_filter onto a
// vulnerability.FindingFilter. Supported keys (all optional; unknown keys are
// ignored): severities/severity, cve_ids/cve_id, sources/source, statuses,
// asset_id, tool_name, search. The tenant is always pinned so the count stays
// tenant-isolated.
func campaignFilterToFindingFilter(tenantID shared.ID, raw map[string]any) vulnerability.FindingFilter {
	f := vulnerability.NewFindingFilter().WithTenantID(tenantID)
	if raw == nil {
		return f
	}

	for _, sev := range stringValues(raw, "severities", "severity") {
		if parsed, err := vulnerability.ParseSeverity(sev); err == nil {
			f.Severities = append(f.Severities, parsed)
		}
	}
	for _, src := range stringValues(raw, "sources", "source") {
		if parsed, err := vulnerability.ParseFindingSource(src); err == nil {
			f.Sources = append(f.Sources, parsed)
		}
	}
	for _, st := range stringValues(raw, "statuses", "status") {
		status := vulnerability.FindingStatus(st)
		if status.IsValid() {
			f.Statuses = append(f.Statuses, status)
		}
	}
	if cves := stringValues(raw, "cve_ids", "cve_id"); len(cves) > 0 {
		f.CVEIDs = cves
	}
	// Explicitly linked findings (a remediation task's "link to finding").
	if ids := stringValues(raw, "finding_ids", "finding_id"); len(ids) > 0 {
		f.FindingIDs = ids
	}
	if assetID := firstString(raw, "asset_id"); assetID != "" {
		if id, err := shared.IDFromString(assetID); err == nil {
			f.AssetID = &id
		}
	}
	if tool := firstString(raw, "tool_name"); tool != "" {
		f.ToolName = &tool
	}
	if search := firstString(raw, "search"); search != "" {
		f.Search = &search
	}
	return f
}

// findingFilterHasScope reports whether a campaign's converted filter narrows
// beyond the tenant. An empty campaign filter ({}) maps to a tenant-only filter
// that matches EVERY finding — the cause of the "every campaign shows N findings
// linked" bug, and a resolve-all footgun. An unscoped campaign must therefore
// own nothing (count 0) and must never resolve. Keyed campaigns are handled on a
// separate path and always have scope.
func findingFilterHasScope(f vulnerability.FindingFilter) bool {
	return len(f.Severities) > 0 ||
		len(f.Sources) > 0 ||
		len(f.Statuses) > 0 ||
		len(f.CVEIDs) > 0 ||
		len(f.FindingIDs) > 0 ||
		f.AssetID != nil ||
		f.ToolName != nil ||
		f.Search != nil
}

// stringValues extracts string values for the first present key, accepting
// either a single string or an array (JSONB decodes arrays as []any).
func stringValues(raw map[string]any, keys ...string) []string {
	for _, k := range keys {
		v, ok := raw[k]
		if !ok {
			continue
		}
		switch val := v.(type) {
		case string:
			if val != "" {
				return []string{val}
			}
		case []string:
			return val
		case []any:
			out := make([]string, 0, len(val))
			for _, item := range val {
				if s, ok := item.(string); ok && s != "" {
					out = append(out, s)
				}
			}
			return out
		}
	}
	return nil
}

// firstString returns the value of key as a string, or "" when absent or not a
// string.
func firstString(raw map[string]any, key string) string {
	if v, ok := raw[key].(string); ok {
		return v
	}
	return ""
}

// CampaignTicketInfo describes a campaign's external tracker link.
type CampaignTicketInfo struct {
	CampaignID     string `json:"campaign_id"`
	Provider       string `json:"provider"`
	IssueKey       string `json:"issue_key"`
	IssueURL       string `json:"issue_url"`
	AlreadyExisted bool   `json:"already_existed"`
}

// CreateTicket creates a Jira epic for a campaign and links it. Idempotent: if
// the campaign already has a Jira ticket, the existing link is returned without
// creating a duplicate epic. Requires the ticketing integration to be wired
// (SetTicketing) and the tenant to have a connected Jira integration.
func (s *RemediationCampaignService) CreateTicket(ctx context.Context, tenantID, campaignID, projectKey string) (*CampaignTicketInfo, error) {
	if s.ticketRepo == nil || s.epicCreator == nil {
		return nil, ErrTicketingNotConfigured
	}
	if projectKey == "" {
		return nil, fmt.Errorf("%w: project_key is required", shared.ErrValidation)
	}
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	cid, err := shared.IDFromString(campaignID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid campaign id", shared.ErrValidation)
	}

	// Ensure the campaign exists and is tenant-scoped before touching Jira.
	campaign, err := s.repo.GetByID(ctx, tid, cid)
	if err != nil {
		return nil, err
	}

	const provider = "jira"

	// Idempotency: return the existing link instead of opening a second epic.
	if existing, gerr := s.ticketRepo.GetByCampaignAndProvider(ctx, tid, cid, provider); gerr == nil {
		return &CampaignTicketInfo{
			CampaignID: campaignID, Provider: provider,
			IssueKey: existing.IssueKey(), IssueURL: existing.IssueURL(),
			AlreadyExisted: true,
		}, nil
	} else if !errors.Is(gerr, remediation.ErrCampaignTicketNotFound) {
		return nil, fmt.Errorf("check existing campaign ticket: %w", gerr)
	}

	summary := fmt.Sprintf("[Remediation] %s", campaign.Name())
	key, url, err := s.epicCreator.CreateEpic(ctx, tid, projectKey, summary, buildEpicDescription(campaign),
		[]string{"openctem", "remediation-campaign"})
	if err != nil {
		return nil, fmt.Errorf("create campaign epic: %w", err)
	}

	link, err := remediation.NewCampaignTicket(tid, cid, provider, key, url)
	if err != nil {
		return nil, err
	}
	if err := s.ticketRepo.Create(ctx, link); err != nil {
		// The epic was created in Jira but we failed to persist the link. Surface
		// the error; a retry is idempotent on the Jira side only if the operator
		// re-runs against the same project (a fresh create would duplicate). We
		// log the orphaned key so it can be reconciled manually.
		s.logger.Error("created jira epic but failed to persist campaign link",
			"campaign_id", campaignID, "issue_key", key, "error", err)
		return nil, fmt.Errorf("persist campaign ticket link: %w", err)
	}

	s.logger.Info("campaign jira epic created", "campaign_id", campaignID, "issue_key", key)
	return &CampaignTicketInfo{
		CampaignID: campaignID, Provider: provider,
		IssueKey: key, IssueURL: url,
	}, nil
}

// CampaignTicketLink is the external tracker link surfaced on a campaign in
// read responses (so the UI can show / link to the epic).
type CampaignTicketLink struct {
	Provider string `json:"provider"`
	IssueKey string `json:"issue_key"`
	IssueURL string `json:"issue_url"`
}

// CampaignTicketFor returns the campaign's linked ticket, or nil when there is
// none / ticketing isn't wired. Never errors on "no link" — absence is normal.
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

// CampaignTicketsFor batch-loads ticket links for the given campaigns, keyed by
// campaign id string. Campaigns with no link are absent. Returns an empty map
// when ticketing isn't wired.
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

// buildEpicDescription renders the epic body from a campaign's current state.
func buildEpicDescription(c *remediation.Campaign) string {
	desc := c.Description()
	if desc == "" {
		desc = "(no description)"
	}
	body := fmt.Sprintf("Remediation campaign tracked by OpenCTEM.\n\n%s\n\nProgress: %d/%d findings resolved (%.0f%%).",
		desc, c.ResolvedCount(), c.FindingCount(), c.Progress())
	if due := c.DueDate(); due != nil {
		body += fmt.Sprintf("\nDue: %s", due.Format("2006-01-02"))
	}
	return body
}

// resolveAssignee applies one side of an assignment update. The two sides are
// independently updatable and must not wipe each other, so each starts from the
// current value:
//
//	nil    -> keep current
//	""     -> clear
//	uuid   -> set
//
// Extracted because AssignedTo and AssignedTeam were two copies of this ladder
// inline, which is what pushed UpdateCampaign past the nesting limit.
func resolveAssignee(current *shared.ID, input *string, field string) (*shared.ID, error) {
	if input == nil {
		return current, nil
	}
	if *input == "" {
		return nil, nil
	}
	id, err := shared.IDFromString(*input)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid %s id", shared.ErrValidation, field)
	}
	return &id, nil
}

// ============================================
// AUDIT
// ============================================

// logAudit writes one audit event, best-effort: an audit failure is logged and
// never fails the change it records. The tenant is always the campaign's own
// (it was loaded tenant-scoped), never a value from the request body.
func (s *RemediationCampaignService) logAudit(ctx context.Context, tenantID shared.ID, actx auditapp.AuditContext, ev auditapp.AuditEvent) {
	if s.audit == nil {
		return
	}
	actx.TenantID = tenantID.String()
	if err := s.audit.LogEvent(ctx, actx, ev); err != nil {
		s.logger.Warn("failed to write remediation campaign audit event", "action", string(ev.Action), "error", logger.SanitizeError(err))
	}
}

// auditStatusChange records a lifecycle transition. trigger says what moved
// it: "manual" (PATCH /status), "auto_complete" (every finding closed) or
// "jira_epic" (the linked epic was closed). Completing while findings are
// still open records how many, so the trail shows a campaign closed early.
func (s *RemediationCampaignService) auditStatusChange(ctx context.Context, campaign *remediation.Campaign, from remediation.CampaignStatus, actx auditapp.AuditContext, trigger string) {
	to := campaign.Status()
	ev := auditapp.NewSuccessEvent(auditdom.ActionRemediationCampaignStatusChanged, auditdom.ResourceTypeRemediationCampaign, campaign.ID().String()).
		WithResourceName(campaign.Name()).
		WithChanges(auditdom.NewChanges().Set("status", string(from), string(to))).
		WithMessage(fmt.Sprintf("Remediation campaign '%s' status changed from %s to %s", campaign.Name(), from, to)).
		WithMetadata("trigger", trigger).
		WithMetadata("finding_count", campaign.FindingCount()).
		WithMetadata("resolved_count", campaign.ResolvedCount()).
		WithSeverity(auditdom.SeverityLow)
	switch to {
	case remediation.CampaignStatusCompleted:
		open := max(campaign.FindingCount()-campaign.ResolvedCount(), 0)
		ev = ev.WithMetadata("open_findings", open)
		if open > 0 {
			// Closing a campaign with work left is worth a reviewer's look.
			ev = ev.WithSeverity(auditdom.SeverityMedium)
		}
	case remediation.CampaignStatusCanceled:
		ev = ev.WithSeverity(auditdom.SeverityMedium)
	}
	s.logAudit(ctx, campaign.TenantID(), actx, ev)
}

// campaignSnapshot is the editable state of a campaign, compared before and
// after an update so the audit row records only what changed.
type campaignSnapshot struct {
	name, description, priority string
	assignedTo, assignedTeam    string
	startDate, dueDate          string
	tags                        []string
	findingFilter               string
}

func snapshotCampaign(c *remediation.Campaign) campaignSnapshot {
	return campaignSnapshot{
		name:          c.Name(),
		description:   c.Description(),
		priority:      string(c.Priority()),
		assignedTo:    idString(c.AssignedTo()),
		assignedTeam:  idString(c.AssignedTeam()),
		startDate:     dateString(c.StartDate()),
		dueDate:       dateString(c.DueDate()),
		tags:          append([]string(nil), c.Tags()...),
		findingFilter: filterString(c.FindingFilter()),
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
	setIf("finding_filter", before.findingFilter, after.findingFilter)
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

// filterString renders a finding filter deterministically (JSON sorts map
// keys) so two equal filters compare equal.
func filterString(f map[string]any) string {
	if len(f) == 0 {
		return ""
	}
	b, err := json.Marshal(f)
	if err != nil {
		return fmt.Sprint(f)
	}
	return string(b)
}
