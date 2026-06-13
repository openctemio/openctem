package exposure

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/api/pkg/domain/remediation"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// FindingCounter is the narrow slice of the finding repository the campaign
// service needs to compute progress: how many findings match a filter.
// Satisfied by *postgres.FindingRepository.
type FindingCounter interface {
	Count(ctx context.Context, filter vulnerability.FindingFilter) (int64, error)
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

// RemediationCampaignService manages remediation campaigns.
type RemediationCampaignService struct {
	repo        remediation.CampaignRepository
	finding     FindingCounter                       // nil → progress stays zero
	ticketRepo  remediation.CampaignTicketRepository // nil → ticketing disabled
	epicCreator CampaignEpicCreator                  // nil → ticketing disabled
	logger      *logger.Logger
}

// NewRemediationCampaignService creates a new service.
func NewRemediationCampaignService(repo remediation.CampaignRepository, log *logger.Logger) *RemediationCampaignService {
	return &RemediationCampaignService{repo: repo, logger: log}
}

// SetFindingCounter wires the finding counter used to compute campaign
// progress. When unset, progress stays at zero (the service still functions as
// plain CRUD). Kept as a setter so the constructor signature is stable and to
// avoid an import cycle at the composition root.
func (s *RemediationCampaignService) SetFindingCounter(c FindingCounter) {
	s.finding = c
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
	StartDate     string
	DueDate       string
	Tags          []string
	ActorID       string
}

// CreateCampaign creates a new remediation campaign.
func (s *RemediationCampaignService) CreateCampaign(ctx context.Context, input CreateRemediationCampaignInput) (*remediation.Campaign, error) {
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
	if input.AssignedTo != "" {
		assignee, aerr := shared.IDFromString(input.AssignedTo)
		if aerr != nil {
			return nil, fmt.Errorf("%w: invalid assigned_to id", shared.ErrValidation)
		}
		campaign.SetAssignment(&assignee, nil)
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
	DueDate     *time.Time
}

// UpdateCampaign updates campaign fields (name, description, priority, tags, due_date).
func (s *RemediationCampaignService) UpdateCampaign(ctx context.Context, tenantID, campaignID string, input UpdateRemediationCampaignInput) (*remediation.Campaign, error) {
	tid, _ := shared.IDFromString(tenantID)
	cid, _ := shared.IDFromString(campaignID)

	campaign, err := s.repo.GetByID(ctx, tid, cid)
	if err != nil {
		return nil, err
	}

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
	if input.DueDate != nil {
		campaign.SetDueDate(input.DueDate)
	}

	if err := s.repo.Update(ctx, campaign); err != nil {
		return nil, fmt.Errorf("failed to update campaign: %w", err)
	}

	s.logger.Info("remediation campaign updated", "id", campaignID)
	return campaign, nil
}

// UpdateCampaignStatus transitions campaign status.
func (s *RemediationCampaignService) UpdateCampaignStatus(ctx context.Context, tenantID, campaignID, newStatus string) (*remediation.Campaign, error) {
	tid, _ := shared.IDFromString(tenantID)
	cid, _ := shared.IDFromString(campaignID)

	campaign, err := s.repo.GetByID(ctx, tid, cid)
	if err != nil {
		return nil, err
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

	s.logger.Info("remediation campaign status updated", "id", campaignID, "status", newStatus)
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
func (s *RemediationCampaignService) DeleteCampaign(ctx context.Context, tenantID, campaignID string) error {
	tid, _ := shared.IDFromString(tenantID)
	cid, _ := shared.IDFromString(campaignID)
	return s.repo.Delete(ctx, tid, cid)
}

// RefreshCampaignProgress recomputes a single campaign's finding counts,
// applies auto-complete when every finding is resolved, and persists the
// result. Returns the up-to-date campaign. This is the on-demand path behind
// the "refresh" endpoint; the controller drives the same logic in bulk.
func (s *RemediationCampaignService) RefreshCampaignProgress(ctx context.Context, tenantID, campaignID string) (*remediation.Campaign, error) {
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
	if completed, cerr := campaign.TryAutoComplete(); cerr != nil {
		s.logger.Warn("campaign auto-complete failed", "id", campaignID, "error", cerr)
	} else if completed {
		changed = true
		s.recordRiskReduction(campaign)
	}

	if changed {
		if err := s.repo.Update(ctx, campaign); err != nil {
			return nil, fmt.Errorf("failed to persist campaign progress: %w", err)
		}
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
	for _, campaign := range campaigns {
		changed, rerr := s.recomputeProgress(ctx, campaign)
		if rerr != nil {
			s.logger.Warn("campaign progress reconcile failed", "id", campaign.ID().String(), "error", rerr)
			continue
		}
		if completed, cerr := campaign.TryAutoComplete(); cerr != nil {
			s.logger.Warn("campaign auto-complete failed", "id", campaign.ID().String(), "error", cerr)
		} else if completed {
			changed = true
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
		updated++
	}
	return updated, nil
}

// recomputeProgress evaluates the campaign's finding filter against the
// findings table and updates the in-memory finding/resolved counts. Returns
// true when either count changed (so the caller knows whether to persist).
// No-op (false, nil) when no finding counter is wired.
func (s *RemediationCampaignService) recomputeProgress(ctx context.Context, campaign *remediation.Campaign) (bool, error) {
	if s.finding == nil {
		return false, nil
	}

	base := campaignFilterToFindingFilter(campaign.TenantID(), campaign.FindingFilter())

	total, err := s.finding.Count(ctx, base)
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
