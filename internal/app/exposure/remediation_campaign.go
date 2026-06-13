package exposure

import (
	"context"
	"fmt"
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

// RemediationCampaignService manages remediation campaigns.
type RemediationCampaignService struct {
	repo    remediation.CampaignRepository
	finding FindingCounter
	logger  *logger.Logger
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

	s.logger.Info("remediation campaign status updated", "id", campaignID, "status", newStatus)
	return campaign, nil
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
