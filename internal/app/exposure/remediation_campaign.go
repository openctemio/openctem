package exposure

import (
	"context"
	"fmt"
	"time"

	"github.com/openctemio/api/pkg/domain/remediation"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// RemediationCampaignService manages remediation campaigns.
type RemediationCampaignService struct {
	repo   remediation.CampaignRepository
	logger *logger.Logger
}

// NewRemediationCampaignService creates a new service.
func NewRemediationCampaignService(repo remediation.CampaignRepository, log *logger.Logger) *RemediationCampaignService {
	return &RemediationCampaignService{repo: repo, logger: log}
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
		assignee, _ := shared.IDFromString(input.AssignedTo)
		campaign.SetAssignment(&assignee, nil)
	}

	if err := s.repo.Create(ctx, campaign); err != nil {
		return nil, fmt.Errorf("failed to create remediation campaign: %w", err)
	}

	s.logger.Info("remediation campaign created", "id", campaign.ID().String(), "name", input.Name)
	return campaign, nil
}

// GetCampaign retrieves a campaign.
func (s *RemediationCampaignService) GetCampaign(ctx context.Context, tenantID, campaignID string) (*remediation.Campaign, error) {
	tid, _ := shared.IDFromString(tenantID)
	cid, _ := shared.IDFromString(campaignID)
	return s.repo.GetByID(ctx, tid, cid)
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
		// Record risk reduction: resolved / total as a simple risk metric
		if err == nil && campaign.FindingCount() > 0 {
			before := float64(campaign.FindingCount())
			after := float64(campaign.FindingCount() - campaign.ResolvedCount())
			campaign.RecordRiskReduction(before, after)
		}
	case remediation.CampaignStatusCanceled:
		campaign.Cancel()
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
