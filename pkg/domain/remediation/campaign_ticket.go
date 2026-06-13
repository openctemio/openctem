package remediation

import (
	"context"
	"fmt"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// CampaignTicket links a remediation campaign to an external tracker issue
// (currently a Jira epic). At most one ticket per (campaign, provider).
type CampaignTicket struct {
	id         shared.ID
	tenantID   shared.ID
	campaignID shared.ID
	provider   string
	issueKey   string
	issueURL   string
	createdAt  time.Time
	updatedAt  time.Time
}

// NewCampaignTicket creates a new campaign↔issue link.
func NewCampaignTicket(tenantID, campaignID shared.ID, provider, issueKey, issueURL string) (*CampaignTicket, error) {
	if provider == "" {
		provider = "jira"
	}
	if issueKey == "" || issueURL == "" {
		return nil, fmt.Errorf("%w: issue key and url are required", shared.ErrValidation)
	}
	now := time.Now()
	return &CampaignTicket{
		id:         shared.NewID(),
		tenantID:   tenantID,
		campaignID: campaignID,
		provider:   provider,
		issueKey:   issueKey,
		issueURL:   issueURL,
		createdAt:  now,
		updatedAt:  now,
	}, nil
}

// ReconstituteCampaignTicket rebuilds a CampaignTicket from persisted data.
func ReconstituteCampaignTicket(id, tenantID, campaignID shared.ID, provider, issueKey, issueURL string, createdAt, updatedAt time.Time) *CampaignTicket {
	return &CampaignTicket{
		id: id, tenantID: tenantID, campaignID: campaignID,
		provider: provider, issueKey: issueKey, issueURL: issueURL,
		createdAt: createdAt, updatedAt: updatedAt,
	}
}

func (t *CampaignTicket) ID() shared.ID         { return t.id }
func (t *CampaignTicket) TenantID() shared.ID   { return t.tenantID }
func (t *CampaignTicket) CampaignID() shared.ID { return t.campaignID }
func (t *CampaignTicket) Provider() string      { return t.provider }
func (t *CampaignTicket) IssueKey() string      { return t.issueKey }
func (t *CampaignTicket) IssueURL() string      { return t.issueURL }
func (t *CampaignTicket) CreatedAt() time.Time  { return t.createdAt }
func (t *CampaignTicket) UpdatedAt() time.Time  { return t.updatedAt }

// ErrCampaignTicketNotFound is returned when no ticket links a campaign.
var ErrCampaignTicketNotFound = fmt.Errorf("%w: campaign ticket not found", shared.ErrNotFound)

// CampaignTicketRepository persists campaign↔issue links.
type CampaignTicketRepository interface {
	Create(ctx context.Context, t *CampaignTicket) error
	// GetByCampaignAndProvider returns the link for a campaign+provider, or
	// ErrCampaignTicketNotFound.
	GetByCampaignAndProvider(ctx context.Context, tenantID, campaignID shared.ID, provider string) (*CampaignTicket, error)
}
