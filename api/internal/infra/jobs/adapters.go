package jobs

import (
	"context"
	"time"

	"github.com/openctemio/api/internal/app"
)

// EmailEnqueuerAdapter wraps the job Client to implement app.EmailJobEnqueuer.
type EmailEnqueuerAdapter struct {
	client *Client
}

// NewEmailEnqueuerAdapter creates a new adapter.
func NewEmailEnqueuerAdapter(client *Client) *EmailEnqueuerAdapter {
	return &EmailEnqueuerAdapter{client: client}
}

// EnqueueTeamInvitation converts app payload to job payload and enqueues.
func (a *EmailEnqueuerAdapter) EnqueueTeamInvitation(ctx context.Context, payload app.TeamInvitationJobPayload) error {
	jobPayload := TeamInvitationPayload{
		RecipientEmail: payload.RecipientEmail,
		InviterName:    payload.InviterName,
		TeamName:       payload.TeamName,
		Token:          payload.Token,
		ExpiresIn:      payload.ExpiresIn,
		InvitationID:   payload.InvitationID,
		TenantID:       payload.TenantID,
	}
	return a.client.EnqueueTeamInvitation(ctx, jobPayload)
}

// UserInfoAdapter provides user information from the user service.
type UserInfoAdapter struct {
	getUserName func(ctx context.Context, userID string) (string, error)
}

// NewUserInfoAdapter creates a new user info adapter.
func NewUserInfoAdapter(getUserName func(ctx context.Context, userID string) (string, error)) *UserInfoAdapter {
	return &UserInfoAdapter{getUserName: getUserName}
}

// GetUserNameByID returns the display name for a user.
func (a *UserInfoAdapter) GetUserNameByID(ctx context.Context, id interface{ String() string }) (string, error) {
	return a.getUserName(ctx, id.String())
}

// NoOpEmailEnqueuer is a no-op implementation that just logs.
type NoOpEmailEnqueuer struct{}

// EnqueueTeamInvitation logs but doesn't actually enqueue.
func (n *NoOpEmailEnqueuer) EnqueueTeamInvitation(_ context.Context, payload app.TeamInvitationJobPayload) error {
	// No-op: email jobs are disabled
	_ = payload
	return nil
}

// Ensure adapters implement the interfaces
var _ app.EmailJobEnqueuer = (*EmailEnqueuerAdapter)(nil)
var _ app.EmailJobEnqueuer = (*NoOpEmailEnqueuer)(nil)

// DefaultExpiresIn is the default expiration time for invitations.
const DefaultExpiresIn = 7 * 24 * time.Hour

// =============================================================================
// AI Triage Adapter
// =============================================================================

// AITriageEnqueuerAdapter wraps the job Client to implement app.AITriageJobEnqueuer.
type AITriageEnqueuerAdapter struct {
	client *Client
}

// NewAITriageEnqueuerAdapter creates a new AI triage enqueuer adapter.
func NewAITriageEnqueuerAdapter(client *Client) *AITriageEnqueuerAdapter {
	return &AITriageEnqueuerAdapter{client: client}
}

// EnqueueAITriage converts app parameters to job payload and enqueues.
func (a *AITriageEnqueuerAdapter) EnqueueAITriage(ctx context.Context, resultID, tenantID, findingID string, delay time.Duration) error {
	payload := AITriagePayload{
		ResultID:  resultID,
		TenantID:  tenantID,
		FindingID: findingID,
	}
	return a.client.EnqueueAITriage(ctx, payload, delay)
}

// Ensure adapter implements the interface
var _ app.AITriageJobEnqueuer = (*AITriageEnqueuerAdapter)(nil)
