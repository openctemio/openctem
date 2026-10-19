package jobs

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/internal/app/aitriage"
)

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
var _ aitriage.AITriageJobEnqueuer = (*AITriageEnqueuerAdapter)(nil)
