package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/internal/app/tenant"
	"github.com/openctemio/openctem/api/pkg/crypto"
	"github.com/openctemio/openctem/api/pkg/domain/durablejob"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Handlers of the durable jobs (api/docs/architecture/durable-jobs.md). The
// controller in internal/infra/controller runs them; a handler error that
// reports Permanent() true is not retried.

// StatusSyncer pushes a finding's current status to its linked ticket. It is
// ticketing.JiraSyncService / GitHubTicketService.SyncFindingStatus, which
// resolve the tenant's integration, no-op when the tenant did not opt in or
// the finding is not linked, and are idempotent (they push the status the
// finding has now).
type StatusSyncer interface {
	SyncFindingStatus(ctx context.Context, tenantID, findingID shared.ID) error
}

// StatusSyncHandler runs a jira_status_sync or github_status_sync job.
func StatusSyncHandler(syncer StatusSyncer) func(context.Context, durablejob.Claimed) error {
	return func(ctx context.Context, j durablejob.Claimed) error {
		return syncer.SyncFindingStatus(ctx, j.TenantID, j.SubjectID)
	}
}

// invitationEmailPayload is the sealed payload of an invitation_email job.
type invitationEmailPayload struct {
	RecipientEmail string    `json:"recipient_email"`
	InviterName    string    `json:"inviter_name"`
	TeamName       string    `json:"team_name"`
	Token          string    `json:"token"`
	ExpiresAt      time.Time `json:"expires_at"`
}

// permanentError is an error a retry cannot fix.
type permanentError struct{ err error }

func (e permanentError) Error() string   { return e.err.Error() }
func (e permanentError) Unwrap() error   { return e.err }
func (e permanentError) Permanent() bool { return true }

// InvitationEmailJobs builds invitation e-mail jobs (tenant.EmailJobEnqueuer).
// The payload carries the raw link token, which the database otherwise only
// holds as a hash, so it is sealed with the application encryption key.
type InvitationEmailJobs struct {
	enc crypto.Encryptor
}

// NewInvitationEmailJobs creates the builder.
func NewInvitationEmailJobs(enc crypto.Encryptor) *InvitationEmailJobs {
	return &InvitationEmailJobs{enc: enc}
}

var _ tenant.EmailJobEnqueuer = (*InvitationEmailJobs)(nil)

// TeamInvitationJob seals the e-mail data into a job.
func (b *InvitationEmailJobs) TeamInvitationJob(p tenant.TeamInvitationJobPayload) (durablejob.Job, error) {
	tenantID, err := shared.IDFromString(p.TenantID)
	if err != nil {
		return durablejob.Job{}, fmt.Errorf("invitation email job: tenant id: %w", err)
	}
	invitationID, err := shared.IDFromString(p.InvitationID)
	if err != nil {
		return durablejob.Job{}, fmt.Errorf("invitation email job: invitation id: %w", err)
	}
	if b.enc == nil {
		return durablejob.Job{}, errors.New("invitation email job: no encryptor")
	}
	data, err := json.Marshal(invitationEmailPayload{
		RecipientEmail: p.RecipientEmail, InviterName: p.InviterName, TeamName: p.TeamName,
		Token: p.Token, ExpiresAt: time.Now().Add(p.ExpiresIn).UTC(),
	})
	if err != nil {
		return durablejob.Job{}, fmt.Errorf("invitation email job: %w", err)
	}
	sealed, err := b.enc.EncryptString(string(data))
	if err != nil {
		return durablejob.Job{}, fmt.Errorf("invitation email job: seal: %w", err)
	}
	return durablejob.Job{Kind: durablejob.KindInvitationEmail, TenantID: tenantID, SubjectID: invitationID, Payload: sealed}, nil
}

// InvitationSender sends the invitation e-mail (*auth.EmailService).
type InvitationSender interface {
	SendTeamInvitationEmail(ctx context.Context, recipientEmail, inviterName, teamName, token string, expiresIn time.Duration, tenantID ...string) error
}

// InvitationEmailHandler runs an invitation_email job: it opens the sealed
// payload and sends the e-mail through the tenant's SMTP (or the platform's).
// An expired invitation or an unreadable payload is not retried.
func InvitationEmailHandler(sender InvitationSender, enc crypto.Encryptor) func(context.Context, durablejob.Claimed) error {
	return func(ctx context.Context, j durablejob.Claimed) error {
		plain, err := enc.DecryptString(j.Payload)
		if err != nil {
			return permanentError{fmt.Errorf("open invitation email payload: %w", err)}
		}
		var p invitationEmailPayload
		if err := json.Unmarshal([]byte(plain), &p); err != nil {
			return permanentError{fmt.Errorf("decode invitation email payload: %w", err)}
		}
		left := time.Until(p.ExpiresAt)
		if left <= 0 {
			return permanentError{errors.New("invitation expired before its e-mail was sent")}
		}
		return sender.SendTeamInvitationEmail(ctx, p.RecipientEmail, p.InviterName, p.TeamName, p.Token, left, j.TenantID.String())
	}
}
