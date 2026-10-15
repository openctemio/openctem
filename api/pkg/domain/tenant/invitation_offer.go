package tenant

import (
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// InvitationOffer is a pending invitation as the invitee's onboarding shows
// it: the organization's name, the role offered and who invited. It carries
// no token (docs/rfcs/RFC-104).
type InvitationOffer struct {
	InvitationID shared.ID
	TenantID     shared.ID
	TenantName   string
	Role         string
	InviterName  string
	ExpiresAt    time.Time
}
