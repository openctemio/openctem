package mcpoauth

import (
	"context"
	"errors"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ConfirmationTTL is how long a person has to confirm a write action.
const ConfirmationTTL = 5 * time.Minute

// ConfirmationStatus is the state of a write-action confirmation.
type ConfirmationStatus string

const (
	ConfirmationPending  ConfirmationStatus = "pending"
	ConfirmationApproved ConfirmationStatus = "approved"
	ConfirmationDenied   ConfirmationStatus = "denied"
	ConfirmationUsed     ConfirmationStatus = "used"
)

// Confirmation is a write action waiting for (or given) the person's
// approval in the web UI (RFC-062 §10).
type Confirmation struct {
	ID         shared.ID
	TenantID   shared.ID
	GrantID    shared.ID
	UserID     shared.ID
	Tool       string
	ArgsDigest string
	Summary    string
	Status     ConfirmationStatus
	CreatedAt  time.Time
	ExpiresAt  time.Time
	// ClientName is the application that asked (read only).
	ClientName string
}

// ErrConfirmationRequired means the action has no usable confirmation:
// none given, not approved yet, denied, expired, used, or for another
// connection, tool or set of arguments.
var ErrConfirmationRequired = errors.New("confirmation required")

// ConfirmationRepository stores confirmations.
type ConfirmationRepository interface {
	CreateConfirmation(ctx context.Context, c *Confirmation) error
	// GetConfirmation returns the confirmation of the user in the tenant.
	GetConfirmation(ctx context.Context, tenantID, userID, id shared.ID) (*Confirmation, error)
	// DecideConfirmation moves a pending, unexpired confirmation of the user
	// to approved or denied.
	DecideConfirmation(ctx context.Context, tenantID, userID, id shared.ID, approve bool, now time.Time) error
	// UseConfirmation atomically moves an approved, unexpired confirmation
	// matching grant, tool and digest to used; anything else is
	// ErrConfirmationRequired.
	UseConfirmation(ctx context.Context, tenantID, grantID, id shared.ID, tool, digest string, now time.Time) error
}
