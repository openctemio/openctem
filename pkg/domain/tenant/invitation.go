package tenant

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

const (
	// DefaultInvitationExpiry is the default expiry duration for invitations.
	DefaultInvitationExpiry = 7 * 24 * time.Hour // 7 days
)

// Invitation represents an invitation to join a tenant.
type Invitation struct {
	id         shared.ID
	tenantID   shared.ID
	email      string
	role       Role
	roleIDs    []string // RBAC role IDs to assign when user accepts
	token      string
	invitedBy  shared.ID // Local user ID (from users table)
	expiresAt  time.Time
	acceptedAt *time.Time
	createdAt  time.Time
}

// NewInvitation creates a new Invitation.
// invitedBy is the local user ID (from users table) of the person sending the invitation.
// roleIDs are the RBAC role IDs to assign when user accepts the invitation.
func NewInvitation(tenantID shared.ID, email string, role Role, invitedBy shared.ID, roleIDs []string) (*Invitation, error) {
	if tenantID.IsZero() {
		return nil, fmt.Errorf("%w: tenantID is required", shared.ErrValidation)
	}
	if email == "" {
		return nil, fmt.Errorf("%w: email is required", shared.ErrValidation)
	}
	if !role.IsValid() {
		return nil, fmt.Errorf("%w: invalid role", shared.ErrValidation)
	}
	if role == RoleOwner {
		return nil, fmt.Errorf("%w: cannot invite as owner", shared.ErrValidation)
	}
	if invitedBy.IsZero() {
		return nil, fmt.Errorf("%w: invitedBy is required", shared.ErrValidation)
	}
	if len(roleIDs) == 0 {
		return nil, fmt.Errorf("%w: at least one role is required", shared.ErrValidation)
	}

	token, err := generateToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}

	now := time.Now().UTC()
	return &Invitation{
		id:        shared.NewID(),
		tenantID:  tenantID,
		email:     email,
		role:      role,
		roleIDs:   roleIDs,
		token:     token,
		invitedBy: invitedBy,
		expiresAt: now.Add(DefaultInvitationExpiry),
		createdAt: now,
	}, nil
}

// ReconstituteInvitation recreates an Invitation from persistence.
func ReconstituteInvitation(
	id shared.ID,
	tenantID shared.ID,
	email string,
	role Role,
	roleIDs []string,
	token string,
	invitedBy shared.ID,
	expiresAt time.Time,
	acceptedAt *time.Time,
	createdAt time.Time,
) *Invitation {
	return &Invitation{
		id:         id,
		tenantID:   tenantID,
		email:      email,
		role:       role,
		roleIDs:    roleIDs,
		token:      token,
		invitedBy:  invitedBy,
		expiresAt:  expiresAt,
		acceptedAt: acceptedAt,
		createdAt:  createdAt,
	}
}

// ID returns the invitation ID.
func (i *Invitation) ID() shared.ID {
	return i.id
}

// TenantID returns the tenant ID.
func (i *Invitation) TenantID() shared.ID {
	return i.tenantID
}

// Email returns the invitee's email.
func (i *Invitation) Email() string {
	return i.email
}

// Role returns the membership role to be assigned.
func (i *Invitation) Role() Role {
	return i.role
}

// RoleIDs returns the RBAC role IDs to be assigned when user accepts.
func (i *Invitation) RoleIDs() []string {
	return i.roleIDs
}

// Token returns the invitation token.
//
// Depending on lifecycle stage this is either the raw token (freshly created
// or freshly rotated in memory, before it is hashed for persistence) or the
// stored hash (when reconstituted from the database). Callers that need the
// value the user receives (email/link) must use the raw token captured before
// SetToken hashes it for storage — see TenantService.CreateInvitation.
func (i *Invitation) Token() string {
	return i.token
}

// SetToken overwrites the in-memory token. The service layer uses this to
// store a hash of the token at rest (crypto.HashToken) instead of the raw
// value, mirroring the hash-at-rest pattern used for refresh/reset tokens.
func (i *Invitation) SetToken(token string) {
	i.token = token
}

// RotateToken generates a fresh raw invitation token, sets it in memory, and
// returns the raw value. The caller is responsible for persisting the hashed
// form (SetToken(crypto.HashToken(raw))) and delivering the raw value to the
// invitee. Used by resend so a lost invite can be re-issued even though only
// the hash is stored at rest.
func (i *Invitation) RotateToken() (string, error) {
	token, err := generateToken()
	if err != nil {
		return "", fmt.Errorf("failed to generate token: %w", err)
	}
	i.token = token
	return token, nil
}

// InvitedBy returns the local user ID of who sent the invitation.
func (i *Invitation) InvitedBy() shared.ID {
	return i.invitedBy
}

// ExpiresAt returns when the invitation expires.
func (i *Invitation) ExpiresAt() time.Time {
	return i.expiresAt
}

// AcceptedAt returns when the invitation was accepted (nil if not accepted).
func (i *Invitation) AcceptedAt() *time.Time {
	return i.acceptedAt
}

// CreatedAt returns when the invitation was created.
func (i *Invitation) CreatedAt() time.Time {
	return i.createdAt
}

// IsExpired checks if the invitation has expired.
func (i *Invitation) IsExpired() bool {
	return time.Now().UTC().After(i.expiresAt)
}

// IsAccepted checks if the invitation has been accepted.
func (i *Invitation) IsAccepted() bool {
	return i.acceptedAt != nil
}

// IsPending checks if the invitation is pending (not expired and not accepted).
func (i *Invitation) IsPending() bool {
	return !i.IsExpired() && !i.IsAccepted()
}

// Accept marks the invitation as accepted.
func (i *Invitation) Accept() error {
	if i.IsExpired() {
		return fmt.Errorf("%w: invitation has expired", shared.ErrValidation)
	}
	if i.IsAccepted() {
		return fmt.Errorf("%w: invitation already accepted", shared.ErrValidation)
	}
	now := time.Now().UTC()
	i.acceptedAt = &now
	return nil
}

// generateToken generates a secure random token.
func generateToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}
