// Package useridentity holds the federated identities bound to a user account:
// the identity provider's (issuer, subject) pair. Federated logins find the
// account by this pair first, so the email address is only an attribute that
// the identity provider may change.
package useridentity

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

var (
	// ErrNotFound is returned when no account is bound to the identity.
	ErrNotFound = fmt.Errorf("%w: federated identity not found", shared.ErrNotFound)
	// ErrConflict is returned when the identity is already bound to another
	// account, or the account already has a different subject from the same
	// issuer.
	ErrConflict = fmt.Errorf("%w: federated identity already bound", shared.ErrConflict)
	// ErrInvalid is returned for an empty issuer or subject.
	ErrInvalid = fmt.Errorf("%w: federated identity needs an issuer and a subject", shared.ErrValidation)
)

// Key names one identity at one identity provider.
//
// ScopeTenantID is nil when only the issuer can assert the identity (an OIDC
// id_token verified against the issuer's published keys, or a social
// provider's API), so the pair names the same person platform-wide. It is set
// for SAML: the organization configures its IdP's signing certificate, so the
// pair is trusted only inside that organization.
type Key struct {
	Issuer        string
	Subject       string
	ScopeTenantID *shared.ID
}

// Valid reports whether the key has both an issuer and a subject.
func (k Key) Valid() bool {
	return strings.TrimSpace(k.Issuer) != "" && strings.TrimSpace(k.Subject) != ""
}

// SameIssuer reports whether other is from the same issuer in the same scope.
func (k Key) SameIssuer(other Key) bool {
	return k.Issuer == other.Issuer && sameScope(k.ScopeTenantID, other.ScopeTenantID)
}

func sameScope(a, b *shared.ID) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

// Identity is one (issuer, subject) bound to an account.
type Identity struct {
	ID         shared.ID
	UserID     shared.ID
	Key        Key
	CreatedAt  time.Time
	LastUsedAt *time.Time
}

// New builds an identity for userID.
func New(userID shared.ID, key Key) (*Identity, error) {
	if !key.Valid() {
		return nil, ErrInvalid
	}
	return &Identity{ID: shared.NewID(), UserID: userID, Key: key, CreatedAt: time.Now().UTC()}, nil
}

// Repository stores federated identities. The table is global (users are
// global); a SAML identity carries the organization it is trusted in.
type Repository interface {
	// GetByKey returns the identity, or ErrNotFound.
	GetByKey(ctx context.Context, key Key) (*Identity, error)
	// ListByUser returns every identity bound to the account.
	ListByUser(ctx context.Context, userID shared.ID) ([]*Identity, error)
	// Create binds the identity; ErrConflict when the identity is bound to any
	// account, or the account already has another subject from the issuer.
	Create(ctx context.Context, identity *Identity) error
	// ChangeSubject re-keys an identity in place (an issuer that moved to a
	// stabler subject claim); ErrConflict when the new key is taken.
	ChangeSubject(ctx context.Context, id shared.ID, subject string) error
	// MarkUsed records a sign-in with the identity.
	MarkUsed(ctx context.Context, id shared.ID, at time.Time) error
}
