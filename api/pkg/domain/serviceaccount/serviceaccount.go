// Package serviceaccount describes organization-owned identities for
// integrations. A service account is a user of kind "service": it belongs to
// one organization, a person is accountable for it, it can never sign in, and
// it acts only through API keys minted for it, which carry at most the roles
// it holds. It never holds the owner or administrator role nor full data
// access (database triggers and the role grant guard).
package serviceaccount

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// EmailDomain is the unroutable domain of a service account's synthetic
// address (RFC 2606 .invalid): nothing can be mailed to it.
const EmailDomain = "service-accounts.invalid"

// MaxNameLength bounds a service account's name.
const MaxNameLength = 100

// Errors.
var (
	ErrNotFound = fmt.Errorf("%w: service account not found", shared.ErrNotFound)
	ErrInvalid  = fmt.Errorf("%w: invalid service account", shared.ErrValidation)
)

// ServiceAccount is one organization-owned identity.
type ServiceAccount struct {
	ID          shared.ID
	TenantID    shared.ID
	Name        string
	Description string
	OwnerID     *shared.ID // the accountable person; nil once they are gone
	OwnerName   string
	Status      string // the membership status: active or suspended
	CreatedAt   time.Time
	APIKeys     int // active keys
}

// Email returns the synthetic, undeliverable address of an account id.
func Email(id shared.ID) string {
	return "svc-" + id.String() + "@" + EmailDomain
}

// ValidateName checks a service account name.
func ValidateName(name string) (string, error) {
	n := strings.TrimSpace(name)
	if n == "" || len(n) > MaxNameLength {
		return "", fmt.Errorf("%w: the name must have 1 to %d characters", ErrInvalid, MaxNameLength)
	}
	return n, nil
}

// Repository persists service accounts, always within one tenant.
type Repository interface {
	// Create stores the account and its membership of the tenant, with no
	// role, in one transaction.
	Create(ctx context.Context, a *ServiceAccount) error
	List(ctx context.Context, tenantID shared.ID) ([]*ServiceAccount, error)
	Get(ctx context.Context, tenantID, id shared.ID) (*ServiceAccount, error)
	// Delete removes the account; its membership, roles, team memberships
	// and API keys go with it.
	Delete(ctx context.Context, tenantID, id shared.ID) error
	// IsServiceAccount reports whether the user is a service account.
	IsServiceAccount(ctx context.Context, userID shared.ID) (bool, error)
}
