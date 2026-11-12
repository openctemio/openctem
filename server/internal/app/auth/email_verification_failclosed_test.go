package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
	userdom "github.com/openctemio/openctem/api/pkg/domain/user"
)

type unreadableTenantRepo struct{ tenantdom.Repository }

func (unreadableTenantRepo) GetByID(context.Context, shared.ID) (*tenantdom.Tenant, error) {
	return nil, errors.New("database unavailable")
}

// An unverified account whose organization cannot be read gets no token: the
// "always" requirement must not be skipped because the lookup failed.
func TestEnforceEmailVerificationPolicy_UnreadableOrganizationFailsClosed(t *testing.T) {
	now := time.Now().UTC()
	unverified := userdom.Reconstitute(shared.NewID(), nil, "u@example.com", "U", "", "", userdom.StatusActive,
		userdom.Preferences{}, nil, now, now, userdom.AuthProviderLocal, nil, false, nil, nil, nil, nil, 0, nil)
	s := &AuthService{tenantRepo: unreadableTenantRepo{}}

	if err := s.enforceEmailVerificationPolicy(context.Background(), unverified, shared.NewID().String()); !errors.Is(err, ErrEmailNotVerified) {
		t.Fatalf("unreadable organization must refuse an unverified account, got %v", err)
	}
	if err := s.enforceEmailVerificationPolicy(context.Background(), unverified, "not-an-id"); !errors.Is(err, ErrEmailNotVerified) {
		t.Fatalf("an invalid organization id must refuse an unverified account, got %v", err)
	}
}
