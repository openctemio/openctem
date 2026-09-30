package auth

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/api/internal/config"
	"github.com/openctemio/api/pkg/logger"
)

// In admin_only mode the onboarding create-first-team path must refuse before
// it touches any token or repository, so no organization can be created
// outside the platform admin console (RFC-022).
func TestCreateFirstTeamRefusedInAdminOnlyMode(t *testing.T) {
	svc := NewAuthService(nil, nil, nil, nil, nil,
		config.AuthConfig{TenantCreationMode: config.TenantCreationAdminOnly}, logger.NewNop())
	_, err := svc.CreateFirstTeam(context.Background(), CreateFirstTeamInput{
		RefreshToken: "irrelevant", TeamName: "Sneaky", TeamSlug: "sneaky",
	})
	if !errors.Is(err, ErrTenantCreationDisabled) {
		t.Fatalf("got %v, want ErrTenantCreationDisabled", err)
	}
}
