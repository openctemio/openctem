package main

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/entitlement"
	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/pkg/domain/limits"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// noDefaultsRepo stores nothing: no console setting.
type noDefaultsRepo struct{ limits.Repository }

func (noDefaultsRepo) GetSelfServiceDefaults(context.Context) (limits.Limits, int, error) {
	return nil, 0, shared.ErrNotFound
}

// TENANT_CREATION_MODE=self_service with no starting limits refuses to
// start; admin_only, an explicit "unlimited" or limits in the environment
// start.
func TestRequireSelfServiceStartLimits(t *testing.T) {
	ctx := context.Background()
	run := func(mode, start string) error {
		cfg := &config.Config{SelfServiceStartLimits: start}
		cfg.Auth.TenantCreationMode = mode
		return requireSelfServiceStartLimits(ctx, cfg, &Services{Entitlement: entitlement.NewService(noDefaultsRepo{}, nil, nil)})
	}
	if err := run(config.TenantCreationSelfService, ""); err == nil {
		t.Fatal("self-service without starting limits must refuse to start")
	}
	if err := run(config.TenantCreationAdminOnly, ""); err != nil {
		t.Fatalf("admin_only: %v", err)
	}
	if err := run(config.TenantCreationSelfService, "unlimited"); err != nil {
		t.Fatalf("explicit unlimited: %v", err)
	}
	if err := run(config.TenantCreationSelfService, `{"seats":5,"orgs_per_user":1}`); err != nil {
		t.Fatalf("environment limits: %v", err)
	}
	cfg := &config.Config{}
	cfg.Auth.TenantCreationMode = config.TenantCreationSelfService
	cfg.InternalAPI.Addr = ":9443"
	if err := requireSelfServiceStartLimits(ctx, cfg, &Services{Entitlement: entitlement.NewService(noDefaultsRepo{}, nil, nil)}); err != nil {
		t.Fatalf("the internal API sets the starting limits: %v", err)
	}
	if err := run(config.TenantCreationAdminOnly, `{"bogus":1}`); err == nil {
		t.Fatal("an invalid SELF_SERVICE_START_LIMITS must refuse to start")
	}
}
