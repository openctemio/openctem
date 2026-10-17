package main

import (
	"context"
	"testing"

	"errors"
	"time"

	"github.com/openctemio/openctem/api/internal/app/entitlement"
	signupapp "github.com/openctemio/openctem/api/internal/app/signup"
	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/pkg/domain/limits"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	signupdom "github.com/openctemio/openctem/api/pkg/domain/signup"
)

// noDefaultsRepo stores nothing: no console setting.
type noDefaultsRepo struct{ limits.Repository }

func (noDefaultsRepo) GetSelfServiceDefaults(context.Context) (limits.Limits, int, error) {
	return nil, 0, shared.ErrNotFound
}

// SIGNUP_MODE=open with no starting limits refuses to
// start; admin_only, an explicit "unlimited" or limits in the environment
// start.
func TestRequireSelfServiceStartLimits(t *testing.T) {
	ctx := context.Background()
	run := func(mode, start string) error {
		cfg := &config.Config{SelfServiceStartLimits: start}
		cfg.Auth.SignupMode = mode
		return requireSelfServiceStartLimits(ctx, cfg, &Services{Entitlement: entitlement.NewService(noDefaultsRepo{}, nil, nil)})
	}
	if err := run(config.SignupModeOpen, ""); err == nil {
		t.Fatal("self-service without starting limits must refuse to start")
	}
	if err := run(config.SignupModeDisabled, ""); err != nil {
		t.Fatalf("admin_only: %v", err)
	}
	if err := run(config.SignupModeOpen, "unlimited"); err != nil {
		t.Fatalf("explicit unlimited: %v", err)
	}
	if err := run(config.SignupModeOpen, `{"seats":5,"orgs_per_user":1}`); err != nil {
		t.Fatalf("environment limits: %v", err)
	}
	cfg := &config.Config{}
	cfg.Auth.SignupMode = config.SignupModeOpen
	cfg.InternalAPI.Addr = ":9443"
	if err := requireSelfServiceStartLimits(ctx, cfg, &Services{Entitlement: entitlement.NewService(noDefaultsRepo{}, nil, nil)}); err != nil {
		t.Fatalf("the internal API sets the starting limits: %v", err)
	}
	if err := run(config.SignupModeDisabled, `{"bogus":1}`); err == nil {
		t.Fatal("an invalid SELF_SERVICE_START_LIMITS must refuse to start")
	}
}

// storedSignupRepo returns a fixed stored policy, or an error.
type storedSignupRepo struct {
	signupdom.Repository
	st  signupdom.State
	err error
}

func (r storedSignupRepo) Get(context.Context) (signupdom.State, error) { return r.st, r.err }

func (storedSignupRepo) Update(context.Context, signupdom.Policy, int, shared.ID, time.Time) (signupdom.State, error) {
	return signupdom.State{}, errors.New("unused")
}

// With the sign-up service wired the stored policy decides, clamped by the
// deployment ceiling; an unreadable policy under SIGNUP_MODE=open refuses to
// start instead of skipping the check.
func TestRequireSelfServiceStartLimits_WithSignupService(t *testing.T) {
	ctx := context.Background()
	run := func(mode string, ceiling signupdom.Ceiling, repo storedSignupRepo) error {
		cfg := &config.Config{}
		cfg.Auth.SignupMode = mode
		su := signupapp.NewService(repo, nil, nil, nil, nil)
		su.SetCeiling(ceiling)
		return requireSelfServiceStartLimits(ctx, cfg, &Services{
			Entitlement: entitlement.NewService(noDefaultsRepo{}, nil, nil),
			Signup:      su,
		})
	}
	stored := storedSignupRepo{st: signupdom.State{Policy: signupdom.Policy{Mode: signupdom.ModeSelfService}, Version: 1}}
	if err := run(config.SignupModeOpen, signupdom.CeilingOpen, stored); !errors.Is(err, entitlement.ErrStartLimitsRequired) {
		t.Fatalf("open + stored self_service + no limits must refuse, got %v", err)
	}
	if err := run(config.SignupModeDisabled, signupdom.CeilingDisabled, stored); err != nil {
		t.Fatalf("disabled clamps a stored self_service row: %v", err)
	}
	broken := storedSignupRepo{err: errors.New("db down")}
	if err := run(config.SignupModeOpen, signupdom.CeilingOpen, broken); err == nil {
		t.Fatal("an unreadable sign-up policy under open must refuse to start")
	}
	// Fail closed both ways: with sign-up not open the stored policy is
	// still read, and an unreadable one refuses the start too.
	if err := run(config.SignupModeDisabled, signupdom.CeilingDisabled, broken); err == nil {
		t.Fatal("an unreadable sign-up policy under a non-open mode must refuse to start")
	}
}
