package main

import (
	"context"
	"fmt"

	"github.com/openctemio/openctem/api/internal/app/entitlement"

	"github.com/openctemio/openctem/api/internal/config"
	signupdom "github.com/openctemio/openctem/api/pkg/domain/signup"
)

// requireSelfServiceStartLimits refuses to start when self-service sign-up
// is on (SIGNUP_MODE=open, or the console sign-up policy)
// and no starting limits are configured: a public sign-up must never create
// unlimited organizations by accident (docs/architecture/limits.md). An
// operator who wants none sets SELF_SERVICE_START_LIMITS=unlimited.
func requireSelfServiceStartLimits(ctx context.Context, cfg *config.Config, svc *Services) error {
	if svc.Entitlement == nil {
		return nil
	}
	if err := svc.Entitlement.SetStartLimits(cfg.SelfServiceStartLimits); err != nil {
		return err
	}
	selfService := cfg.Auth.SignupOpen()
	if svc.Signup != nil {
		if cfg.Auth.SignupOpen() {
			// Fail closed: an unreadable policy must not skip the check,
			// because the stored policy may be self_service.
			st, err := svc.Signup.Get(ctx)
			if err != nil {
				return fmt.Errorf("read the sign-up policy to check the starting limits: %w", err)
			}
			selfService = svc.Signup.Effective(st.Policy).Mode == signupdom.ModeSelfService
		} else {
			selfService = svc.Signup.Current(ctx).Mode == signupdom.ModeSelfService
		}
	}
	// A hosted service's control plane sets the starting limits through the
	// internal API.
	if !selfService || cfg.InternalAPI.Enabled() {
		return nil
	}
	ok, err := svc.Entitlement.StartLimitsConfigured(ctx)
	if err != nil {
		return fmt.Errorf("read the starting limits of self-service organizations: %w", err)
	}
	if !ok {
		return fmt.Errorf("self-service sign-up is on but no starting limits are configured: %w", entitlement.ErrStartLimitsRequired)
	}
	return nil
}
