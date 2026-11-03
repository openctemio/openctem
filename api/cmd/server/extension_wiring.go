package main

import (
	"context"

	entitlementapp "github.com/openctemio/openctem/api/internal/app/entitlement"
	"github.com/openctemio/openctem/api/pkg/domain/limits"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// extensionEntitlements answers an extension's grant questions from the
// core entitlement service (fail closed, like every grant gate).
type extensionEntitlements struct{ s *entitlementapp.Service }

func (e extensionEntitlements) RequireGrant(ctx context.Context, tenantID shared.ID, key limits.GrantKey) error {
	if e.s == nil {
		return &limits.ErrGrantRequired{Key: key}
	}
	return e.s.RequireAddon(ctx, tenantID, key)
}
