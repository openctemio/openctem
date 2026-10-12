package easmdns

// Per-tenant switch and interval for the DNS-only checks (research/22
// P0-11, owner decision E3). Architecture: docs/architecture/easm-dns-checks.md.

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// TenantSettingsReader reads a tenant's EASM settings (*tenant.TenantService).
type TenantSettingsReader interface {
	GetEASMSettings(ctx context.Context, tenantID string) (*tenant.EASMSettings, error)
}

// SetTenantSettings wires the per-tenant switch and interval (nil: platform
// defaults for every tenant).
func (s *Service) SetTenantSettings(r TenantSettingsReader) { s.tenantSettings = r }

// tenantRecheck returns whether the checks run for the tenant and its
// re-check window; a failed read skips the tenant.
func (s *Service) tenantRecheck(ctx context.Context, tenantID shared.ID) (bool, time.Duration) {
	if s.tenantSettings == nil {
		return true, s.recheckAfter
	}
	es, err := s.tenantSettings.GetEASMSettings(ctx, tenantID.String())
	if err != nil {
		s.logger.Warn("easm dns: tenant settings unreadable; tenant skipped", "tenant_id", tenantID.String(), "error", err)
		return false, 0
	}
	if es == nil {
		return true, s.recheckAfter
	}
	if es.DNSChecksDisabled {
		return false, 0
	}
	if es.DNSIntervalHours > 0 {
		return true, time.Duration(es.DNSIntervalHours)*time.Hour - 30*time.Minute
	}
	return true, s.recheckAfter
}
