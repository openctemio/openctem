package certmonitor

// Per-tenant monitoring settings (research/22 P0-11, owner decision E8):
// a tenant may turn the CT monitor off (its names are then not sent to
// crt.sh or Cert Spotter) or set its own re-check interval within the
// platform floor. Architecture: docs/architecture/easm.md.

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// TenantSettingsReader reads a tenant\x27s EASM settings (*tenant.TenantService).
type TenantSettingsReader interface {
	GetEASMSettings(ctx context.Context, tenantID string) (*tenant.EASMSettings, error)
}

// SetTenantSettings wires the per-tenant switch and interval (nil: platform
// defaults for every tenant).
func (s *Service) SetTenantSettings(r TenantSettingsReader) { s.tenantSettings = r }

// tenantRecheck returns whether CT runs for the tenant and its re-check
// window. A failed read skips the tenant (fail closed: a tenant that opted
// out must not have its names sent on a database hiccup).
func (s *Service) tenantRecheck(ctx context.Context, tenantID shared.ID) (bool, time.Duration) {
	if s.tenantSettings == nil {
		return true, s.recheckAfter
	}
	es, err := s.tenantSettings.GetEASMSettings(ctx, tenantID.String())
	if err != nil {
		s.logger.Warn("ct sweep: tenant settings unreadable; tenant skipped", "tenant_id", tenantID.String(), "error", err)
		return false, 0
	}
	if es == nil {
		return true, s.recheckAfter
	}
	if es.CTDisabled {
		return false, 0
	}
	return true, RecheckFor(es.CTIntervalHours, s.recheckAfter)
}

// RecheckFor is the re-check window for an interval of hours (0: the given
// default). It is half an hour short of the interval, so an hourly tick
// re-queries a name once per interval.
func RecheckFor(hours int, def time.Duration) time.Duration {
	if hours <= 0 {
		return def
	}
	return time.Duration(hours)*time.Hour - 30*time.Minute
}
