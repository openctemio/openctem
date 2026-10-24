package auth

import (
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/integration"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// An organization's relay stored on a port that is not a mail port (from
// before the rule) is not used for transactional mail: the platform relay
// takes over, and the organization's host is never dialed on that port.
func TestTenantSMTPConfig_NonMailPortFallsBack(t *testing.T) {
	r := NewIntegrationSMTPResolver(nil, logger.NewNop())
	mk := func(port float64) *integration.Integration {
		intg := integration.NewIntegration(shared.NewID(), shared.NewID(), "mail",
			integration.CategoryNotification, integration.ProviderEmail, integration.AuthTypeBasic)
		intg.SetMetadata(map[string]any{"smtp_host": "smtp.example.com", "smtp_port": port, "smtp_from": "a@example.com"})
		return intg
	}
	for _, port := range []float64{6379, 22, 8080} {
		if cfg := r.extractSMTPConfig(mk(port)); cfg != nil {
			t.Errorf("port %v: tenant relay used (%s:%d)", port, cfg.Host, cfg.Port)
		}
	}
	if cfg := r.extractSMTPConfig(mk(587)); cfg == nil || cfg.Port != 587 {
		t.Errorf("port 587: got %+v, want the tenant relay", cfg)
	}
}
