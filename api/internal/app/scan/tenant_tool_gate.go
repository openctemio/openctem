package scan

import (
	"context"
	"errors"
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tool"
)

// TenantToolConfigs reads an organization's per-tool settings
// (tenant_tool_configs). Only the enabled flag is enforced here.
type TenantToolConfigs interface {
	GetByTenantAndTool(ctx context.Context, tenantID, toolID shared.ID) (*tool.TenantToolConfig, error)
}

// WithTenantToolConfigs makes trigger-time validation honor an
// organization's "disabled" switch on a tool (settings decision B10). Before,
// the switch was stored but a disabled tool was still dispatched.
func WithTenantToolConfigs(c TenantToolConfigs) ServiceOption {
	return func(s *Service) { s.tenantTools = c }
}

// ErrToolDisabledForTenant: the organization switched this tool off.
func toolDisabledForTenant(name string) error {
	return shared.NewDomainError("TOOL_DISABLED",
		fmt.Sprintf("Tool '%s' is disabled for this organization. Enable it in Settings, Scanning, Tools, or use a different tool.", name),
		shared.ErrValidation)
}

// checkTenantToolEnabled refuses a tool the organization disabled. No
// configuration row means the tool is enabled (the default). A lookup error
// other than not-found fails closed: the tool may be disabled.
func (s *Service) checkTenantToolEnabled(ctx context.Context, tenantID shared.ID, t *tool.Tool) error {
	if s.tenantTools == nil || t == nil || tenantID.IsZero() {
		return nil
	}
	cfg, err := s.tenantTools.GetByTenantAndTool(ctx, tenantID, t.ID)
	if errors.Is(err, shared.ErrNotFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("check tool %s is enabled for the organization: %w", t.Name, err)
	}
	if cfg != nil && !cfg.IsEnabled {
		return toolDisabledForTenant(t.Name)
	}
	return nil
}
