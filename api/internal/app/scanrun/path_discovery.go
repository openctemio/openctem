package scanrun

// The organization's path discovery switch on workflow steps
// (docs/architecture/web-discovery.md): a step that runs enumerate.web_paths
// is skipped with the reason while the organization has path discovery
// turned off. Unwired, such a step is skipped (fail closed).

import (
	"context"
	"strings"

	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// PathDiscoverySwitch reads the organization's path discovery switch.
type PathDiscoverySwitch interface {
	PathDiscoveryEnabled(ctx context.Context, tenantID shared.ID) (bool, error)
}

// SetPathDiscoverySwitch wires the switch.
func (s *Service) SetPathDiscoverySwitch(sw PathDiscoverySwitch) { s.pathSwitch = sw }

// Skip reasons of a path discovery step.
const (
	skipPathDiscoveryOff     = "Path discovery is turned off for the organization (scope settings)."
	skipPathDiscoveryUnknown = "Path discovery is not configured on this server, or its switch could not be read."
)

// stepRunsPathDiscovery reports whether the step runs enumerate.web_paths.
func stepRunsPathDiscovery(step *scanworkflow.Step) bool {
	if step == nil {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(step.Tool), commanddom.DiscoveryTool) {
		return true
	}
	for _, c := range step.Capabilities {
		w, _, _ := strings.Cut(strings.ToLower(strings.TrimSpace(c)), "@")
		if w == commanddom.DiscoveryCapability {
			return true
		}
	}
	return false
}

// pathDiscoverySkipReason is why a path discovery step does not run ("" when
// it runs, and for every other step).
func (s *Service) pathDiscoverySkipReason(ctx context.Context, run *scanrun.Run, step *scanworkflow.Step) string {
	if !stepRunsPathDiscovery(step) {
		return ""
	}
	if s.pathSwitch == nil || run == nil {
		return skipPathDiscoveryUnknown
	}
	on, err := s.pathSwitch.PathDiscoveryEnabled(ctx, run.TenantID)
	if err != nil {
		s.logger.Warn("path discovery switch unreadable; step skipped", "run_id", run.ID.String(), "error", logger.SanitizeError(err))
		return skipPathDiscoveryUnknown
	}
	if !on {
		return skipPathDiscoveryOff
	}
	return ""
}
