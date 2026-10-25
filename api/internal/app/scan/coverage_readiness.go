package scan

// Readiness of continuous coverage (docs/rfcs/RFC-093-asset-coverage.md):
// before the planner creates a coverage run it asks whether the capability
// could be dispatched for the tenant at all, from the same answers the
// trigger uses (the tool's switch and availability on the tenant's sensors,
// an online sensor for the tool). A capability that is not ready gets no run
// and no blocked run; the planner pauses its pairs with the reason. The
// answer only narrows: a ready capability still passes every trigger and
// claim-time check. It reads only the tenant's own sensors and catalog, and
// a reason never names another tenant's sensor.

import (
	"context"
	"errors"
	"strings"

	covdom "github.com/openctemio/openctem/api/pkg/domain/coverage"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
)

// CoverageReadiness returns, per capability, the readiness reason that
// keeps it from running for the tenant now ("" = ready as far as these
// checks know). A source that cannot be read counts as ready: the trigger's
// own checks still apply.
func (s *Service) CoverageReadiness(ctx context.Context, tenantID shared.ID, capabilities []string) map[string]string {
	out := make(map[string]string, len(capabilities))
	byTool := map[string]string{}
	for _, c := range capabilities {
		st, ok := stage.Lookup(stage.Key(c))
		if !ok {
			continue
		}
		tool := st.DefaultTool()
		if tool == "" {
			out[c] = covdom.ReadyToolMissing
			continue
		}
		r, done := byTool[tool]
		if !done {
			r = s.toolReadiness(ctx, tenantID, tool)
			byTool[tool] = r
		}
		out[c] = r
	}
	return out
}

// toolReadiness is the readiness of one tool for the tenant.
func (s *Service) toolReadiness(ctx context.Context, tenantID shared.ID, tool string) string {
	var ta *sensordom.ToolAvailability
	if s.toolAvailability != nil {
		got, err := s.toolAvailability.ToolAvailabilityFor(ctx, tenantID, nil, tool)
		if err != nil {
			s.logger.Warn("coverage readiness: tool availability unreadable; checking sensors only",
				"tenant_id", tenantID.String(), "tool", tool, "error", err)
		} else {
			ta = got
		}
	}
	if ta != nil {
		switch ta.Status {
		case sensordom.ToolDisabled:
			return covdom.ReadyPolicyDisabled
		case sensordom.ToolOfflineOnly:
			return covdom.ReadySensorOffline
		case sensordom.ToolOutdated:
			return covdom.ReadySensorOutdated
		case sensordom.ToolNoSensor:
			if ta.SensorsExcluded > 0 {
				return covdom.ReadyToolNotAllowed
			}
			if !s.tenantHasOnlineSensor(ctx, tenantID) {
				return covdom.ReadyNoEligibleSensor
			}
			return covdom.ReadyToolMissing
		}
	}
	// The trigger's own sensor check: an online sensor of the tenant with
	// the tool.
	if s.sensorSelector != nil {
		if a := s.sensorSelector.CheckSensorAvailability(ctx, tenantID, tool, false); a != nil && !a.Available {
			// The selector counts only sensors with free capacity. A
			// tenant sensor that is online but full is busy, not offline:
			// the run queues for it, so the capability stays ready.
			if ta != nil && ta.SensorsOnline > 0 {
				return ""
			}
			if ta != nil && ta.SensorsTotal > 0 {
				return covdom.ReadySensorOffline
			}
			return covdom.ReadyNoEligibleSensor
		}
	}
	return ""
}

func (s *Service) tenantHasOnlineSensor(ctx context.Context, tenantID shared.ID) bool {
	if s.sensorSelector == nil {
		return true
	}
	a := s.sensorSelector.CheckSensorAvailability(ctx, tenantID, "", false)
	return a != nil && a.Available
}

// CoverageReadinessForRefusal maps a trigger refusal of a whole coverage
// batch to the readiness reason it means: the refusals that say the
// capability cannot run for the tenant now (no sensor, a tool no sensor may
// run, an organization policy). It returns "" for anything else: a refusal
// about the batch's targets (targets that never open under the scan
// windows, targets in no scan zone, excluded targets) or an error that is
// not a refusal. One bad target must not stall the capability, so the
// planner handles those per batch.
func CoverageReadinessForRefusal(err error) string {
	var tu *ToolUnavailableError
	if errors.As(err, &tu) {
		switch {
		case tu.Status == string(sensordom.ToolOfflineOnly):
			return covdom.ReadySensorOffline
		case tu.SensorsExcluded > 0:
			return covdom.ReadyToolNotAllowed
		default:
			return covdom.ReadyToolMissing
		}
	}
	var de *shared.DomainError
	if !errors.As(err, &de) {
		return ""
	}
	switch de.Code {
	case CodeNoSensorForTool:
		return covdom.ReadyToolMissing
	case "NO_SENSOR_AVAILABLE", codePlatformRefused:
		return covdom.ReadyNoEligibleSensor
	case codeSensorPolicyRefused:
		return covdom.ReadyToolNotAllowed
	case "TOOL_NOT_SCANNER", codeNoMatchingTool:
		return covdom.ReadyToolMissing
	case "TOOL_DISABLED", codeSensorOptInDisabled, "SCAN_NOT_TRIGGERABLE", codeTierExceeds,
		"SCAN_MANAGED_BY_POLICY", "PROGRAM_RULES_UNAVAILABLE":
		return covdom.ReadyPolicyDisabled
	}
	if strings.HasPrefix(de.Code, "SCAN_APPROVAL") {
		return covdom.ReadyPolicyDisabled
	}
	return ""
}
