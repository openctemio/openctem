package scan

// Trigger-time refusal of a scan no sensor can run
// (docs/architecture/tool-availability.md): a trigger whose scanner, or the
// tool of one of its workflow steps, is on no online sensor that may run it
// is refused with NO_SENSOR_FOR_TOOL and the counts behind it, instead of
// queueing jobs that wait until they expire. Zone-pinned scans are judged
// on the zone's sensors. The answer comes from the sensors' manifests and
// only narrows: dispatch still checks every job at claim time.

import (
	"context"
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"

	"github.com/openctemio/openctem/api/pkg/domain/scan"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// CodeNoSensorForTool is the trigger refusal when no online sensor may run
// a tool the scan needs.
const CodeNoSensorForTool = "NO_SENSOR_FOR_TOOL"

// ToolAvailability answers whether a scan job for a tool can be dispatched
// now. Satisfied by the tool service. A nil answer means unknown (the tool
// is not listed, or availability is not wired).
type ToolAvailability interface {
	ToolAvailabilityFor(ctx context.Context, tenantID shared.ID, zoneID *shared.ID, tool string) (*sensordom.ToolAvailability, error)
}

// WithToolAvailability enables the trigger-time tool availability check.
func WithToolAvailability(a ToolAvailability) ServiceOption {
	return func(s *Service) { s.toolAvailability = a }
}

// ToolUnavailableError is a NO_SENSOR_FOR_TOOL refusal with what the client
// needs to explain it. It unwraps to the domain error (code and message).
type ToolUnavailableError struct {
	Domain *shared.DomainError
	// Tool is the tool no sensor may run; Step the workflow step that needs
	// it ("" for a single-scanner scan).
	Tool string
	Step string
	// Status is the tool's availability status (no_sensor, offline_only).
	Status          string
	SensorsTotal    int
	SensorsOnline   int
	SensorsExcluded int
	// ZoneID is the scan zone the sensors were counted in ("" = all).
	ZoneID string
}

func (e *ToolUnavailableError) Error() string { return e.Domain.Error() }
func (e *ToolUnavailableError) Unwrap() error { return e.Domain }

// checkScanToolsDispatchable refuses the trigger when a tool the scan needs
// is on no online sensor that may run it. Without the availability source,
// or when it cannot be read, it lets the trigger through (the sensor
// availability check that follows still applies).
func (s *Service) checkScanToolsDispatchable(ctx context.Context, sc *scan.Scan) error {
	if s.toolAvailability == nil {
		return nil
	}
	switch sc.ScanType {
	case scan.ScanTypeSingle:
		if sc.ScannerName == "" {
			return nil
		}
		// A connector scan runs through its integration's connector
		// commands, not a scanner on a sensor's manifest.
		if t, err := s.toolRepo.GetByName(ctx, sc.TenantID, sc.ScannerName); err == nil && t != nil && t.IsConnector() {
			return nil
		}
		return s.checkToolDispatchable(ctx, sc, sc.ScannerName, "")
	case scan.ScanTypeWorkflow:
		if sc.ScanWorkflowID == nil {
			return nil
		}
		steps, err := s.stepRepo.GetByScanWorkflowID(ctx, *sc.ScanWorkflowID)
		if err != nil {
			return fmt.Errorf("failed to get scan workflow steps: %w", err)
		}
		seen := map[string]bool{}
		for _, step := range steps {
			name := s.stepToolName(ctx, sc.TenantID, step)
			if name == "" || seen[name] {
				continue
			}
			seen[name] = true
			if err := s.checkToolDispatchable(ctx, sc, name, step.StepKey); err != nil {
				return err
			}
		}
	}
	return nil
}

// stepToolName is the tool a workflow step runs: its tool, or the tool its
// capabilities resolve to; "" when neither applies.
func (s *Service) stepToolName(ctx context.Context, tenantID shared.ID, step *scanworkflow.Step) string {
	if step.Tool != "" {
		return step.Tool
	}
	if len(step.Capabilities) == 0 {
		return ""
	}
	resolved, err := ResolveStepTool(ctx, s.toolRepo, tenantID, step)
	if err != nil {
		return ""
	}
	return resolved.Name
}

// checkToolDispatchable refuses when tool is enabled but on no online
// sensor that may run it (in the scan's zone when it is pinned to one).
func (s *Service) checkToolDispatchable(ctx context.Context, sc *scan.Scan, tool, stepKey string) error {
	ta, err := s.toolAvailability.ToolAvailabilityFor(ctx, sc.TenantID, sc.ScanZoneID, tool)
	if err != nil {
		s.logger.Warn("tool availability unreadable at trigger; checking sensors only",
			"scan_id", sc.ID.String(), "tool", tool, "error", err)
		return nil
	}
	// Unknown, runnable, or switched off (the tool checks before this one
	// refuse a disabled tool with TOOL_DISABLED).
	if ta == nil || ta.Runnable() || ta.Status == sensordom.ToolDisabled {
		return nil
	}
	e := &ToolUnavailableError{
		Tool: tool, Step: stepKey, Status: string(ta.Status),
		SensorsTotal: ta.SensorsTotal, SensorsOnline: ta.SensorsOnline, SensorsExcluded: ta.SensorsExcluded,
	}
	if sc.ScanZoneID != nil {
		e.ZoneID = sc.ScanZoneID.String()
	}
	e.Domain = shared.NewDomainError(CodeNoSensorForTool, toolUnavailableMessage(ta, stepKey, sc.ScanZoneID != nil), shared.ErrValidation)
	return e
}

// toolUnavailableMessage explains why no sensor can run the tool now.
func toolUnavailableMessage(ta *sensordom.ToolAvailability, stepKey string, zoned bool) string {
	where := ""
	if zoned {
		where = " in the scan's zone"
	}
	prefix := ""
	if stepKey != "" {
		prefix = fmt.Sprintf("Step %q: ", stepKey)
	}
	switch {
	case ta.Status == sensordom.ToolOfflineOnly:
		return fmt.Sprintf("%sNo online sensor has %s%s: %d sensor(s) have it and none is online now. Start one, or wait until it reconnects.",
			prefix, ta.Name, where, ta.SensorsTotal)
	case ta.SensorsExcluded > 0:
		return fmt.Sprintf("%sNo sensor%s may run %s: %d sensor(s) have it, but their grant or local policy does not allow it.",
			prefix, where, ta.Name, ta.SensorsExcluded)
	default:
		return fmt.Sprintf("%sNo sensor%s has %s. Add it to a sensor (Settings > Scanning > Tools shows how) or choose another tool.",
			prefix, where, ta.Name)
	}
}
