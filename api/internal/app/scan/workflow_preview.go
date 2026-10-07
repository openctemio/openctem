package scan

import (
	"context"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/pipeline"
	"github.com/openctemio/openctem/api/pkg/domain/scanfreeze"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
)

// Workflow preview (lite): what a workflow scan would do before it is saved
// or triggered, per step and for its targets, computed by the code the
// trigger runs. Read-only: no scan, run or command is created.
//
//   - per step: the capability and tier, the tool the planner picks
//     (ResolveStepTool) and whether an online sensor that may run it exists
//     (the trigger's NO_SENSOR_FOR_TOOL check, same message);
//   - the targets: the zone routing preview with the scan type workflow
//     (the trigger's target resolution, scope exclusions, zone plan);
//   - a freeze window active now for the zone, for active work.
//
// A blocking verdict is one the trigger would refuse with.

// maxWorkflowPreviewSamples bounds the per-target sample of a preview.
const maxWorkflowPreviewSamples = 20

// WorkflowPreviewInput is a workflow and the targets a scan would run it on.
type WorkflowPreviewInput struct {
	TenantID      string
	PipelineID    string
	Targets       []string
	AssetGroupIDs []string
	ScanZoneID    string
}

// WorkflowPreviewNode is what one step would run.
type WorkflowPreviewNode struct {
	StepKey    string `json:"step_key"`
	Name       string `json:"name"`
	Capability string `json:"capability,omitempty"`
	Tier       string `json:"tier,omitempty"`
	// Tool is the tool the planner picks now; Pinned when the step names it.
	Tool       string   `json:"tool,omitempty"`
	Pinned     bool     `json:"pinned"`
	Candidates []string `json:"candidates"`
	// Availability is the tool's sensor status (ready, offline_only,
	// no_sensor, ...) with the counts behind it; nil when unknown.
	Availability *WorkflowPreviewAvailability `json:"availability,omitempty"`
	// ChunkSize is how many targets one command of the step takes when
	// the step is cut into chunks (0: the step is one command).
	ChunkSize int `json:"chunk_size,omitempty"`
	// MaxParallelSensors is how many sensors can work on the step at once:
	// every online sensor that may run the tool for a chunked step, one
	// otherwise; 0 when none can (or availability is unknown).
	MaxParallelSensors int `json:"max_parallel_sensors"`
	// Blocking is what the trigger would refuse this step with.
	Blocking *PreviewError `json:"blocking,omitempty"`
}

// WorkflowPreviewAvailability is a tool's sensor availability.
type WorkflowPreviewAvailability struct {
	Status          string `json:"status"`
	SensorsOnline   int    `json:"sensors_online"`
	SensorsTotal    int    `json:"sensors_total"`
	SensorsExcluded int    `json:"sensors_excluded"`
}

// WorkflowPreviewFreeze is a freeze window active now.
type WorkflowPreviewFreeze struct {
	Window string    `json:"window"`
	Until  time.Time `json:"until"`
}

// WorkflowPreview is the preview of a workflow scan.
type WorkflowPreview struct {
	Nodes   []WorkflowPreviewNode  `json:"nodes"`
	Targets *ZoneRoutingPreview    `json:"targets"`
	Freeze  *WorkflowPreviewFreeze `json:"freeze,omitempty"`
	// Blocking: a trigger with these settings would be refused.
	Blocking bool `json:"blocking"`
}

// PreviewWorkflow previews a workflow scan. The workflow must be the
// tenant's or a system workflow; anything else is not found.
func (s *Service) PreviewWorkflow(ctx context.Context, in WorkflowPreviewInput) (*WorkflowPreview, error) {
	tenantID, err := shared.IDFromString(in.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	pid, err := shared.IDFromString(in.PipelineID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid pipeline id", shared.ErrValidation)
	}
	tpl, err := s.templateRepo.GetWithSteps(ctx, pid)
	if err != nil {
		return nil, err
	}
	if !tpl.IsSystemTemplate && tpl.TenantID != tenantID {
		return nil, shared.ErrNotFound
	}

	targets, err := s.PreviewZoneRouting(ctx, ZoneRoutingPreviewInput{
		TenantID:      in.TenantID,
		Targets:       in.Targets,
		AssetGroupIDs: in.AssetGroupIDs,
		ScanType:      "workflow",
		ScanZoneID:    in.ScanZoneID,
	})
	if err != nil {
		return nil, err
	}
	if len(targets.Targets) > maxWorkflowPreviewSamples {
		targets.Targets = targets.Targets[:maxWorkflowPreviewSamples]
	}

	var zoneID *shared.ID
	if targets.SelectedZoneID != "" {
		z, _ := shared.IDFromString(targets.SelectedZoneID)
		zoneID = &z
	}

	out := &WorkflowPreview{Nodes: make([]WorkflowPreviewNode, 0, len(tpl.Steps)), Targets: targets}
	for _, step := range tpl.Steps {
		node := s.previewStep(ctx, tenantID, zoneID, step)
		if node.Blocking != nil {
			out.Blocking = true
		}
		out.Nodes = append(out.Nodes, node)
	}
	if targets.Error != nil {
		out.Blocking = true
	}

	if s.freezeWindows != nil && workflowActive(tpl.Steps) {
		var zones []shared.ID
		if zoneID != nil {
			zones = []shared.ID{*zoneID}
		}
		ws, err := s.freezeWindows.ActiveAt(ctx, tenantID, zones, time.Now())
		if err != nil {
			return nil, fmt.Errorf("freeze window check failed: %w", err)
		}
		if w := scanfreeze.Latest(ws); w != nil && w.ActiveUntil != nil {
			out.Freeze = &WorkflowPreviewFreeze{Window: w.Name, Until: *w.ActiveUntil}
			out.Blocking = true
		}
	}
	return out, nil
}

// maxParallelSensors is how many sensors can work on a step at once: a
// chunked step is shared by every online eligible sensor, an unchunked one
// runs on one.
func maxParallelSensors(chunkSize, online int) int {
	if online <= 0 {
		return 0
	}
	if chunkSize > 0 {
		return online
	}
	return 1
}

// previewStep resolves one step as the trigger would.
func (s *Service) previewStep(ctx context.Context, tenantID shared.ID, zoneID *shared.ID, step *pipeline.Step) WorkflowPreviewNode {
	node := WorkflowPreviewNode{StepKey: step.StepKey, Name: step.Name, Candidates: []string{}}
	resolved, err := ResolveStepTool(ctx, s.toolRepo, tenantID, step)
	if err != nil {
		node.Blocking = previewError(err)
		if st, ok := stage.ForStep(step.Tool, step.Capabilities); ok {
			node.Capability, node.Tier = st.ID(), st.Tier.String()
		}
		return node
	}
	node.Tool, node.Pinned = resolved.Name, resolved.Pinned
	node.Candidates = append(node.Candidates, resolved.Candidates...)
	if resolved.HasStage {
		node.Capability, node.Tier = resolved.Capability(), resolved.Stage.Tier.String()
		node.ChunkSize = resolved.Stage.ChunkSizeFor(resolved.Name)
	}
	if s.toolAvailability == nil {
		return node
	}
	ta, err := s.toolAvailability.ToolAvailabilityFor(ctx, tenantID, zoneID, resolved.Name)
	if err != nil || ta == nil {
		return node // unknown: the trigger lets it through too
	}
	node.Availability = &WorkflowPreviewAvailability{
		Status: string(ta.Status), SensorsOnline: ta.SensorsOnline,
		SensorsTotal: ta.SensorsTotal, SensorsExcluded: ta.SensorsExcluded,
	}
	node.MaxParallelSensors = maxParallelSensors(node.ChunkSize, ta.SensorsOnline)
	if !ta.Runnable() && ta.Status != sensordom.ToolDisabled {
		node.Blocking = &PreviewError{Code: CodeNoSensorForTool, Message: toolUnavailableMessage(ta, step.StepKey, zoneID != nil)}
	}
	return node
}
