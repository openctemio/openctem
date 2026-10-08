package scanworkflow

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Spec is what a run of a scan workflow executes: its settings and steps
// (research/62 P0-10). It is saved as an immutable version when a run starts
// with it, and the run reads its settings and steps from that version, so an
// edit made while the run is going changes the next run, never this one.
type Spec struct {
	Settings Settings   `json:"settings"`
	Steps    []SpecStep `json:"steps"`
}

// SpecStep is one step as saved in a version. It keeps the step's id: the
// run's step runs reference the step they were created for.
type SpecStep struct {
	ID                string         `json:"id"`
	StepKey           string         `json:"step_key"`
	Name              string         `json:"name"`
	Description       string         `json:"description,omitempty"`
	StepOrder         int            `json:"step_order"`
	UIPosition        *UIPosition    `json:"ui_position,omitempty"`
	Tool              string         `json:"tool,omitempty"`
	ToolID            string         `json:"tool_id,omitempty"`
	Capabilities      []string       `json:"capabilities,omitempty"`
	PreferTools       []string       `json:"prefer_tools,omitempty"`
	Config            map[string]any `json:"config,omitempty"`
	TimeoutSeconds    int            `json:"timeout_seconds,omitempty"`
	DependsOn         []string       `json:"depends_on,omitempty"`
	Condition         Condition      `json:"condition"`
	MaxRetries        int            `json:"max_retries,omitempty"`
	RetryDelaySeconds int            `json:"retry_delay_seconds,omitempty"`
}

// SpecOf is the spec of a workflow loaded with its steps.
func SpecOf(w *Workflow) Spec {
	steps := make([]SpecStep, 0, len(w.Steps))
	for _, st := range w.Steps {
		pos := st.UIPosition
		ss := SpecStep{
			ID:                st.ID.String(),
			StepKey:           st.StepKey,
			Name:              st.Name,
			Description:       st.Description,
			StepOrder:         st.StepOrder,
			UIPosition:        &pos,
			Tool:              st.Tool,
			Capabilities:      st.Capabilities,
			PreferTools:       st.PreferTools,
			Config:            st.Config,
			TimeoutSeconds:    st.TimeoutSeconds,
			DependsOn:         st.DependsOn,
			Condition:         st.Condition,
			MaxRetries:        st.MaxRetries,
			RetryDelaySeconds: st.RetryDelaySeconds,
		}
		if st.ToolID != nil {
			ss.ToolID = st.ToolID.String()
		}
		steps = append(steps, ss)
	}
	return Spec{Settings: w.Settings, Steps: steps}
}

// Digest identifies what the spec does. The builder layout (node positions)
// is left out, so moving a node does not make a new version.
func (s Spec) Digest() (string, error) {
	steps := make([]SpecStep, len(s.Steps))
	for i, st := range s.Steps {
		st.UIPosition = nil
		steps[i] = st
	}
	raw, err := json.Marshal(Spec{Settings: s.Settings, Steps: steps})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

// Workflow is the workflow a pinned run executes: the live workflow's
// identity with the version's settings and steps.
func (s Spec) Workflow(live *Workflow) *Workflow {
	w := *live
	w.Settings = s.Settings
	w.Steps = make([]*Step, 0, len(s.Steps))
	for _, ss := range s.Steps {
		st := &Step{
			ScanWorkflowID:    live.ID,
			StepKey:           ss.StepKey,
			Name:              ss.Name,
			Description:       ss.Description,
			StepOrder:         ss.StepOrder,
			Tool:              ss.Tool,
			Capabilities:      ss.Capabilities,
			PreferTools:       ss.PreferTools,
			Config:            ss.Config,
			TimeoutSeconds:    ss.TimeoutSeconds,
			DependsOn:         ss.DependsOn,
			Condition:         ss.Condition,
			MaxRetries:        ss.MaxRetries,
			RetryDelaySeconds: ss.RetryDelaySeconds,
		}
		st.ID, _ = shared.IDFromString(ss.ID)
		if ss.UIPosition != nil {
			st.UIPosition = *ss.UIPosition
		}
		if ss.ToolID != "" {
			if id, err := shared.IDFromString(ss.ToolID); err == nil {
				st.ToolID = &id
			}
		}
		w.Steps = append(w.Steps, st)
	}
	return &w
}

// VersionStore keeps the immutable versions runs are pinned to. Every call
// is scoped to the tenant: a workflow of another tenant is not found.
type VersionStore interface {
	// PinVersion saves spec as the workflow's next version unless it equals
	// the latest one (same digest), and returns the version to pin.
	PinVersion(ctx context.Context, tenantID, workflowID shared.ID, spec Spec) (version int, digest string, err error)
	// GetVersion returns a saved version of the tenant's workflow.
	GetVersion(ctx context.Context, tenantID, workflowID shared.ID, version int) (*Spec, error)
}
