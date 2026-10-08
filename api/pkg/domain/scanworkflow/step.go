package scanworkflow

import (
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Step timeout limits.
const (
	// MinTimeoutSeconds is the minimum allowed timeout (1 minute).
	MinTimeoutSeconds = 60
	// MaxTimeoutSeconds is the maximum allowed timeout (24 hours).
	MaxTimeoutSeconds = 86400
	// DefaultTimeoutSeconds is the default timeout (30 minutes).
	DefaultTimeoutSeconds = 1800
)

// ConditionType represents the type of condition for step execution.
type ConditionType string

const (
	ConditionTypeAlways     ConditionType = "always"      // Always run
	ConditionTypeNever      ConditionType = "never"       // Never run (disabled)
	ConditionTypeExpression ConditionType = "expression"  // Custom expression (NOT YET IMPLEMENTED)
	ConditionTypeAssetType  ConditionType = "asset_type"  // Based on asset type
	ConditionTypeStepResult ConditionType = "step_result" // Based on previous step result
)

// IsValid checks if the condition type is valid.
func (c ConditionType) IsValid() bool {
	switch c {
	case ConditionTypeAlways, ConditionTypeNever, ConditionTypeExpression, ConditionTypeAssetType, ConditionTypeStepResult:
		return true
	}
	return false
}

// Condition represents a step execution condition.
type Condition struct {
	Type  ConditionType `json:"type"`
	Value string        `json:"value,omitempty"`
}

// AlwaysCondition creates an always-run condition.
func AlwaysCondition() Condition {
	return Condition{Type: ConditionTypeAlways}
}

// NeverCondition creates a never-run condition.
func NeverCondition() Condition {
	return Condition{Type: ConditionTypeNever}
}

// ExpressionCondition creates an expression-based condition.
func ExpressionCondition(expr string) Condition {
	return Condition{Type: ConditionTypeExpression, Value: expr}
}

// AssetTypeCondition creates an asset-type condition.
func AssetTypeCondition(assetType string) Condition {
	return Condition{Type: ConditionTypeAssetType, Value: assetType}
}

// UIPosition represents the visual position in the workflow builder.
type UIPosition struct {
	X float64 `json:"x"`
	Y float64 `json:"y"`
}

// Step represents a single step in a scan workflow.
type Step struct {
	ID             shared.ID
	ScanWorkflowID shared.ID

	// Step definition
	StepKey     string
	Name        string
	Description string
	StepOrder   int

	// Visual workflow builder
	UIPosition UIPosition

	// Tool requirements. A step is a capability node; how it picks its tool
	// (ToolSelection):
	//   - pin:    Tool names the one tool it runs (strict);
	//   - prefer: PreferTools lists the tools to try, in order;
	//   - auto:   any implementation of the capability, the catalog default
	//             first.
	Tool         string     // Pinned tool name (optional)
	ToolID       *shared.ID // Pinned tool ID (FK reference to tools table, optional)
	Capabilities []string   // Required capabilities
	PreferTools  []string   // Ordered tools to try when no tool is pinned

	// Configuration
	Config         map[string]any
	TimeoutSeconds int

	// Dependencies
	DependsOn []string // Step keys this step depends on

	// Conditions
	Condition Condition

	// Retry settings
	MaxRetries        int
	RetryDelaySeconds int

	// Timestamps
	CreatedAt time.Time
}

// NewStep creates a new workflow step.
func NewStep(
	scanWorkflowID shared.ID,
	stepKey string,
	name string,
	order int,
	capabilities []string,
) (*Step, error) {
	if stepKey == "" {
		return nil, shared.NewDomainError("VALIDATION", "step_key is required", shared.ErrValidation)
	}
	if name == "" {
		name = stepKey
	}
	if len(capabilities) == 0 {
		return nil, shared.NewDomainError("VALIDATION", "at least one capability is required", shared.ErrValidation)
	}

	return &Step{
		ID:                shared.NewID(),
		ScanWorkflowID:    scanWorkflowID,
		StepKey:           stepKey,
		Name:              name,
		StepOrder:         order,
		UIPosition:        UIPosition{X: 0, Y: float64(order * 150)}, // Default vertical layout
		Capabilities:      capabilities,
		Config:            make(map[string]any),
		TimeoutSeconds:    1800, // 30 minutes default
		DependsOn:         []string{},
		Condition:         AlwaysCondition(),
		MaxRetries:        0,
		RetryDelaySeconds: 60,
		CreatedAt:         time.Now(),
	}, nil
}

// SetTool sets the preferred tool for the step.
func (s *Step) SetTool(tool string) {
	s.Tool = tool
}

// ToolSelection is how a step picks its tool.
type ToolSelection string

const (
	ToolSelectionAuto   ToolSelection = "auto"
	ToolSelectionPrefer ToolSelection = "prefer"
	ToolSelectionPin    ToolSelection = "pin"
)

// Selection is the step's tool selection mode: pin when it names a tool,
// prefer when it lists tools to try, auto otherwise.
func (s *Step) Selection() ToolSelection {
	switch {
	case strings.TrimSpace(s.Tool) != "":
		return ToolSelectionPin
	case len(s.PreferTools) > 0:
		return ToolSelectionPrefer
	}
	return ToolSelectionAuto
}

// SetToolID sets the preferred tool ID (FK reference to tools table).
func (s *Step) SetToolID(id *shared.ID) {
	s.ToolID = id
}

// SetConfig sets the step configuration.
func (s *Step) SetConfig(config map[string]any) {
	s.Config = config
}

// SetTimeout sets the timeout in seconds with validation.
// Returns error if timeout is out of valid range [60, 86400].
func (s *Step) SetTimeout(seconds int) error {
	if seconds < MinTimeoutSeconds {
		return shared.NewDomainError("VALIDATION",
			fmt.Sprintf("timeout must be at least %d seconds (1 minute)", MinTimeoutSeconds),
			shared.ErrValidation)
	}
	if seconds > MaxTimeoutSeconds {
		return shared.NewDomainError("VALIDATION",
			fmt.Sprintf("timeout cannot exceed %d seconds (24 hours)", MaxTimeoutSeconds),
			shared.ErrValidation)
	}
	s.TimeoutSeconds = seconds
	return nil
}

// AddDependency adds a dependency on another step.
func (s *Step) AddDependency(stepKey string) {
	s.DependsOn = append(s.DependsOn, stepKey)
}

// SetDependencies sets the step dependencies.
func (s *Step) SetDependencies(stepKeys []string) {
	s.DependsOn = stepKeys
}

// SetCondition sets the execution condition with validation.
// Returns error if the condition type is not yet supported.
func (s *Step) SetCondition(condition Condition) error {
	if !condition.Type.IsValid() {
		return shared.NewDomainError("VALIDATION",
			fmt.Sprintf("invalid condition type: %s", condition.Type),
			shared.ErrValidation)
	}

	// Expression conditions are defined but not yet implemented in evaluateCondition()
	// Block them at creation time to prevent silent bypass
	if condition.Type == ConditionTypeExpression {
		return shared.NewDomainError("VALIDATION",
			"expression conditions are not yet supported; use 'always', 'never', 'asset_type', or 'step_result'",
			shared.ErrValidation)
	}

	s.Condition = condition
	return nil
}

// SetRetry sets the retry configuration.
func (s *Step) SetRetry(maxRetries, delaySeconds int) {
	s.MaxRetries = maxRetries
	s.RetryDelaySeconds = delaySeconds
}

// MaxUIPosition bounds a builder coordinate (either sign).
const MaxUIPosition = 1_000_000

// SetUIPosition sets the step's place on the builder canvas. The canvas
// works in fractional and negative coordinates; the stored layout keeps
// whole numbers, so the position is rounded. A coordinate that is not a
// finite number within MaxUIPosition is refused (it would fail the
// integer column with a server error).
func (s *Step) SetUIPosition(x, y float64) error {
	for _, v := range []float64{x, y} {
		if math.IsNaN(v) || math.IsInf(v, 0) || math.Abs(v) > MaxUIPosition {
			return fmt.Errorf("%w: a step position must be a number between -%d and %d", shared.ErrValidation, MaxUIPosition, MaxUIPosition)
		}
	}
	s.UIPosition = UIPosition{X: math.Round(x), Y: math.Round(y)}
	return nil
}

// HasDependencies checks if the step has dependencies.
func (s *Step) HasDependencies() bool {
	return len(s.DependsOn) > 0
}

// ShouldAlwaysRun checks if the step should always run.
func (s *Step) ShouldAlwaysRun() bool {
	return s.Condition.Type == ConditionTypeAlways
}

// IsDisabled checks if the step is disabled.
func (s *Step) IsDisabled() bool {
	return s.Condition.Type == ConditionTypeNever
}

// Clone creates a copy of the step with a new ID.
func (s *Step) Clone() *Step {
	clone := &Step{
		ID:                shared.NewID(),
		ScanWorkflowID:    s.ScanWorkflowID,
		StepKey:           s.StepKey,
		Name:              s.Name,
		Description:       s.Description,
		StepOrder:         s.StepOrder,
		UIPosition:        s.UIPosition,
		Tool:              s.Tool,
		ToolID:            s.ToolID,
		Capabilities:      make([]string, len(s.Capabilities)),
		Config:            make(map[string]any),
		TimeoutSeconds:    s.TimeoutSeconds,
		DependsOn:         make([]string, len(s.DependsOn)),
		Condition:         s.Condition,
		MaxRetries:        s.MaxRetries,
		RetryDelaySeconds: s.RetryDelaySeconds,
		CreatedAt:         time.Now(),
	}

	copy(clone.Capabilities, s.Capabilities)
	copy(clone.DependsOn, s.DependsOn)

	// Deep copy config
	for k, v := range s.Config {
		clone.Config[k] = v
	}

	return clone
}

// ConditionMet reports whether the step's condition allows it to run in run.
// One implementation for every scheduler (the scan run service and a scan's
// workflow trigger); the scan path used to ignore conditions entirely.
//
// A condition that cannot be evaluated never passes (research/27 F2): an
// "expression" condition used to be true whatever it said, so a step meant
// to run only sometimes always ran. Such a step is skipped with
// ConditionSkipReason saying why. SetCondition refuses expressions; this
// covers rows stored before that check and any unknown type.
func (s *Step) ConditionMet(run RunView) bool {
	switch s.Condition.Type {
	case ConditionTypeAlways, "":
		return true
	case ConditionTypeNever:
		return false
	case ConditionTypeAssetType:
		assetType, ok := run.ContextValue("asset_type").(string)
		return ok && assetType == s.Condition.Value
	case ConditionTypeStepResult:
		return run.StepSucceeded(s.Condition.Value)
	default: // expression (not evaluated) or a type this version does not know
		return false
	}
}

// ConditionUnsupported reports whether the step's condition is one the
// scheduler cannot evaluate (and so never passes).
func (s *Step) ConditionUnsupported() bool {
	switch s.Condition.Type {
	case ConditionTypeAlways, "", ConditionTypeNever, ConditionTypeAssetType, ConditionTypeStepResult:
		return false
	}
	return true
}

// ConditionSkipReason is the skip reason of a step whose condition did not
// pass.
func (s *Step) ConditionSkipReason() string {
	if s.ConditionUnsupported() {
		return fmt.Sprintf("Condition type %q cannot be evaluated; the step never runs. Edit the step to use always, never, asset_type or step_result.", s.Condition.Type)
	}
	return "Condition not met"
}

// BlockedByDependency returns the first dependency of the step that finished
// without producing results (failed, skipped, timed out, canceled), or "".
// Such a step can never run: its dependency will not succeed any more. A
// partial dependency does not block: its results are kept.
func (s *Step) BlockedByDependency(run RunView) string {
	for _, dep := range s.DependsOn {
		if run.StepFinishedWithoutResults(dep) {
			return dep
		}
	}
	return ""
}

// RunView is what a step reads from the run it belongs to when it decides
// whether it can run.
type RunView interface {
	// ContextValue returns a value of the run context, or nil.
	ContextValue(key string) any
	// StepSucceeded reports whether the step run of stepKey succeeded.
	StepSucceeded(stepKey string) bool
	// StepFinishedWithoutResults reports whether the step run of stepKey
	// finished without producing results (failed, skipped, timed out,
	// canceled).
	StepFinishedWithoutResults(stepKey string) bool
}
