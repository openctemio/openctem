package pipeline

import (
	"fmt"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
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

// Step represents a single step in a pipeline.
type Step struct {
	ID         shared.ID
	PipelineID shared.ID

	// Step definition
	StepKey     string
	Name        string
	Description string
	StepOrder   int

	// Visual workflow builder
	UIPosition UIPosition

	// Tool requirements
	Tool         string   // Preferred tool (optional)
	Capabilities []string // Required capabilities

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

// NewStep creates a new pipeline step.
func NewStep(
	pipelineID shared.ID,
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
		PipelineID:        pipelineID,
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

// SetUIPosition sets the visual position for the workflow builder.
func (s *Step) SetUIPosition(x, y float64) {
	s.UIPosition = UIPosition{X: x, Y: y}
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
		PipelineID:        s.PipelineID,
		StepKey:           s.StepKey,
		Name:              s.Name,
		Description:       s.Description,
		StepOrder:         s.StepOrder,
		UIPosition:        s.UIPosition,
		Tool:              s.Tool,
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
