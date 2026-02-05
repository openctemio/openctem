// Package pipeline defines the Pipeline domain entities for scan orchestration.
package pipeline

import (
	"strings"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// TriggerType represents how a pipeline can be triggered.
type TriggerType string

const (
	TriggerTypeManual           TriggerType = "manual"
	TriggerTypeSchedule         TriggerType = "schedule"
	TriggerTypeWebhook          TriggerType = "webhook"
	TriggerTypeAPI              TriggerType = "api"
	TriggerTypeOnAssetDiscovery TriggerType = "on_asset_discovery"
)

// Trigger represents a pipeline trigger configuration.
type Trigger struct {
	Type     TriggerType    `json:"type"`
	Schedule string         `json:"schedule,omitempty"` // Cron expression
	Webhook  string         `json:"webhook,omitempty"`  // Webhook name/path
	Filters  map[string]any `json:"filters,omitempty"`  // Asset filters
}

// AgentPreference determines which agents can execute the pipeline.
type AgentPreference string

const (
	// AgentPreferenceAuto tries tenant agents first, falls back to platform.
	AgentPreferenceAuto AgentPreference = "auto"
	// AgentPreferenceTenant only uses tenant's own agents.
	AgentPreferenceTenant AgentPreference = "tenant"
	// AgentPreferencePlatform only uses platform agents.
	AgentPreferencePlatform AgentPreference = "platform"
)

// Settings represents pipeline execution settings.
type Settings struct {
	MaxParallelSteps     int             `json:"max_parallel_steps,omitempty"`
	FailFast             bool            `json:"fail_fast,omitempty"`
	RetryFailedSteps     int             `json:"retry_failed_steps,omitempty"`
	TimeoutSeconds       int             `json:"timeout_seconds,omitempty"`
	NotifyOnComplete     bool            `json:"notify_on_complete,omitempty"`
	NotifyOnFailure      bool            `json:"notify_on_failure,omitempty"`
	NotificationChannels []string        `json:"notification_channels,omitempty"`
	AgentPreference      AgentPreference `json:"agent_preference,omitempty"` // Agent selection mode: auto, tenant, platform
}

// DefaultSettings returns default pipeline settings.
func DefaultSettings() Settings {
	return Settings{
		MaxParallelSteps: 3,
		FailFast:         false,
		RetryFailedSteps: 0,
		TimeoutSeconds:   7200, // 2 hours
		NotifyOnComplete: false,
		NotifyOnFailure:  true,
		AgentPreference:  AgentPreferenceAuto,
	}
}

// Template represents a reusable pipeline definition.
type Template struct {
	ID          shared.ID
	TenantID    shared.ID
	Name        string
	Description string
	Version     int

	// Configuration
	Triggers []Trigger
	Settings Settings

	// Status
	IsActive         bool
	IsSystemTemplate bool

	// Metadata
	Tags []string

	// Visual Builder UI positions for Start/End nodes
	UIStartPosition *UIPosition
	UIEndPosition   *UIPosition

	// Steps (loaded separately)
	Steps []*Step

	// Audit
	CreatedBy *shared.ID
	CreatedAt time.Time
	UpdatedAt time.Time
}

// NewTemplate creates a new pipeline template.
func NewTemplate(tenantID shared.ID, name, description string) (*Template, error) {
	if name == "" {
		return nil, shared.NewDomainError("VALIDATION", "name is required", shared.ErrValidation)
	}

	now := time.Now()
	return &Template{
		ID:          shared.NewID(),
		TenantID:    tenantID,
		Name:        name,
		Description: description,
		Version:     1,
		Triggers:    []Trigger{{Type: TriggerTypeManual}},
		Settings:    DefaultSettings(),
		IsActive:    true,
		Tags:        []string{},
		Steps:       []*Step{},
		CreatedAt:   now,
		UpdatedAt:   now,
	}, nil
}

// SetCreatedBy sets the user who created the template.
func (t *Template) SetCreatedBy(userID shared.ID) {
	t.CreatedBy = &userID
}

// SetUIStartPosition sets the visual builder Start node position.
func (t *Template) SetUIStartPosition(pos *UIPosition) {
	t.UIStartPosition = pos
	t.UpdatedAt = time.Now()
}

// SetUIEndPosition sets the visual builder End node position.
func (t *Template) SetUIEndPosition(pos *UIPosition) {
	t.UIEndPosition = pos
	t.UpdatedAt = time.Now()
}

// AddTrigger adds a trigger to the template.
func (t *Template) AddTrigger(trigger Trigger) {
	t.Triggers = append(t.Triggers, trigger)
	t.UpdatedAt = time.Now()
}

// SetSettings sets the pipeline settings.
func (t *Template) SetSettings(settings Settings) {
	t.Settings = settings
	t.UpdatedAt = time.Now()
}

// Activate activates the template.
func (t *Template) Activate() {
	t.IsActive = true
	t.UpdatedAt = time.Now()
}

// Deactivate deactivates the template.
func (t *Template) Deactivate() {
	t.IsActive = false
	t.UpdatedAt = time.Now()
}

// IncrementVersion increments the template version.
func (t *Template) IncrementVersion() {
	t.Version++
	t.UpdatedAt = time.Now()
}

// AddStep adds a step to the template.
func (t *Template) AddStep(step *Step) {
	step.PipelineID = t.ID
	t.Steps = append(t.Steps, step)
	t.UpdatedAt = time.Now()
}

// GetStepByKey returns a step by its key.
func (t *Template) GetStepByKey(key string) *Step {
	for _, s := range t.Steps {
		if s.StepKey == key {
			return s
		}
	}
	return nil
}

// ValidateSteps validates the step configuration.
func (t *Template) ValidateSteps() error {
	stepKeys := make(map[string]bool)

	for _, step := range t.Steps {
		// Check for duplicate keys
		if stepKeys[step.StepKey] {
			return shared.NewDomainError("VALIDATION", "duplicate step key: "+step.StepKey, shared.ErrValidation)
		}
		stepKeys[step.StepKey] = true
	}

	// Validate dependencies exist
	for _, step := range t.Steps {
		for _, depKey := range step.DependsOn {
			if !stepKeys[depKey] {
				return shared.NewDomainError("VALIDATION", "unknown dependency: "+depKey+" in step "+step.StepKey, shared.ErrValidation)
			}
		}
	}

	// Check for circular dependencies using DFS with 3-color marking
	if err := t.detectCircularDependencies(); err != nil {
		return err
	}

	return nil
}

// detectCircularDependencies detects circular dependencies in steps using DFS.
// Uses 3-color marking: 0=unvisited, 1=visiting (in current path), 2=visited (complete).
// Returns error if a cycle is detected.
func (t *Template) detectCircularDependencies() error {
	if len(t.Steps) == 0 {
		return nil
	}

	// Build adjacency list: step -> dependencies
	deps := make(map[string][]string)
	for _, step := range t.Steps {
		deps[step.StepKey] = step.DependsOn
	}

	// Track visit state: 0=unvisited, 1=visiting, 2=visited
	visited := make(map[string]int)

	// Track the path for better error messages
	var currentPath []string

	var visit func(key string) error
	visit = func(key string) error {
		if visited[key] == 1 {
			// Found cycle - build error message with the cycle path
			cycleStart := 0
			for i, k := range currentPath {
				if k == key {
					cycleStart = i
					break
				}
			}
			cyclePath := append(currentPath[cycleStart:], key)
			return shared.NewDomainError("VALIDATION",
				"circular dependency detected: "+joinStepKeys(cyclePath, " → "),
				shared.ErrValidation)
		}
		if visited[key] == 2 {
			return nil // Already fully visited
		}

		visited[key] = 1 // Mark as visiting
		currentPath = append(currentPath, key)

		for _, dep := range deps[key] {
			if err := visit(dep); err != nil {
				return err
			}
		}

		visited[key] = 2 // Mark as fully visited
		currentPath = currentPath[:len(currentPath)-1]
		return nil
	}

	// Visit all steps (handles disconnected subgraphs)
	for key := range deps {
		if visited[key] == 0 {
			if err := visit(key); err != nil {
				return err
			}
		}
	}

	return nil
}

// joinStepKeys joins step keys with a separator for error messages.
func joinStepKeys(keys []string, sep string) string {
	if len(keys) == 0 {
		return ""
	}
	if len(keys) == 1 {
		return keys[0]
	}
	// Use strings.Join for efficiency
	var builder strings.Builder
	builder.WriteString(keys[0])
	for i := 1; i < len(keys); i++ {
		builder.WriteString(sep)
		builder.WriteString(keys[i])
	}
	return builder.String()
}

// GetRunnableSteps returns steps that can be run (no pending dependencies).
func (t *Template) GetRunnableSteps(completedSteps map[string]bool) []*Step {
	var runnable []*Step
	for _, step := range t.Steps {
		if completedSteps[step.StepKey] {
			continue
		}

		canRun := true
		for _, depKey := range step.DependsOn {
			if !completedSteps[depKey] {
				canRun = false
				break
			}
		}

		if canRun {
			runnable = append(runnable, step)
		}
	}
	return runnable
}

// Clone creates a copy of the template with a new ID.
func (t *Template) Clone(newName string) *Template {
	now := time.Now()
	clone := &Template{
		ID:               shared.NewID(),
		TenantID:         t.TenantID,
		Name:             newName,
		Description:      t.Description,
		Version:          1,
		Triggers:         make([]Trigger, len(t.Triggers)),
		Settings:         t.Settings,
		IsActive:         true,
		IsSystemTemplate: false,
		Tags:             make([]string, len(t.Tags)),
		CreatedAt:        now,
		UpdatedAt:        now,
	}

	copy(clone.Triggers, t.Triggers)
	copy(clone.Tags, t.Tags)

	// Clone UI positions
	if t.UIStartPosition != nil {
		clone.UIStartPosition = &UIPosition{X: t.UIStartPosition.X, Y: t.UIStartPosition.Y}
	}
	if t.UIEndPosition != nil {
		clone.UIEndPosition = &UIPosition{X: t.UIEndPosition.X, Y: t.UIEndPosition.Y}
	}

	// Clone steps
	clone.Steps = make([]*Step, len(t.Steps))
	for i, step := range t.Steps {
		clone.Steps[i] = step.Clone()
		clone.Steps[i].PipelineID = clone.ID
	}

	return clone
}
