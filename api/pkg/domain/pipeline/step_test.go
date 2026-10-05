package pipeline_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openctemio/openctem/api/pkg/domain/pipeline"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestStep_SetTimeout_Validation(t *testing.T) {
	pipelineID := shared.NewID()

	t.Run("valid timeout - minimum", func(t *testing.T) {
		step, err := pipeline.NewStep(pipelineID, "test-step", "Test Step", 1, []string{"scan"})
		require.NoError(t, err)

		err = step.SetTimeout(60) // 1 minute - minimum allowed
		assert.NoError(t, err)
		assert.Equal(t, 60, step.TimeoutSeconds)
	})

	t.Run("valid timeout - maximum", func(t *testing.T) {
		step, err := pipeline.NewStep(pipelineID, "test-step", "Test Step", 1, []string{"scan"})
		require.NoError(t, err)

		err = step.SetTimeout(86400) // 24 hours - maximum allowed
		assert.NoError(t, err)
		assert.Equal(t, 86400, step.TimeoutSeconds)
	})

	t.Run("valid timeout - typical value", func(t *testing.T) {
		step, err := pipeline.NewStep(pipelineID, "test-step", "Test Step", 1, []string{"scan"})
		require.NoError(t, err)

		err = step.SetTimeout(3600) // 1 hour
		assert.NoError(t, err)
		assert.Equal(t, 3600, step.TimeoutSeconds)
	})

	t.Run("invalid timeout - below minimum", func(t *testing.T) {
		step, err := pipeline.NewStep(pipelineID, "test-step", "Test Step", 1, []string{"scan"})
		require.NoError(t, err)

		err = step.SetTimeout(59) // Below minimum
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "at least 60 seconds")
	})

	t.Run("invalid timeout - zero", func(t *testing.T) {
		step, err := pipeline.NewStep(pipelineID, "test-step", "Test Step", 1, []string{"scan"})
		require.NoError(t, err)

		err = step.SetTimeout(0)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "at least 60 seconds")
	})

	t.Run("invalid timeout - above maximum", func(t *testing.T) {
		step, err := pipeline.NewStep(pipelineID, "test-step", "Test Step", 1, []string{"scan"})
		require.NoError(t, err)

		err = step.SetTimeout(86401) // Above maximum
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "cannot exceed")
	})

	t.Run("invalid timeout - way above maximum", func(t *testing.T) {
		step, err := pipeline.NewStep(pipelineID, "test-step", "Test Step", 1, []string{"scan"})
		require.NoError(t, err)

		err = step.SetTimeout(999999999)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "cannot exceed")
	})
}

func TestStep_SetCondition_Validation(t *testing.T) {
	pipelineID := shared.NewID()

	t.Run("valid condition - always", func(t *testing.T) {
		step, err := pipeline.NewStep(pipelineID, "test-step", "Test Step", 1, []string{"scan"})
		require.NoError(t, err)

		err = step.SetCondition(pipeline.AlwaysCondition())
		assert.NoError(t, err)
		assert.Equal(t, pipeline.ConditionTypeAlways, step.Condition.Type)
	})

	t.Run("valid condition - never", func(t *testing.T) {
		step, err := pipeline.NewStep(pipelineID, "test-step", "Test Step", 1, []string{"scan"})
		require.NoError(t, err)

		err = step.SetCondition(pipeline.NeverCondition())
		assert.NoError(t, err)
		assert.Equal(t, pipeline.ConditionTypeNever, step.Condition.Type)
	})

	t.Run("valid condition - asset_type", func(t *testing.T) {
		step, err := pipeline.NewStep(pipelineID, "test-step", "Test Step", 1, []string{"scan"})
		require.NoError(t, err)

		err = step.SetCondition(pipeline.AssetTypeCondition("domain"))
		assert.NoError(t, err)
		assert.Equal(t, pipeline.ConditionTypeAssetType, step.Condition.Type)
		assert.Equal(t, "domain", step.Condition.Value)
	})

	t.Run("valid condition - step_result", func(t *testing.T) {
		step, err := pipeline.NewStep(pipelineID, "test-step", "Test Step", 1, []string{"scan"})
		require.NoError(t, err)

		err = step.SetCondition(pipeline.Condition{
			Type:  pipeline.ConditionTypeStepResult,
			Value: "previous-step",
		})
		assert.NoError(t, err)
		assert.Equal(t, pipeline.ConditionTypeStepResult, step.Condition.Type)
	})

	t.Run("blocked condition - expression (not yet implemented)", func(t *testing.T) {
		step, err := pipeline.NewStep(pipelineID, "test-step", "Test Step", 1, []string{"scan"})
		require.NoError(t, err)

		err = step.SetCondition(pipeline.ExpressionCondition("${step.output} == 'success'"))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "expression conditions are not yet supported")
	})

	t.Run("invalid condition - unknown type", func(t *testing.T) {
		step, err := pipeline.NewStep(pipelineID, "test-step", "Test Step", 1, []string{"scan"})
		require.NoError(t, err)

		err = step.SetCondition(pipeline.Condition{
			Type: pipeline.ConditionType("invalid_type"),
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid condition type")
	})
}

func TestStep_NewStep_Defaults(t *testing.T) {
	pipelineID := shared.NewID()

	step, err := pipeline.NewStep(pipelineID, "test-step", "Test Step", 1, []string{"scan"})
	require.NoError(t, err)

	// Check defaults
	assert.Equal(t, 1800, step.TimeoutSeconds) // 30 minutes default
	assert.Equal(t, pipeline.ConditionTypeAlways, step.Condition.Type)
	assert.Equal(t, 0, step.MaxRetries)
	assert.Equal(t, 60, step.RetryDelaySeconds)
	assert.Empty(t, step.DependsOn)
}

// research/27 F2: a condition the scheduler cannot evaluate never passes.
// An expression condition used to be true whatever it said, so a step meant
// to run only sometimes always ran. Rows stored before SetCondition refused
// expressions still exist; they are skipped with a reason that says why.
func TestConditionMet_UnevaluableConditionsNeverPass(t *testing.T) {
	run := &pipeline.Run{Context: map[string]any{"asset_type": "domain"}}
	for _, c := range []pipeline.Condition{
		{Type: pipeline.ConditionTypeExpression, Value: "true"},
		{Type: pipeline.ConditionTypeExpression, Value: ""},
		{Type: "cel", Value: "1 == 1"},
	} {
		s := &pipeline.Step{StepKey: "x", Condition: c}
		if s.ConditionMet(run) {
			t.Errorf("%s condition passed", c.Type)
		}
		if !s.ConditionUnsupported() || !strings.Contains(s.ConditionSkipReason(), "cannot be evaluated") {
			t.Errorf("%s: reason %q", c.Type, s.ConditionSkipReason())
		}
	}
	for _, c := range []pipeline.Condition{pipeline.AlwaysCondition(), {}, pipeline.AssetTypeCondition("domain")} {
		s := &pipeline.Step{StepKey: "y", Condition: c}
		if !s.ConditionMet(run) || s.ConditionUnsupported() {
			t.Errorf("%q condition did not pass", c.Type)
		}
	}
	never := &pipeline.Step{Condition: pipeline.NeverCondition()}
	if never.ConditionMet(run) || never.ConditionSkipReason() != "Condition not met" {
		t.Error("never condition")
	}
	if err := (&pipeline.Step{}).SetCondition(pipeline.ExpressionCondition("x")); err == nil {
		t.Error("an expression condition was accepted")
	}
}
