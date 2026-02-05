package pipeline_test

import (
	"testing"

	"github.com/openctemio/api/pkg/domain/pipeline"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
