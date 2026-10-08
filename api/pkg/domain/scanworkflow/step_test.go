package scanworkflow_test

import (
	"math"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestStep_SetTimeout_Validation(t *testing.T) {
	scanWorkflowID := shared.NewID()

	t.Run("valid timeout - minimum", func(t *testing.T) {
		step, err := scanworkflow.NewStep(scanWorkflowID, "test-step", "Test Step", 1, []string{"scan"})
		require.NoError(t, err)

		err = step.SetTimeout(60) // 1 minute - minimum allowed
		assert.NoError(t, err)
		assert.Equal(t, 60, step.TimeoutSeconds)
	})

	t.Run("valid timeout - maximum", func(t *testing.T) {
		step, err := scanworkflow.NewStep(scanWorkflowID, "test-step", "Test Step", 1, []string{"scan"})
		require.NoError(t, err)

		err = step.SetTimeout(86400) // 24 hours - maximum allowed
		assert.NoError(t, err)
		assert.Equal(t, 86400, step.TimeoutSeconds)
	})

	t.Run("valid timeout - typical value", func(t *testing.T) {
		step, err := scanworkflow.NewStep(scanWorkflowID, "test-step", "Test Step", 1, []string{"scan"})
		require.NoError(t, err)

		err = step.SetTimeout(3600) // 1 hour
		assert.NoError(t, err)
		assert.Equal(t, 3600, step.TimeoutSeconds)
	})

	t.Run("invalid timeout - below minimum", func(t *testing.T) {
		step, err := scanworkflow.NewStep(scanWorkflowID, "test-step", "Test Step", 1, []string{"scan"})
		require.NoError(t, err)

		err = step.SetTimeout(59) // Below minimum
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "at least 60 seconds")
	})

	t.Run("invalid timeout - zero", func(t *testing.T) {
		step, err := scanworkflow.NewStep(scanWorkflowID, "test-step", "Test Step", 1, []string{"scan"})
		require.NoError(t, err)

		err = step.SetTimeout(0)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "at least 60 seconds")
	})

	t.Run("invalid timeout - above maximum", func(t *testing.T) {
		step, err := scanworkflow.NewStep(scanWorkflowID, "test-step", "Test Step", 1, []string{"scan"})
		require.NoError(t, err)

		err = step.SetTimeout(86401) // Above maximum
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "cannot exceed")
	})

	t.Run("invalid timeout - way above maximum", func(t *testing.T) {
		step, err := scanworkflow.NewStep(scanWorkflowID, "test-step", "Test Step", 1, []string{"scan"})
		require.NoError(t, err)

		err = step.SetTimeout(999999999)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "cannot exceed")
	})
}

func TestStep_SetCondition_Validation(t *testing.T) {
	scanWorkflowID := shared.NewID()

	t.Run("valid condition - always", func(t *testing.T) {
		step, err := scanworkflow.NewStep(scanWorkflowID, "test-step", "Test Step", 1, []string{"scan"})
		require.NoError(t, err)

		err = step.SetCondition(scanworkflow.AlwaysCondition())
		assert.NoError(t, err)
		assert.Equal(t, scanworkflow.ConditionTypeAlways, step.Condition.Type)
	})

	t.Run("valid condition - never", func(t *testing.T) {
		step, err := scanworkflow.NewStep(scanWorkflowID, "test-step", "Test Step", 1, []string{"scan"})
		require.NoError(t, err)

		err = step.SetCondition(scanworkflow.NeverCondition())
		assert.NoError(t, err)
		assert.Equal(t, scanworkflow.ConditionTypeNever, step.Condition.Type)
	})

	t.Run("valid condition - asset_type", func(t *testing.T) {
		step, err := scanworkflow.NewStep(scanWorkflowID, "test-step", "Test Step", 1, []string{"scan"})
		require.NoError(t, err)

		err = step.SetCondition(scanworkflow.AssetTypeCondition("domain"))
		assert.NoError(t, err)
		assert.Equal(t, scanworkflow.ConditionTypeAssetType, step.Condition.Type)
		assert.Equal(t, "domain", step.Condition.Value)
	})

	t.Run("valid condition - step_result", func(t *testing.T) {
		step, err := scanworkflow.NewStep(scanWorkflowID, "test-step", "Test Step", 1, []string{"scan"})
		require.NoError(t, err)

		err = step.SetCondition(scanworkflow.Condition{
			Type:  scanworkflow.ConditionTypeStepResult,
			Value: "previous-step",
		})
		assert.NoError(t, err)
		assert.Equal(t, scanworkflow.ConditionTypeStepResult, step.Condition.Type)
	})

	t.Run("blocked condition - expression (not yet implemented)", func(t *testing.T) {
		step, err := scanworkflow.NewStep(scanWorkflowID, "test-step", "Test Step", 1, []string{"scan"})
		require.NoError(t, err)

		err = step.SetCondition(scanworkflow.ExpressionCondition("${step.output} == 'success'"))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "expression conditions are not yet supported")
	})

	t.Run("invalid condition - unknown type", func(t *testing.T) {
		step, err := scanworkflow.NewStep(scanWorkflowID, "test-step", "Test Step", 1, []string{"scan"})
		require.NoError(t, err)

		err = step.SetCondition(scanworkflow.Condition{
			Type: scanworkflow.ConditionType("invalid_type"),
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid condition type")
	})
}

func TestStep_NewStep_Defaults(t *testing.T) {
	scanWorkflowID := shared.NewID()

	step, err := scanworkflow.NewStep(scanWorkflowID, "test-step", "Test Step", 1, []string{"scan"})
	require.NoError(t, err)

	// Check defaults
	assert.Equal(t, 1800, step.TimeoutSeconds) // 30 minutes default
	assert.Equal(t, scanworkflow.ConditionTypeAlways, step.Condition.Type)
	assert.Equal(t, 0, step.MaxRetries)
	assert.Equal(t, 60, step.RetryDelaySeconds)
	assert.Empty(t, step.DependsOn)
}

// research/27 F2: a condition the scheduler cannot evaluate never passes.
// An expression condition used to be true whatever it said, so a step meant
// to run only sometimes always ran. Rows stored before SetCondition refused
// expressions still exist; they are skipped with a reason that says why.
func TestConditionMet_UnevaluableConditionsNeverPass(t *testing.T) {
	run := &scanrun.Run{Context: map[string]any{"asset_type": "domain"}}
	for _, c := range []scanworkflow.Condition{
		{Type: scanworkflow.ConditionTypeExpression, Value: "true"},
		{Type: scanworkflow.ConditionTypeExpression, Value: ""},
		{Type: "cel", Value: "1 == 1"},
	} {
		s := &scanworkflow.Step{StepKey: "x", Condition: c}
		if s.ConditionMet(run) {
			t.Errorf("%s condition passed", c.Type)
		}
		if !s.ConditionUnsupported() || !strings.Contains(s.ConditionSkipReason(), "cannot be evaluated") {
			t.Errorf("%s: reason %q", c.Type, s.ConditionSkipReason())
		}
	}
	for _, c := range []scanworkflow.Condition{scanworkflow.AlwaysCondition(), {}, scanworkflow.AssetTypeCondition("domain")} {
		s := &scanworkflow.Step{StepKey: "y", Condition: c}
		if !s.ConditionMet(run) || s.ConditionUnsupported() {
			t.Errorf("%q condition did not pass", c.Type)
		}
	}
	never := &scanworkflow.Step{Condition: scanworkflow.NeverCondition()}
	if never.ConditionMet(run) || never.ConditionSkipReason() != "Condition not met" {
		t.Error("never condition")
	}
	if err := (&scanworkflow.Step{}).SetCondition(scanworkflow.ExpressionCondition("x")); err == nil {
		t.Error("an expression condition was accepted")
	}
}

// The builder canvas sends fractional and negative positions; the stored
// layout is whole numbers. A non-finite or absurd coordinate is a
// validation error, never a server error.
func TestStep_SetUIPosition(t *testing.T) {
	s, err := scanworkflow.NewStep(shared.NewID(), "ports", "Ports", 1, []string{"scan.ports"})
	require.NoError(t, err)

	require.NoError(t, s.SetUIPosition(-307.4222108759977, 120.5))
	assert.Equal(t, scanworkflow.UIPosition{X: -307, Y: 121}, s.UIPosition)

	for _, bad := range [][2]float64{
		{math.NaN(), 0}, {0, math.Inf(1)}, {math.Inf(-1), 0}, {2e6, 0}, {0, -1e300},
	} {
		err := s.SetUIPosition(bad[0], bad[1])
		assert.ErrorIs(t, err, shared.ErrValidation, "%v", bad)
	}
	assert.Equal(t, scanworkflow.UIPosition{X: -307, Y: 121}, s.UIPosition, "a refused position changes nothing")
}
