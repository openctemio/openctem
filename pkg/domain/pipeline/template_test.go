package pipeline_test

import (
	"testing"

	"github.com/openctemio/api/pkg/domain/pipeline"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTemplate_ValidateSteps_CircularDependency(t *testing.T) {
	tenantID := shared.NewID()

	t.Run("no circular dependency - linear chain", func(t *testing.T) {
		template, err := pipeline.NewTemplate(tenantID, "Test Pipeline", "Linear chain")
		require.NoError(t, err)

		// A -> B -> C (linear chain, no cycle)
		stepA := createStep(t, template.ID, "step-a", []string{"scan"})
		stepB := createStep(t, template.ID, "step-b", []string{"scan"})
		stepB.SetDependencies([]string{"step-a"})
		stepC := createStep(t, template.ID, "step-c", []string{"scan"})
		stepC.SetDependencies([]string{"step-b"})

		template.AddStep(stepA)
		template.AddStep(stepB)
		template.AddStep(stepC)

		err = template.ValidateSteps()
		assert.NoError(t, err)
	})

	t.Run("no circular dependency - diamond shape", func(t *testing.T) {
		template, err := pipeline.NewTemplate(tenantID, "Test Pipeline", "Diamond shape")
		require.NoError(t, err)

		// Diamond: A -> B,C -> D (no cycle)
		//     A
		//    / \
		//   B   C
		//    \ /
		//     D
		stepA := createStep(t, template.ID, "step-a", []string{"scan"})
		stepB := createStep(t, template.ID, "step-b", []string{"scan"})
		stepB.SetDependencies([]string{"step-a"})
		stepC := createStep(t, template.ID, "step-c", []string{"scan"})
		stepC.SetDependencies([]string{"step-a"})
		stepD := createStep(t, template.ID, "step-d", []string{"scan"})
		stepD.SetDependencies([]string{"step-b", "step-c"})

		template.AddStep(stepA)
		template.AddStep(stepB)
		template.AddStep(stepC)
		template.AddStep(stepD)

		err = template.ValidateSteps()
		assert.NoError(t, err)
	})

	t.Run("circular dependency - self reference", func(t *testing.T) {
		template, err := pipeline.NewTemplate(tenantID, "Test Pipeline", "Self reference")
		require.NoError(t, err)

		// A -> A (self reference)
		stepA := createStep(t, template.ID, "step-a", []string{"scan"})
		stepA.SetDependencies([]string{"step-a"})

		template.AddStep(stepA)

		err = template.ValidateSteps()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "circular dependency detected")
		assert.Contains(t, err.Error(), "step-a")
	})

	t.Run("circular dependency - two step cycle", func(t *testing.T) {
		template, err := pipeline.NewTemplate(tenantID, "Test Pipeline", "Two step cycle")
		require.NoError(t, err)

		// A -> B -> A (two step cycle)
		stepA := createStep(t, template.ID, "step-a", []string{"scan"})
		stepB := createStep(t, template.ID, "step-b", []string{"scan"})
		stepA.SetDependencies([]string{"step-b"})
		stepB.SetDependencies([]string{"step-a"})

		template.AddStep(stepA)
		template.AddStep(stepB)

		err = template.ValidateSteps()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "circular dependency detected")
	})

	t.Run("circular dependency - three step cycle", func(t *testing.T) {
		template, err := pipeline.NewTemplate(tenantID, "Test Pipeline", "Three step cycle")
		require.NoError(t, err)

		// A -> B -> C -> A (three step cycle)
		stepA := createStep(t, template.ID, "step-a", []string{"scan"})
		stepB := createStep(t, template.ID, "step-b", []string{"scan"})
		stepC := createStep(t, template.ID, "step-c", []string{"scan"})
		stepA.SetDependencies([]string{"step-c"})
		stepB.SetDependencies([]string{"step-a"})
		stepC.SetDependencies([]string{"step-b"})

		template.AddStep(stepA)
		template.AddStep(stepB)
		template.AddStep(stepC)

		err = template.ValidateSteps()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "circular dependency detected")
	})

	t.Run("circular dependency - partial cycle in larger graph", func(t *testing.T) {
		template, err := pipeline.NewTemplate(tenantID, "Test Pipeline", "Partial cycle")
		require.NoError(t, err)

		// Graph: A -> B -> C -> D, but also D -> B (cycle in B-C-D)
		stepA := createStep(t, template.ID, "step-a", []string{"scan"})
		stepB := createStep(t, template.ID, "step-b", []string{"scan"})
		stepC := createStep(t, template.ID, "step-c", []string{"scan"})
		stepD := createStep(t, template.ID, "step-d", []string{"scan"})

		stepB.SetDependencies([]string{"step-a", "step-d"}) // D -> B creates cycle
		stepC.SetDependencies([]string{"step-b"})
		stepD.SetDependencies([]string{"step-c"})

		template.AddStep(stepA)
		template.AddStep(stepB)
		template.AddStep(stepC)
		template.AddStep(stepD)

		err = template.ValidateSteps()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "circular dependency detected")
	})

	t.Run("empty steps - no error", func(t *testing.T) {
		template, err := pipeline.NewTemplate(tenantID, "Test Pipeline", "Empty")
		require.NoError(t, err)

		err = template.ValidateSteps()
		assert.NoError(t, err)
	})

	t.Run("duplicate step key", func(t *testing.T) {
		template, err := pipeline.NewTemplate(tenantID, "Test Pipeline", "Duplicate key")
		require.NoError(t, err)

		stepA1 := createStep(t, template.ID, "step-a", []string{"scan"})
		stepA2 := createStep(t, template.ID, "step-a", []string{"scan"}) // Duplicate key

		template.AddStep(stepA1)
		template.AddStep(stepA2)

		err = template.ValidateSteps()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "duplicate step key")
	})

	t.Run("unknown dependency", func(t *testing.T) {
		template, err := pipeline.NewTemplate(tenantID, "Test Pipeline", "Unknown dependency")
		require.NoError(t, err)

		stepA := createStep(t, template.ID, "step-a", []string{"scan"})
		stepA.SetDependencies([]string{"step-unknown"})

		template.AddStep(stepA)

		err = template.ValidateSteps()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unknown dependency")
	})
}

func createStep(t *testing.T, pipelineID shared.ID, stepKey string, capabilities []string) *pipeline.Step {
	step, err := pipeline.NewStep(pipelineID, stepKey, stepKey, 1, capabilities)
	require.NoError(t, err)
	return step
}
