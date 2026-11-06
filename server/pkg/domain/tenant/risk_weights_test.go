package tenant

import (
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Weights that put everything on CTEM are only valid with CTEM points on.
func TestRiskScoringValidate_CTEMOnlyWeightsNeedCTEMPoints(t *testing.T) {
	s := LegacyRiskScoringSettings()
	s.Weights = ComponentWeights{CTEM: 100}
	s.CTEMPoints.Enabled = false
	if err := s.Validate(); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("Validate() = %v, want a validation error", err)
	}
	s = DefaultRiskScoringPreset()
	if err := s.Validate(); err != nil {
		t.Fatalf("default preset must stay valid: %v", err)
	}
}
