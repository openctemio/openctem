package widgets

// The attack surface posture widget (docs/architecture/easm-posture.md):
// the grade, score and category deductions of the read's scope, summed
// from the precomputed posture facts and stored in the snapshot like every
// widget.

import (
	"context"
	"time"

	postureapp "github.com/openctemio/openctem/api/internal/app/posture"
	"github.com/openctemio/openctem/api/pkg/domain/dashboard"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Reasons of the posture widget.
const (
	// ReasonNoSurface: no surface asset is in the scope, so no grade.
	ReasonNoSurface = "no_surface"
	// ReasonPostureBuilding: the organization's first posture computation
	// has not run yet.
	ReasonPostureBuilding = "posture_building"
)

const drillPosture = "/attack-surface/posture"

// PostureReader reads the posture of a scope (*postureapp.Service).
type PostureReader interface {
	ReadForScope(ctx context.Context, tenantID shared.ID, assets *shared.DataScope) (*postureapp.View, error)
}

// SetPosture wires the posture reader; unwired, the widget is not measured.
func (s *Service) SetPosture(r PostureReader) { s.posture = r }

// PostureCategory is one category's deduction.
type PostureCategory struct {
	Category  string  `json:"category"`
	Max       float64 `json:"max"`
	Deduction float64 `json:"deduction"`
	Issues    int64   `json:"issues"`
}

// PostureValue is the posture of a read.
type PostureValue struct {
	Score  int    `json:"score"`
	Grade  string `json:"grade" enums:"A,B,C,D,F"`
	Assets int64  `json:"assets"`
	// NextGrade and NextFloor: the grade above and its lowest score (empty
	// at A); FixSteps is how many items of the fix plan reach it (0 when the
	// plan does not reach it).
	NextGrade  string            `json:"next_grade,omitempty"`
	NextFloor  int               `json:"next_floor,omitempty"`
	FixSteps   int               `json:"fix_steps,omitempty"`
	Categories []PostureCategory `json:"categories"`
	ComputedAt *time.Time        `json:"computed_at,omitempty"`
}

// postureMetric fills the surface.posture widget.
func (s *Service) postureMetric(ctx context.Context, v *WidgetValue, scope dashboard.ReadScope) error {
	if s.posture == nil {
		v.State, v.Reason = StateNotMeasured, ReasonFailed
		return nil
	}
	view, err := s.posture.ReadForScope(ctx, scope.TenantID, scope.Assets)
	if err != nil {
		return err
	}
	v.Drill = drillPosture
	if view.State == nil || view.State.ComputedAt == nil {
		v.State, v.Reason = StateBuilding, ReasonPostureBuilding
		return nil
	}
	if !view.Score.Measured {
		v.State, v.Reason = StateNotMeasured, ReasonNoSurface
		return nil
	}
	out := &PostureValue{Score: view.Score.Value, Grade: view.Score.Grade, Assets: view.Score.Assets,
		NextGrade: view.Plan.Target, NextFloor: view.Plan.Floor, ComputedAt: view.State.ComputedAt,
		Categories: make([]PostureCategory, 0, len(view.Score.Categories))}
	if view.Plan.Reached {
		out.FixSteps = len(view.Plan.Steps)
	}
	for _, c := range view.Score.Categories {
		out.Categories = append(out.Categories, PostureCategory{Category: string(c.Category), Max: c.Max, Deduction: c.Deduction, Issues: c.Issues})
	}
	v.Posture = out
	return nil
}
