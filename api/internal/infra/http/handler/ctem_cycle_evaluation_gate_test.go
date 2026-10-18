package handler

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/ctemcycle"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// The charter evaluation is organization-wide: it is shown only to a viewer
// the data scope allows, and an unwired enforcer (or any error) leaves it
// out, never in.
func TestWithVisibleEvaluation_FailsClosed(t *testing.T) {
	h := NewCTEMCycleHandler(nil, nil, logger.NewNop())
	c := CTEMCycleResponse{ID: "c1", CharterEvaluation: &ctemcycle.CharterEvaluation{Met: 7}}
	got := h.withVisibleEvaluation(context.Background(), shared.NewID().String(), c)
	if got.CharterEvaluation != nil {
		t.Fatal("charter evaluation shown with no data-scope enforcer wired")
	}
	if got.ID != "c1" {
		t.Fatal("the rest of the cycle must stay readable")
	}
	// An unparseable tenant id leaves it out as well.
	if h.withVisibleEvaluation(context.Background(), "not-a-tenant", c).CharterEvaluation != nil {
		t.Fatal("charter evaluation shown for an unparseable tenant")
	}
	// An owner is unrestricted: shown.
	h.WithDataScope(unrestrictedDataScope())
	if h.withVisibleEvaluation(context.Background(), shared.NewID().String(), c).CharterEvaluation == nil {
		t.Fatal("charter evaluation hidden from an unrestricted viewer")
	}
}
