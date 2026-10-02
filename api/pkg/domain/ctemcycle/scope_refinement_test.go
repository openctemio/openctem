package ctemcycle

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/openctemio/api/pkg/domain/shared"
)

// SetScopeRefinementNotes is the one charter field editable after planning —
// it captures the feedback-to-scope loop and is only meaningful once the cycle
// has run, so it is allowed in review/closed and rejected in planning/active.
func TestCycle_SetScopeRefinementNotes_StatusGating(t *testing.T) {
	newActiveCycle := func(t *testing.T) *Cycle {
		t.Helper()
		c, err := NewCycle(shared.NewID(), "Q3 cycle", shared.NewID())
		if err != nil {
			t.Fatalf("NewCycle: %v", err)
		}
		if err := c.Activate(); err != nil {
			t.Fatalf("Activate: %v", err)
		}
		return c
	}

	t.Run("rejected in planning", func(t *testing.T) {
		c, _ := NewCycle(shared.NewID(), "c", shared.NewID())
		if err := c.SetScopeRefinementNotes("x"); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("planning must reject, got %v", err)
		}
	})

	t.Run("rejected in active", func(t *testing.T) {
		c := newActiveCycle(t)
		if err := c.SetScopeRefinementNotes("x"); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("active must reject, got %v", err)
		}
	})

	t.Run("allowed in review", func(t *testing.T) {
		c := newActiveCycle(t)
		if err := c.StartReview(); err != nil {
			t.Fatalf("StartReview: %v", err)
		}
		if err := c.SetScopeRefinementNotes("add exposed RDP next cycle"); err != nil {
			t.Fatalf("review should allow, got %v", err)
		}
		if got := c.Charter().ScopeRefinementNotes; got != "add exposed RDP next cycle" {
			t.Fatalf("notes not stored, got %q", got)
		}
	})

	t.Run("allowed in closed", func(t *testing.T) {
		c := newActiveCycle(t)
		if err := c.StartReview(); err != nil {
			t.Fatalf("StartReview: %v", err)
		}
		if err := c.Close(shared.NewID()); err != nil {
			t.Fatalf("Close: %v", err)
		}
		if err := c.SetScopeRefinementNotes("late lesson"); err != nil {
			t.Fatalf("closed should allow, got %v", err)
		}
	})
}

// TestCharter_ScopeRefinementNotes_RoundTrip proves the field survives the
// marshal→JSONB→unmarshal path the handler uses, and stays omitted when empty.
func TestCharter_ScopeRefinementNotes_RoundTrip(t *testing.T) {
	raw, err := json.Marshal(Charter{ScopeRefinementNotes: "exclude legacy VPN next cycle"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got Charter
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.ScopeRefinementNotes != "exclude legacy VPN next cycle" {
		t.Fatalf("round-trip lost notes, got %q", got.ScopeRefinementNotes)
	}

	// The field is omitempty: a charter without notes must not emit the key,
	// so pre-existing charters load unchanged.
	if bs, _ := json.Marshal(Charter{RiskAppetite: "low"}); strings.Contains(string(bs), "scope_refinement_notes") {
		t.Fatalf("empty notes should be omitted, got %s", bs)
	}
}
