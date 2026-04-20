package sla

import (
	"testing"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// F3 (Q1/WS-C): priority class must drive SLA deadline; severity is the
// fallback only when the finding has no priority class yet. These tests
// pin down the contract.

func newTestPolicy(t *testing.T) *Policy {
	t.Helper()
	tid := shared.NewID()
	p, err := NewPolicy(tid, "test-policy")
	if err != nil {
		t.Fatalf("NewPolicy: %v", err)
	}
	return p
}

func TestCalculateDeadlineFor_UsesPriorityOverSeverity(t *testing.T) {
	p := newTestPolicy(t)
	// Defaults: P0=2d, critical=2d — use custom values so divergence is visible.
	p.WithPriorityDays(1, 7, 14, 30)
	// Severity "critical" would normally map to 2d. Class P0 must win.
	now := time.Now().UTC()
	got := p.CalculateDeadlineFor("P0", "critical", now)
	want := now.Add(1 * 24 * time.Hour)
	if !got.Equal(want) {
		t.Fatalf("P0 deadline = %s, want %s", got, want)
	}

	// P3 with critical severity: priority P3=30d must win over severity=2d.
	got = p.CalculateDeadlineFor("P3", "critical", now)
	want = now.Add(30 * 24 * time.Hour)
	if !got.Equal(want) {
		t.Fatalf("P3 deadline = %s, want %s", got, want)
	}
}

func TestCalculateDeadlineFor_FallsBackToSeverity(t *testing.T) {
	p := newTestPolicy(t)
	now := time.Now().UTC()

	// Empty priority class → severity-based.
	got := p.CalculateDeadlineFor("", "critical", now)
	want := now.Add(time.Duration(p.CriticalDays()) * 24 * time.Hour)
	if !got.Equal(want) {
		t.Fatalf("severity fallback = %s, want %s", got, want)
	}

	// Unknown priority class (e.g. legacy "P4") → severity-based.
	got = p.CalculateDeadlineFor("P4", "high", now)
	want = now.Add(time.Duration(p.HighDays()) * 24 * time.Hour)
	if !got.Equal(want) {
		t.Fatalf("unknown class fallback = %s, want %s", got, want)
	}
}

func TestGetDaysForPriorityClass(t *testing.T) {
	p := newTestPolicy(t)
	p.WithPriorityDays(1, 7, 14, 30)
	cases := map[string]int{
		"P0":      1,
		"P1":      7,
		"P2":      14,
		"P3":      30,
		"":        0,
		"garbage": 0,
	}
	for in, want := range cases {
		if got := p.GetDaysForPriorityClass(in); got != want {
			t.Errorf("%q → %d, want %d", in, got, want)
		}
	}
}

func TestWithPriorityDays_KeepsDefaultsOnZero(t *testing.T) {
	// Persisted value of 0 (e.g. legacy row) must not wipe the default —
	// it is treated as "inherit default". This is the backward-compat
	// guarantee for the P0-2 / F3 rollout.
	p := newTestPolicy(t)
	before := [4]int{p.P0Days(), p.P1Days(), p.P2Days(), p.P3Days()}
	p.WithPriorityDays(0, 0, 0, 0)
	after := [4]int{p.P0Days(), p.P1Days(), p.P2Days(), p.P3Days()}
	if before != after {
		t.Fatalf("zero values wiped defaults: before=%v after=%v", before, after)
	}
}

func TestNewPolicy_HasDefaultPriorityDays(t *testing.T) {
	p := newTestPolicy(t)
	if p.P0Days() != DefaultPriorityDays["P0"] {
		t.Fatalf("P0 default = %d, want %d", p.P0Days(), DefaultPriorityDays["P0"])
	}
	if p.P3Days() != DefaultPriorityDays["P3"] {
		t.Fatalf("P3 default = %d, want %d", p.P3Days(), DefaultPriorityDays["P3"])
	}
}

func TestCalculateDeadline_LegacySeverityPathUnchanged(t *testing.T) {
	// Ensure the old CalculateDeadline still works identically for
	// callers that have not migrated yet (backward compatibility).
	p := newTestPolicy(t)
	now := time.Now().UTC()
	got := p.CalculateDeadline("critical", now)
	want := now.Add(time.Duration(p.CriticalDays()) * 24 * time.Hour)
	if !got.Equal(want) {
		t.Fatalf("legacy path = %s, want %s", got, want)
	}
}
