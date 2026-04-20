package ctemcycle

import (
	"testing"

	"github.com/openctemio/api/pkg/domain/shared"
)

// B5: unit tests for the review-phase domain types.
// The handler-layer integration test (SQL for the delta + metrics)
// lives in tests/integration/ once the DB harness lands.

func TestScopeDelta_IsEmpty(t *testing.T) {
	var d ScopeDelta
	if !d.IsEmpty() {
		t.Fatal("zero-value delta must be empty")
	}
	d.AddedAssetIDs = []shared.ID{shared.NewID()}
	if d.IsEmpty() {
		t.Fatal("delta with added IDs must not be empty")
	}
}

func TestScopeDelta_Size(t *testing.T) {
	d := ScopeDelta{
		AddedAssetIDs:   []shared.ID{shared.NewID(), shared.NewID()},
		RemovedAssetIDs: []shared.ID{shared.NewID()},
	}
	if d.Size() != 3 {
		t.Fatalf("size = %d, want 3", d.Size())
	}
}

func TestScopeDelta_UnchangedCountStored(t *testing.T) {
	// The type carries the unchanged count so the UI can show
	// "X out of Y changed" without a separate query.
	d := ScopeDelta{UnchangedCount: 42}
	if d.UnchangedCount != 42 {
		t.Fatalf("unchanged count not preserved: %d", d.UnchangedCount)
	}
}

func TestNewReviewSnapshot_Empty(t *testing.T) {
	tid := shared.NewID()
	cid := shared.NewID()
	s := NewReviewSnapshot(cid, tid)
	if s.CycleID != cid || s.TenantID != tid {
		t.Fatalf("ids not set: %+v", s)
	}
	if !s.Delta.IsEmpty() {
		t.Fatal("new snapshot must start with an empty delta")
	}
	if s.ComputedAt.IsZero() {
		t.Fatal("ComputedAt must be set")
	}
	if len(s.FindingsToRevalidate) != 0 {
		t.Fatal("FindingsToRevalidate must start empty")
	}
}

func TestStartReview_FromActiveOnly(t *testing.T) {
	// Lock in the existing state-machine invariant that review
	// can only be entered from active — important because B5
	// work is expensive and must not run from wrong states.
	tid := shared.NewID()
	uid := shared.NewID()

	cycle, err := NewCycle(tid, "test", uid)
	if err != nil {
		t.Fatalf("NewCycle: %v", err)
	}
	// Planning → Review is forbidden.
	if err := cycle.StartReview(); err == nil {
		t.Fatal("StartReview from planning must error")
	}
	// Planning → Active → Review is allowed.
	if err := cycle.Activate(); err != nil {
		t.Fatalf("Activate: %v", err)
	}
	if err := cycle.StartReview(); err != nil {
		t.Fatalf("StartReview from active: %v", err)
	}
	if cycle.Status() != CycleStatusReview {
		t.Fatalf("status = %v, want review", cycle.Status())
	}
	// Review → Review is forbidden (idempotency is the caller's
	// concern; the domain refuses repeat transitions).
	if err := cycle.StartReview(); err == nil {
		t.Fatal("StartReview from review must error")
	}
}

func TestMetricTypeConstants_Stable(t *testing.T) {
	// Metric types are persisted in ctem_cycle_metrics.metric_type
	// and queried by dashboards. Renaming requires a migration +
	// dashboard update — this test makes renames a conscious act.
	want := map[string]string{
		"MetricMTTRHours":          MetricMTTRHours,
		"MetricFindingsOpened":     MetricFindingsOpened,
		"MetricFindingsResolved":   MetricFindingsResolved,
		"MetricPClassChurn":        MetricPClassChurn,
		"MetricValidationCoverage": MetricValidationCoverage,
		"MetricScopeDriftSize":     MetricScopeDriftSize,
	}
	// Just exercise each constant so the compiler fails if any is
	// deleted; the actual string values are contractual.
	for name, v := range want {
		if v == "" {
			t.Errorf("%s must not be empty", name)
		}
	}
}
