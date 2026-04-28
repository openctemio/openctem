package controller

import (
	"testing"
	"time"
)

// tests for the priority-aware queue ordering algorithm.

func TestOrderBatch_Empty(t *testing.T) {
	got := OrderBatch(nil, OrderConfig{})
	if len(got) != 0 {
		t.Fatalf("empty input → non-empty output: %v", got)
	}
}

func TestOrderBatch_Single(t *testing.T) {
	it := QueueItem{ID: "a", PriorityClass: "P2"}
	got := OrderBatch([]QueueItem{it}, OrderConfig{})
	if len(got) != 1 || got[0].ID != "a" {
		t.Fatalf("single item mishandled: %v", got)
	}
}

func TestOrderBatch_PriorityFirst(t *testing.T) {
	items := []QueueItem{
		{ID: "1", PriorityClass: "P3"},
		{ID: "2", PriorityClass: "P0"},
		{ID: "3", PriorityClass: "P1"},
		{ID: "4", PriorityClass: ""},
	}
	got := OrderBatch(items, OrderConfig{})
	order := []string{got[0].ID, got[1].ID, got[2].ID, got[3].ID}
	if order[0] != "2" || order[1] != "3" || order[2] != "1" || order[3] != "4" {
		t.Fatalf("priority ordering wrong: %v", order)
	}
}

func TestOrderBatch_TenantRoundRobin(t *testing.T) {
	// Three tenants all have 2 P0s each. Round-robin means we
	// pop one from each tenant before going back to the first.
	items := []QueueItem{
		{ID: "a1", TenantID: "A", PriorityClass: "P0"},
		{ID: "a2", TenantID: "A", PriorityClass: "P0"},
		{ID: "b1", TenantID: "B", PriorityClass: "P0"},
		{ID: "b2", TenantID: "B", PriorityClass: "P0"},
		{ID: "c1", TenantID: "C", PriorityClass: "P0"},
		{ID: "c2", TenantID: "C", PriorityClass: "P0"},
	}
	got := OrderBatch(items, OrderConfig{})
	// First 3 should be one from each tenant.
	seen := map[string]int{}
	for _, it := range got[:3] {
		seen[it.TenantID]++
	}
	if len(seen) != 3 {
		t.Fatalf("first 3 items not spread across 3 tenants: %v", got[:3])
	}
}

func TestOrderBatch_AgeBonus(t *testing.T) {
	now := time.Now()
	items := []QueueItem{
		// P1 that has waited 2h — with 1h bonus cutoff, it becomes P0-equivalent.
		{ID: "old-p1", PriorityClass: "P1", EnqueuedAt: now.Add(-2 * time.Hour)},
		// Fresh P0.
		{ID: "fresh-p0", PriorityClass: "P0", EnqueuedAt: now},
		// Fresh P1 — stays P1.
		{ID: "fresh-p1", PriorityClass: "P1", EnqueuedAt: now},
	}
	cfg := OrderConfig{MaxAgeBonus: time.Hour, Now: func() time.Time { return now }}
	got := OrderBatch(items, cfg)
	// Both "old-p1" (bonus → P0) and "fresh-p0" are P0-weight;
	// fresh-p1 is last.
	if got[2].ID != "fresh-p1" {
		t.Fatalf("fresh-p1 should be last, got %q", got[2].ID)
	}
	// old-p1 and fresh-p0 should both be before fresh-p1.
	firstTwo := map[string]bool{got[0].ID: true, got[1].ID: true}
	if !firstTwo["old-p1"] || !firstTwo["fresh-p0"] {
		t.Fatalf("old-p1 should be bumped to P0 band: %v", got)
	}
}

func TestOrderBatch_AgeBonusDoesNotEscalateP0(t *testing.T) {
	now := time.Now()
	items := []QueueItem{
		{ID: "ancient-p0", PriorityClass: "P0", EnqueuedAt: now.Add(-10 * time.Hour)},
		{ID: "recent-p0", PriorityClass: "P0", EnqueuedAt: now},
	}
	cfg := OrderConfig{MaxAgeBonus: time.Hour, Now: func() time.Time { return now }}
	got := OrderBatch(items, cfg)
	// Both are P0; oldest should come first by age within the
	// same band.
	if got[0].ID != "ancient-p0" {
		t.Fatalf("oldest P0 should sort first within band, got %q", got[0].ID)
	}
}

func TestOrderBatch_StableAgeOrderWithinTenant(t *testing.T) {
	now := time.Now()
	items := []QueueItem{
		{ID: "newer", TenantID: "A", PriorityClass: "P2", EnqueuedAt: now},
		{ID: "older", TenantID: "A", PriorityClass: "P2", EnqueuedAt: now.Add(-5 * time.Minute)},
	}
	got := OrderBatch(items, OrderConfig{})
	if got[0].ID != "older" {
		t.Fatalf("older item should dispatch first within same tenant+priority: %v", got)
	}
}

func TestOrderBatch_DoesNotMutateInput(t *testing.T) {
	items := []QueueItem{
		{ID: "1", PriorityClass: "P2"},
		{ID: "2", PriorityClass: "P0"},
	}
	_ = OrderBatch(items, OrderConfig{})
	if items[0].ID != "1" || items[1].ID != "2" {
		t.Fatal("input slice was mutated")
	}
}

func TestOrderBatch_UnknownClassSortsLast(t *testing.T) {
	items := []QueueItem{
		{ID: "junk", PriorityClass: "X"},
		{ID: "p3", PriorityClass: "P3"},
	}
	got := OrderBatch(items, OrderConfig{})
	if got[0].ID != "p3" || got[1].ID != "junk" {
		t.Fatalf("unknown class should sort after P3, got %v", got)
	}
}
