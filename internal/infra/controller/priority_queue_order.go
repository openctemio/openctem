package controller

import (
	"sort"
	"time"
)

// Q2/WS-C: priority-aware queue ordering.
//
// The existing platform-job queue (scan retries, ingest backlog,
// notification fan-out) pulls by FIFO. After F3 + reclassify sweep
// land, tenants with a burst of P0 findings want those to jump the
// queue — but not so aggressively that one tenant's 1000 P0s starve
// another tenant's P1.
//
// Design: two-axis sort.
//   1. PriorityClass first (P0 < P1 < P2 < P3 < empty).
//   2. Per-tenant fair queuing: the scheduler rotates which tenant
//      it pops from at each priority level so tenant A's P0 doesn't
//      monopolise against tenant B's P0.
//   3. Age bonus: once an item has waited > maxAge, it jumps one
//     priority band so nothing stays stuck forever.
//
// This file is pure sorting logic — no DB, no side effects. It is
// composed by the real queue impl (separate task in agent-repo).

// QueueItem is the minimal shape the scheduler orders. A production
// queue wraps this with a payload pointer; for ordering we only need
// the priority, tenant, and enqueue time.
type QueueItem struct {
	ID            string
	TenantID      string
	PriorityClass string // "P0" | "P1" | "P2" | "P3" | ""
	EnqueuedAt    time.Time
}

// OrderConfig tunes the scheduler.
type OrderConfig struct {
	// MaxAgeBonus is the age after which an item jumps one
	// priority band. Zero disables age bonus.
	MaxAgeBonus time.Duration
	// Now is injectable for tests.
	Now func() time.Time
}

// priorityWeight maps a class string to a sortable integer. Lower
// is higher priority. Unknown values land after P3.
func priorityWeight(class string) int {
	switch class {
	case "P0":
		return 0
	case "P1":
		return 1
	case "P2":
		return 2
	case "P3":
		return 3
	}
	return 4
}

// effectiveWeight applies the age-bonus rule: items waiting longer
// than MaxAgeBonus get one priority band boost. The boost does not
// escalate beyond P0 (weight 0).
func effectiveWeight(item QueueItem, cfg OrderConfig) int {
	w := priorityWeight(item.PriorityClass)
	if cfg.MaxAgeBonus > 0 {
		now := time.Now()
		if cfg.Now != nil {
			now = cfg.Now()
		}
		if now.Sub(item.EnqueuedAt) >= cfg.MaxAgeBonus && w > 0 {
			w--
		}
	}
	return w
}

// OrderBatch sorts items for dispatch. The contract:
//
//   - Lower effectiveWeight dispatches first.
//   - Within the same weight, tenants are rotated (round-robin) to
//     prevent one tenant from monopolising the band.
//   - Within the same (weight, tenant), older items dispatch first.
//
// OrderBatch returns a NEW slice; the input is not mutated.
func OrderBatch(items []QueueItem, cfg OrderConfig) []QueueItem {
	if len(items) <= 1 {
		out := make([]QueueItem, len(items))
		copy(out, items)
		return out
	}

	// Step 1: bucket by effective weight, then by tenant.
	type bucket struct {
		tenant string
		items  []QueueItem
	}
	// Preserve first-seen tenant order per weight for deterministic
	// round-robin.
	weightBuckets := map[int][]*bucket{}
	tenantIdx := map[int]map[string]int{}

	for _, it := range items {
		w := effectiveWeight(it, cfg)
		if _, ok := tenantIdx[w]; !ok {
			tenantIdx[w] = make(map[string]int)
		}
		idx, ok := tenantIdx[w][it.TenantID]
		if !ok {
			weightBuckets[w] = append(weightBuckets[w], &bucket{tenant: it.TenantID})
			idx = len(weightBuckets[w]) - 1
			tenantIdx[w][it.TenantID] = idx
		}
		weightBuckets[w][idx].items = append(weightBuckets[w][idx].items, it)
	}

	// Step 2: sort items within each tenant bucket by age (oldest first).
	for _, buckets := range weightBuckets {
		for _, b := range buckets {
			sort.SliceStable(b.items, func(i, j int) bool {
				return b.items[i].EnqueuedAt.Before(b.items[j].EnqueuedAt)
			})
		}
	}

	// Step 3: process weights in ascending order, round-robin tenants.
	sortedWeights := make([]int, 0, len(weightBuckets))
	for w := range weightBuckets {
		sortedWeights = append(sortedWeights, w)
	}
	sort.Ints(sortedWeights)

	out := make([]QueueItem, 0, len(items))
	for _, w := range sortedWeights {
		buckets := weightBuckets[w]
		// Round-robin across tenant buckets until all drain.
		for {
			drained := true
			for _, b := range buckets {
				if len(b.items) == 0 {
					continue
				}
				out = append(out, b.items[0])
				b.items = b.items[1:]
				drained = false
			}
			if drained {
				break
			}
		}
	}
	return out
}
