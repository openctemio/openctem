package ingest

import (
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/tenant"
)

// FieldOwnership maps a property field name to the source ID that
// most recently wrote it. Callers derive this from
// asset_sources.contributed_data; the gate never talks to storage
// directly — that keeps the algorithm pure and easy to test.
type FieldOwnership map[string]shared.ID

// WriteDecision is the outcome of CanWrite for a single field.
type WriteDecision struct {
	Allowed bool
	// Reason is a stable string tag (e.g. "lower_priority",
	// "unowned_field", "feature_disabled"). Used for metrics and
	// structured logs.
	Reason string
}

// PriorityGate decides whether an incoming source may overwrite an
// existing field on an asset. Implementations must be pure: same
// inputs always produce the same output. No I/O, no time.
//
// The asset_sources table + tenant settings are the two inputs a
// caller assembles upstream; the gate itself takes the distilled
// data.
type PriorityGate interface {
	// CanWrite returns Allowed=true when the incoming source may
	// overwrite the field's current value. Unknown fields (not in
	// ownership) are always writable — the caller hasn't seen any
	// source claim them, so there is nothing to protect.
	CanWrite(
		settings tenant.AssetSourceSettings,
		incomingSourceID shared.ID,
		field string,
		ownership FieldOwnership,
	) WriteDecision

	// FilterProperties applies CanWrite to every key in `incoming`
	// and returns a new map containing only the keys the incoming
	// source is permitted to write. The original map is never
	// mutated.
	//
	// Returns (allowed, skipped) — skipped is the list of field
	// names that were filtered out, for audit logging upstream.
	FilterProperties(
		settings tenant.AssetSourceSettings,
		incomingSourceID shared.ID,
		incoming map[string]any,
		ownership FieldOwnership,
	) (allowed map[string]any, skipped []string)
}

// Reason tags — kept as constants so callers can match without
// relying on string formatting stability.
const (
	ReasonFeatureDisabled   = "feature_disabled"
	ReasonUnownedField      = "unowned_field"
	ReasonSameSource        = "same_source"
	ReasonHigherOrEqualRank = "higher_or_equal_rank"
	ReasonLowerRank         = "lower_rank"
)

// defaultPriorityGate is the standard implementation.
// Stateless — safe to share across goroutines.
type defaultPriorityGate struct{}

// NewPriorityGate returns the default implementation of PriorityGate.
func NewPriorityGate() PriorityGate {
	return defaultPriorityGate{}
}

// CanWrite implements PriorityGate.
func (defaultPriorityGate) CanWrite(
	settings tenant.AssetSourceSettings,
	incomingSourceID shared.ID,
	field string,
	ownership FieldOwnership,
) WriteDecision {
	// Fast path: when the tenant has not configured the feature,
	// every write is allowed. This is the backward-compat guarantee
	// promised by RFC-003 — callers that skip invoking the gate
	// when !settings.IsEnabled() also land here if they do invoke.
	if !settings.IsEnabled() {
		return WriteDecision{Allowed: true, Reason: ReasonFeatureDisabled}
	}

	// A field nobody has claimed is always writable. This covers
	// the common case of a source contributing NEW fields that no
	// other source ever touched — there is no precedence to
	// violate.
	existingOwner, owned := ownership[field]
	if !owned {
		return WriteDecision{Allowed: true, Reason: ReasonUnownedField}
	}

	// Same source re-writing its own field: always allowed. The
	// source is free to update a value it owns — a re-scan of the
	// same Nessus instance should refresh its own CVE list.
	if existingOwner == incomingSourceID {
		return WriteDecision{Allowed: true, Reason: ReasonSameSource}
	}

	// Compare ranks. Two sources may both be "listed" in Priority,
	// both "listed" via TrustLevels only, or either unlisted. The
	// rank function is defined below so it covers all combinations
	// with a single numeric comparison.
	incomingRank := rankOfSource(settings, incomingSourceID)
	existingRank := rankOfSource(settings, existingOwner)

	if incomingRank >= existingRank {
		return WriteDecision{Allowed: true, Reason: ReasonHigherOrEqualRank}
	}
	return WriteDecision{Allowed: false, Reason: ReasonLowerRank}
}

// FilterProperties implements PriorityGate.
func (g defaultPriorityGate) FilterProperties(
	settings tenant.AssetSourceSettings,
	incomingSourceID shared.ID,
	incoming map[string]any,
	ownership FieldOwnership,
) (map[string]any, []string) {
	// Feature off: return the input unchanged (no allocation). The
	// common case has to be cheap — ingest processes batches of
	// thousands of assets.
	if !settings.IsEnabled() {
		return incoming, nil
	}

	allowed := make(map[string]any, len(incoming))
	var skipped []string
	for field, value := range incoming {
		decision := g.CanWrite(settings, incomingSourceID, field, ownership)
		if decision.Allowed {
			allowed[field] = value
			continue
		}
		skipped = append(skipped, field)
	}
	return allowed, skipped
}

// rankOfSource returns a comparable integer rank for a source ID.
// Higher = wins. The ranking combines two inputs per RFC-003 §Data
// model:
//
//  1. Priority is the authoritative order. Position 0 ranks highest,
//     so we invert with a large offset so that both ordered sources
//     (non-zero rank) and trust-level-only sources (0) can coexist
//     in a single scale.
//  2. TrustLevels is advisory when Priority is present, authoritative
//     when Priority is empty. We read its numeric Rank() value.
//  3. A source present in neither ranks 0 — lower than every
//     configured source. This matches the "unlisted sources always
//     lose to listed" decision in Q2 of the RFC.
//
// The rank is computed inline rather than cached because tenant
// settings are small (capped at 500 entries) and comparisons are
// cheap; adding a lookup map would add allocation pressure without
// measurable speed-up.
func rankOfSource(settings tenant.AssetSourceSettings, id shared.ID) int {
	// Priority list — position 0 beats position 1, etc. Offset
	// the inverted position by the trust-level cap so listed
	// sources always outrank any trust-level-only entry, honoring
	// the "listed > unlisted" rule.
	const trustLevelCeiling = 10 // leaves headroom above TrustLevel.Rank() which maxes at 4
	for pos, entry := range settings.Priority {
		if entry == id {
			return trustLevelCeiling + (len(settings.Priority) - pos)
		}
	}

	// Trust level (no Priority match)
	level := settings.TrustLevelFor(id)
	return level.Rank()
}
