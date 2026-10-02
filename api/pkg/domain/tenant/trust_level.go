package tenant

import (
	"fmt"

	"github.com/openctemio/api/pkg/domain/shared"
)

// TrustLevel expresses how much a data source is trusted relative to
// others when multiple sources report conflicting values for the same
// asset field. Used by the ingest priority gate (RFC-003 Phase 1).
//
// Four buckets are enough to express the common case ("Nessus always
// wins, manual entries always win, everything else neutral") without
// forcing users to reason about numeric ranks. Inside a bucket,
// conflicts fall back to today's behavior (last-write-wins) — see
// RFC-003 §Open questions Q8.
type TrustLevel string

const (
	// TrustLevelPrimary — authoritative source. Overrides all other
	// buckets. Typical use: the customer's source of truth (CMDB,
	// trusted scanner, manual operator entry).
	TrustLevelPrimary TrustLevel = "primary"

	// TrustLevelHigh — strongly trusted. Overrides Medium and Low.
	TrustLevelHigh TrustLevel = "high"

	// TrustLevelMedium — neutral default. Assigned at migration to
	// every existing source so behavior remains backward compatible
	// until an admin rebalances.
	TrustLevelMedium TrustLevel = "medium"

	// TrustLevelLow — least trusted. Only overrides unlisted sources
	// or sources with no explicit level set.
	TrustLevelLow TrustLevel = "low"
)

// trustLevelRanks maps each level to a stable numeric rank. Higher
// wins. Ranks are not exposed in the API — callers compare levels
// via Outranks() to keep the enum the single source of truth.
var trustLevelRanks = map[TrustLevel]int{
	TrustLevelLow:     1,
	TrustLevelMedium:  2,
	TrustLevelHigh:    3,
	TrustLevelPrimary: 4,
}

// IsValid reports whether the level is one of the four known buckets.
func (l TrustLevel) IsValid() bool {
	_, ok := trustLevelRanks[l]
	return ok
}

// String implements fmt.Stringer.
func (l TrustLevel) String() string {
	return string(l)
}

// Rank returns the bucket's numeric rank. Unknown or empty levels
// rank 0 so they always lose to any configured level.
func (l TrustLevel) Rank() int {
	return trustLevelRanks[l]
}

// Outranks reports whether this level should win over other. Equal
// levels return false — the caller decides tie-breaking.
func (l TrustLevel) Outranks(other TrustLevel) bool {
	return l.Rank() > other.Rank()
}

// Validate returns a ValidationError when the level is unrecognized.
// Empty level is considered valid (means "unset") — callers who
// want to forbid unset levels check for the empty string themselves.
func (l TrustLevel) Validate() error {
	if l == "" {
		return nil
	}
	if !l.IsValid() {
		return fmt.Errorf(
			"%w: trust_level must be one of primary|high|medium|low, got %q",
			shared.ErrValidation, l,
		)
	}
	return nil
}

// DefaultTrustLevel returns the neutral level used when a source is
// created without an explicit choice. Keeps pre-feature behavior
// backward-compatible: every existing source starts at Medium and
// no tenant experiences a precedence change on upgrade.
func DefaultTrustLevel() TrustLevel { return TrustLevelMedium }

// AllTrustLevels returns the known levels in descending rank order.
// Useful for UI dropdowns and validation lists.
func AllTrustLevels() []TrustLevel {
	return []TrustLevel{
		TrustLevelPrimary,
		TrustLevelHigh,
		TrustLevelMedium,
		TrustLevelLow,
	}
}
