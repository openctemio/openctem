package scan

// Dynamic target selectors: RFC-068
// (docs/rfcs/RFC-068-dynamic-scan-targets.md). A scan's targets may hold
// selectors besides plain hosts: a wildcard domain ("*.example.com") and a
// CIDR. They are resolved against the inventory at the start of every run,
// never when the scan is saved, so a scheduled scan picks up the names and
// addresses found since its last run. TargetOptions tunes that resolution.

import (
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// CIDRMode says what a CIDR target scans.
type CIDRMode string

const (
	// CIDRModeSweep hands the range itself to the scanner (every address in
	// it is probed). The default, and what a CIDR target always meant.
	CIDRModeSweep CIDRMode = "sweep"
	// CIDRModeInventory replaces the range, at each run, with the address
	// assets of the inventory inside it.
	CIDRModeInventory CIDRMode = "inventory"
)

// MaxSeenWithinDays bounds the freshness window.
const MaxSeenWithinDays = 365

// TargetOptions tunes how a run resolves the scan's selectors. The zero
// value is the default: CIDRs swept, every non-archived, non-stale asset.
type TargetOptions struct {
	// CIDRMode: sweep (default) or inventory.
	CIDRMode CIDRMode `json:"cidr_mode,omitempty"`
	// SeenWithinDays keeps only inventory assets seen in the last N days
	// (0: any). Applies to what a selector adds, never to a typed host.
	SeenWithinDays int `json:"seen_within_days,omitempty"`
	// IncludeStale also takes assets the lifecycle marked stale or inactive
	// (not seen for a while). Archived assets are never taken.
	IncludeStale bool `json:"include_stale,omitempty"`
	// NewSinceLastRun keeps only the inventory assets that came into the
	// organization's scope since the scan's previous successful run: their
	// attribution was confirmed since then, or they were first seen since
	// then without an attribution record (the dispatch gate still decides
	// each). The first run takes every such asset. Never a typed host
	// (RFC-071, continuous discovery).
	NewSinceLastRun bool `json:"new_since_last_run,omitempty"`
}

// Validate refuses an unknown CIDR mode or an out-of-range window.
func (o TargetOptions) Validate() error {
	switch o.CIDRMode {
	case "", CIDRModeSweep, CIDRModeInventory:
	default:
		return fmt.Errorf("%w: target_options.cidr_mode must be sweep or inventory", shared.ErrValidation)
	}
	if o.SeenWithinDays < 0 || o.SeenWithinDays > MaxSeenWithinDays {
		return fmt.Errorf("%w: target_options.seen_within_days must be between 0 and %d", shared.ErrValidation, MaxSeenWithinDays)
	}
	return nil
}

// EffectiveCIDRMode is the mode, sweep when unset.
func (o TargetOptions) EffectiveCIDRMode() CIDRMode {
	if o.CIDRMode == "" {
		return CIDRModeSweep
	}
	return o.CIDRMode
}

// IsZero reports whether every option is the default.
func (o TargetOptions) IsZero() bool {
	return o.EffectiveCIDRMode() == CIDRModeSweep && o.SeenWithinDays == 0 && !o.IncludeStale && !o.NewSinceLastRun
}

// SetTargetOptions sets the options after validating them.
func (s *Scan) SetTargetOptions(o TargetOptions) error {
	if err := o.Validate(); err != nil {
		return err
	}
	if o.CIDRMode == CIDRModeSweep {
		o.CIDRMode = ""
	}
	s.TargetOptions = o
	s.UpdatedAt = time.Now()
	return nil
}

// SelectorQuery asks the inventory for the assets one selector covers, as
// they are now. Exactly one of UnderDomain and InCIDR is set.
type SelectorQuery struct {
	TenantID shared.ID
	// UnderDomain: domain-class assets named the root or ending in ".root".
	UnderDomain string
	// InCIDR: address assets inside the range.
	InCIDR string
	// SeenSince keeps assets seen at or after it (nil: any).
	SeenSince *time.Time
	// IncludeStale also returns stale and inactive assets.
	IncludeStale bool
	// NewOnly keeps only assets whose attribution is confirmed, or that have
	// no attribution record; with NewSince, only those confirmed (or first
	// seen without a record) at or after it.
	NewOnly  bool
	NewSince *time.Time
	// Limit bounds the rows, freshest first.
	Limit int
}
