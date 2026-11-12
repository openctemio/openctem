package scope

// Replacing a scope entry's pattern (docs/architecture/scope-entry-replace.md).
//
// A pattern never changes in place: the approvals, the audit history and the
// scans that name an entry are bound to it. A replacement is a new entry of
// the same type that names the entry it replaces. While the replacement waits
// for approval the old entry stays in effect; once the replacement is in
// effect the old entry is superseded: it authorizes nothing and keeps its
// history, with a link to its replacement.

import (
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/openctem/server/pkg/domain/scope/ipset"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// Replacement errors.
var (
	ErrEntrySuperseded = shared.NewDomainError("ENTRY_SUPERSEDED",
		"the scope entry was replaced by another entry; change that entry instead", shared.ErrConflict)
	ErrEntryNotReplaceable = shared.NewDomainError("ENTRY_NOT_REPLACEABLE",
		"only an entry in effect can have its pattern replaced; a pending, inactive, expired or rejected entry is removed and added again", shared.ErrConflict)
	ErrReplacementPending = shared.NewDomainError("REPLACEMENT_PENDING",
		"a replacement of this entry is already waiting for approval; approve, reject or delete it first", shared.ErrConflict)
	ErrReplaceSamePattern = shared.NewDomainError("REPLACE_SAME_PATTERN",
		"the new pattern is the entry's current pattern", shared.ErrValidation)
	ErrReplaceReasonRequired = shared.NewDomainError("REPLACE_REASON_REQUIRED",
		"a reason is required to replace a scope entry's pattern", shared.ErrValidation)
)

// Supersedes is the entry this one replaces (nil: none).
func (t *Target) Supersedes() *shared.ID { return t.supersedes }

// SupersededBy is the entry that replaced this one (nil: none).
func (t *Target) SupersededBy() *shared.ID { return t.supersededBy }

// IsSuperseded reports whether the entry was replaced.
func (t *Target) IsSuperseded() bool { return t.status == StatusSuperseded }

// SetSupersedes marks a new entry as the replacement of old. It is set when
// the replacement is created, never later.
func (t *Target) SetSupersedes(old shared.ID) {
	id := old
	t.supersedes = &id
}

// RestoreReplacement sets the replacement links read from persistence.
func (t *Target) RestoreReplacement(supersedes, supersededBy *shared.ID) {
	t.supersedes, t.supersededBy = supersedes, supersededBy
}

// Supersede retires the entry for its replacement by. It then
// authorizes nothing.
func (t *Target) Supersede(by shared.ID, now time.Time) {
	id := by
	t.status = StatusSuperseded
	t.supersededBy = &id
	t.updatedAt = now
}

// CoverageChange is what replacing one pattern with another adds to and
// removes from what an entry covers.
type CoverageChange struct {
	// Widens: the new pattern may cover something the old one did not.
	// When the two cannot be compared it is true (the safe side).
	Widens bool
	// Narrows: the old pattern covered something the new one does not.
	Narrows bool
	// Added and Removed list the addresses (ranges) or patterns gained
	// and lost.
	Added   []string
	Removed []string
	// AddedAddresses and RemovedAddresses count the addresses gained and
	// lost (address types only; saturated for very large IPv6 sets).
	AddedAddresses   uint64
	RemovedAddresses uint64
	// Addresses: the counts above are meaningful (an address type).
	Addresses bool
}

// IsAddressType reports whether entries of type t name addresses.
func IsAddressType(t TargetType) bool {
	return t == TargetTypeIPAddress || t == TargetTypeIPRange || t == TargetTypeCIDR
}

// AddressSet is the address set an address-type pattern covers.
func AddressSet(pattern string) (ipset.Set, bool) {
	r, ok := ipset.Parse(pattern)
	if !ok {
		return ipset.Set{}, false
	}
	return ipset.Of(r), true
}

// ReplacementChange compares the coverage of two patterns of one type.
func ReplacementChange(t TargetType, oldPattern, newPattern string) CoverageChange {
	if IsAddressType(t) {
		if c, ok := addressChange(oldPattern, newPattern); ok {
			return c
		}
	}
	c := CoverageChange{Added: []string{newPattern}, Removed: []string{oldPattern}, Narrows: true, Widens: true}
	if patternWithin(t, newPattern, oldPattern) {
		c.Widens, c.Added = false, nil
	}
	if patternWithin(t, oldPattern, newPattern) {
		c.Narrows, c.Removed = false, nil
	}
	return c
}

func addressChange(oldPattern, newPattern string) (CoverageChange, bool) {
	o, okO := AddressSet(oldPattern)
	n, okN := AddressSet(newPattern)
	if !okO || !okN {
		return CoverageChange{}, false
	}
	added, removed := n.Subtract(o), o.Subtract(n)
	c := CoverageChange{Addresses: true, Widens: !added.Empty(), Narrows: !removed.Empty()}
	c.AddedAddresses, _ = added.Size()
	c.RemovedAddresses, _ = removed.Size()
	for _, r := range added.Ranges() {
		c.Added = append(c.Added, r.String())
	}
	for _, r := range removed.Ranges() {
		c.Removed = append(c.Removed, r.String())
	}
	return c, true
}

// patternWithin reports whether everything inner covers is provably covered
// by outer. False when it cannot be shown (the safe side for "widens").
func patternWithin(t TargetType, inner, outer string) bool {
	switch t {
	case TargetTypeDomain, TargetTypeSubdomain, TargetTypeEmailDomain:
		iw, in := splitDomainWildcard(inner)
		ow, on := splitDomainWildcard(outer)
		if in == "" || on == "" {
			return false
		}
		if !ow {
			return !iw && in == on
		}
		// *.outer covers the strict subdomains of outer only.
		if iw {
			return in == on || strings.HasSuffix(in, "."+on)
		}
		return strings.HasSuffix(in, "."+on)
	}
	if strings.Contains(inner, "*") {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(inner), strings.TrimSpace(outer)) ||
		EntryMatches(t, outer, Constraint{}, inner)
}

// String describes the change for logs and notifications.
func (c CoverageChange) String() string {
	return fmt.Sprintf("adds %s; removes %s", listOrNone(c.Added), listOrNone(c.Removed))
}

func listOrNone(l []string) string {
	if len(l) == 0 {
		return "nothing"
	}
	return strings.Join(l, ", ")
}
