package scope

// Scope entries on provider shared addresses (research/531 §6 step 4): an
// address, CIDR or range entry that lies wholly inside one range a provider
// publishes for a front end many organizations share. Such an entry names
// the provider's infrastructure, not the organization's, and is put in
// front of the organization once, per provider, to move out of scope or
// keep. Design: docs/architecture/provider-shared-addresses.md.

import (
	"github.com/openctemio/openctem/server/pkg/domain/edgeaddr"
	"github.com/openctemio/openctem/server/pkg/domain/scope/ipset"
)

// SharedProviderEntry answers the provider when an entry of type t and
// pattern lies wholly inside one published shared front-end range: a single
// address that edgeaddr.SharedFrontEnd holds, or a CIDR or "a-b" range whose
// two ends do and that one published range holds whole. A range that only
// partly overlaps a shared range, a dedicated prefix (the classifier's "any
// doubt: not shared"), any other entry type, and an unparsable pattern
// answer false: they stay ordinary entries (not held: the hold is the narrow, whole-range case only).
func SharedProviderEntry(t TargetType, pattern string) (edgeaddr.Result, bool) {
	switch t {
	case TargetTypeIPAddress, TargetTypeCIDR, TargetTypeIPRange:
	default:
		return edgeaddr.Result{}, false
	}
	rg, ok := ipset.Parse(pattern)
	if !ok {
		return edgeaddr.Result{}, false
	}
	c := edgeaddr.Default()
	lo, loShared := c.SharedFrontEnd(rg.Lo.String())
	if !loShared {
		return edgeaddr.Result{}, false
	}
	if rg.Lo == rg.Hi {
		return lo, true
	}
	hi, hiShared := c.SharedFrontEnd(rg.Hi.String())
	r := c.Range(rg.Lo, rg.Hi)
	if !hiShared || !r.Shared() || r.Basis != edgeaddr.BasisRange || r.Provider != lo.Provider || hi.Provider != lo.Provider {
		return edgeaddr.Result{}, false
	}
	return r, true
}
