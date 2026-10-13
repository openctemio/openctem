package scan

// Range targets are cut around exclusions and the built-in deny list instead
// of being dropped whole. Design:
// docs/rfcs/RFC-088-scope-aware-target-allocation.md; architecture:
// docs/architecture/active-probe-gate.md.

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/pkg/domain/scanzone"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/scope/ipset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// MaxRangePieces bounds how many pieces one dispatch may cut its range
// targets into. More is refused (RANGE_TOO_FRAGMENTED): the exclusions are
// too scattered to send as ranges.
const MaxRangePieces = 4096

// MaxRangeAddresses bounds one range target: 2^16 addresses, the scan target
// validator's own bound (an IPv4 /16, an IPv6 /112). A wider range is
// refused here too, for the paths that skip the validator.
const MaxRangeAddresses = 1 << 16

// CodeRangeTooFragmented: the range targets of one dispatch split into more
// than MaxRangePieces pieces.
const CodeRangeTooFragmented = "RANGE_TOO_FRAGMENTED"

// Reasons of the refusals the split adds.
const (
	ReasonRangeDenied   = "every address of this range is in the built-in deny list (loopback, link-local/metadata, multicast, unspecified)"
	ReasonRangeTooLarge = "the range has more than 65536 addresses; split it into /16 (IPv4) or /112 (IPv6) ranges or smaller"
)

// ExclusionAddressSource returns the addresses the tenant's active
// exclusions of an address kind cover. The scope service implements it; a
// gate whose exclusion filter does not keeps the whole-target rule (a range
// that overlaps an exclusion is excluded whole).
type ExclusionAddressSource interface {
	ExcludedAddressSet(ctx context.Context, tenantID string) (ipset.Set, error)
}

// The scope service is the production exclusion filter: it must answer
// address sets, or ranges fall back to the whole-target rule.
var _ ExclusionAddressSource = (*scope.Service)(nil)

// SplitTarget is a range target the gate cut: the pieces it dispatches
// instead, and how many addresses exclusions and the deny list removed.
type SplitTarget struct {
	Target  string   `json:"target"`
	Pieces  []string `json:"pieces"`
	Removed uint64   `json:"removed_addresses"`
}

// denySet is the built-in deny list as an address set.
var denySet = func() ipset.Set {
	ps := scanzone.DenyPrefixes()
	rs := make([]ipset.Range, 0, len(ps))
	for _, p := range ps {
		if r, ok := ipset.PrefixRange(p); ok {
			rs = append(rs, r)
		}
	}
	return ipset.Of(rs...)
}()

// rangeTarget reads a target that names more than one address: a CIDR or an
// "a-b" range. A single address (or a /32, /128) is not a range.
func rangeTarget(t string) (ipset.Range, bool) {
	if !strings.ContainsAny(t, "/-") {
		return ipset.Range{}, false
	}
	r, ok := ipset.Parse(t)
	if !ok || r.Lo == r.Hi {
		return ipset.Range{}, false
	}
	return r, true
}

// splitRangeTargets replaces every range target that overlaps an active
// exclusion of an address kind or the built-in deny list with the exact
// rest: the fewest prefixes that hold the range's addresses minus the
// excluded and denied ones. A range with nothing left is excluded (or
// refused, when only the deny list removed it). A range target that also
// matches by other names (DispatchAsset.AlsoMatch) is left to the
// whole-target rule: an exclusion of one of its names is not an address
// subtraction. Pieces inherit the range's inventory asset entry.
//
// Nothing is listed per address. A lookup error is returned (fail closed);
// more than MaxRangePieces pieces is RANGE_TOO_FRAGMENTED.
func (s *Service) splitRangeTargets(ctx context.Context, in *DispatchTargetsInput, targets []string, out *DispatchTargets) ([]string, error) {
	idx := make(map[int]ipset.Range)
	for i, t := range targets {
		r, ok := rangeTarget(t)
		if !ok {
			continue
		}
		if a, has := assetOf(in.Assets, t); has && len(a.AlsoMatch) > 0 {
			continue
		}
		idx[i] = r
	}
	if len(idx) == 0 {
		return targets, nil
	}
	src, ok := s.scopeExclusions.(ExclusionAddressSource)
	if !ok {
		return targets, nil
	}
	excluded, err := src.ExcludedAddressSet(ctx, in.TenantID.String())
	if err != nil {
		return nil, fmt.Errorf("scope exclusion check failed, nothing dispatched: %w", err)
	}
	remove := ipset.Of(append(excluded.Ranges(), denySet.Ranges()...)...)

	kept := make([]string, 0, len(targets))
	budget := MaxRangePieces
	for i, t := range targets {
		r, isRange := idx[i]
		if !isRange {
			kept = append(kept, t)
			continue
		}
		if n, full := r.Size(); full || n > MaxRangeAddresses {
			out.Refused = append(out.Refused, RefusedTarget{Target: t, Reason: ReasonRangeTooLarge, Code: scopedom.RefusalInvalidTarget})
			continue
		}
		whole := ipset.Of(r)
		rest := whole.Subtract(remove)
		if rest.Equal(whole) {
			kept = append(kept, t)
			continue
		}
		if rest.Empty() {
			if whole.Subtract(denySet).Empty() {
				out.Refused = append(out.Refused, RefusedTarget{Target: t, Reason: ReasonRangeDenied, Code: scopedom.RefusalDenyList})
			} else {
				out.Excluded = append(out.Excluded, t)
			}
			continue
		}
		prefixes, err := rest.Prefixes(ipset.PieceBits{}, budget)
		if err != nil {
			if errors.Is(err, ipset.ErrTooManyPieces) {
				return nil, rangeTooFragmentedError()
			}
			return nil, err
		}
		budget -= len(prefixes)
		pieces := make([]string, len(prefixes))
		a, hasAsset := assetOf(in.Assets, t)
		for j, p := range prefixes {
			pieces[j] = pieceString(p.String())
			if hasAsset {
				in.Assets[assetKey(pieces[j])] = a
			}
		}
		n, _ := whole.Size()
		left, _ := rest.Size()
		out.Split = append(out.Split, SplitTarget{Target: t, Pieces: pieces, Removed: n - left})
		kept = append(kept, pieces...)
	}
	return dedupeTargets(kept), nil
}

// pieceString writes a single-address piece as the bare address.
func pieceString(p string) string {
	if a, bits, ok := strings.Cut(p, "/"); ok && (bits == "32" && !strings.Contains(a, ":") || bits == "128") {
		return a
	}
	return p
}

func rangeTooFragmentedError() error {
	return shared.NewDomainError(CodeRangeTooFragmented,
		fmt.Sprintf("The exclusions cut the network ranges of this scan into more than %d pieces. Merge nearby exclusions into wider ones, or scan smaller ranges.", MaxRangePieces),
		shared.ErrValidation)
}
