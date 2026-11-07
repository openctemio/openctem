package scan

// Range targets are cut around exclusions and the built-in deny list instead
// of being dropped whole; a range wider than a /16 (a large range) is also
// cut to the tenant's in-scope networks, into /16 chunks. Design:
// docs/rfcs/RFC-088-scope-aware-target-allocation.md,
// docs/rfcs/RFC-151-large-range-targets.md; architecture:
// docs/architecture/active-probe-gate.md.

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/pkg/domain/scanzone"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/scope/ipset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/validator"
)

// MaxRangePieces bounds how many pieces one dispatch may cut its range
// targets into. More is refused (RANGE_TOO_FRAGMENTED): the exclusions are
// too scattered to send as ranges.
const MaxRangePieces = 4096

// MaxPieceBits is the widest piece a range is dispatched as: an IPv4 /24,
// an IPv6 /120 (256 addresses). A wider range is cut, so its pieces can be
// chunked by address count and spread over sensors.
var MaxPieceBits = ipset.PieceBits{V4: 24, V6: 120}

// fitsOnePiece reports whether r is one prefix no wider than MaxPieceBits.
func fitsOnePiece(r ipset.Range) bool {
	p, ok := r.Prefix()
	if !ok {
		return false
	}
	if p.Addr().Is4() {
		return p.Bits() >= MaxPieceBits.V4
	}
	return p.Bits() >= MaxPieceBits.V6
}

// MaxRangeAddresses bounds one range target of a dispatch that does not
// allow large ranges: 2^16 addresses, the scan target validator's default
// bound (an IPv4 /16, an IPv6 /112). A wider range is refused here too, for
// the paths that skip the validator.
const MaxRangeAddresses = 1 << validator.DefaultCIDRHostBits

// LargePieceBits is the widest chunk a large range (wider than
// MaxRangeAddresses) is dispatched as: an IPv4 /16, an IPv6 /112. A /8 is
// 256 chunks, never 16M addresses or 65,536 /24 rows.
var LargePieceBits = ipset.PieceBits{V4: 32 - validator.DefaultCIDRHostBits, V6: 128 - validator.DefaultCIDRHostBits}

// RangeLimits answers the widest range one scan target of a tenant may name,
// in host bits (the tenant's scope setting; *tenant.TenantService).
type RangeLimits interface {
	MaxRangeHostBits(ctx context.Context, tenantID shared.ID) (int, error)
}

// WithRangeLimits sets the per-tenant range bound. Without it every range
// target is at most a /16 (the validator's default).
func WithRangeLimits(l RangeLimits) ServiceOption {
	return func(s *Service) { s.rangeLimits = l }
}

// tenantRangeHostBits is the widest range the tenant's scan targets may
// name, in host bits, clamped to [DefaultCIDRHostBits?, the platform limit]:
// a tenant may lower it below a /16 too. No limits source: the default /16.
func (s *Service) tenantRangeHostBits(ctx context.Context, tenantID shared.ID) (int, error) {
	if s.rangeLimits == nil {
		return validator.DefaultCIDRHostBits, nil
	}
	bits, err := s.rangeLimits.MaxRangeHostBits(ctx, tenantID)
	if err != nil {
		return 0, fmt.Errorf("read the organization's widest range target: %w", err)
	}
	return min(max(bits, 0), validator.MaxCIDRHostBitsLimit), nil
}

// tenantRangeHostBitsOf is tenantRangeHostBits for a tenant id in text (an
// invalid id gets the default /16; the caller refuses it elsewhere).
func (s *Service) tenantRangeHostBitsOf(ctx context.Context, tenantID string) (int, error) {
	if id, perr := shared.IDFromString(tenantID); perr == nil {
		return s.tenantRangeHostBits(ctx, id)
	}
	return validator.DefaultCIDRHostBits, nil
}

// InScopeAddressSource returns the addresses the tenant's active scope
// entries of an address kind (address, range, CIDR) cover: a large range is
// cut to them, so its out-of-scope parts are never dispatched. The scope
// service implements it.
type InScopeAddressSource interface {
	InScopeAddressSet(ctx context.Context, tenantID string) (ipset.Set, error)
}

var _ InScopeAddressSource = (*scope.Service)(nil)

// CodeRangeTooFragmented: the range targets of one dispatch split into more
// than MaxRangePieces pieces.
const CodeRangeTooFragmented = "RANGE_TOO_FRAGMENTED"

// Reasons of the refusals the split adds.
const (
	ReasonRangeDenied     = "every address of this range is in the built-in deny list (loopback, link-local/metadata, multicast, unspecified)"
	ReasonRangeTooLarge   = "the range is wider than one scan target may be here: a /16 (IPv6 /112), or the organization's widest range (Scope settings, a /8 at most) for a scan that finds live hosts first"
	ReasonRangeOutOfScope = "no scope entry of an address kind covers any address of this range"
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
	// OutOfScope counts the addresses of a large range no scope entry covers
	// (included in Removed).
	OutOfScope uint64 `json:"out_of_scope_addresses,omitempty"`
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
// exclusion of an address kind or the built-in deny list, or is wider than
// one piece (MaxPieceBits), with the exact rest: the fewest prefixes no
// wider than a piece that hold the range's addresses minus the excluded and
// denied ones. A range with nothing left is excluded (or
// refused, when only the deny list removed it). A range target of at most
// a /16 that also matches by other names (DispatchAsset.AlsoMatch) is left
// to the whole-target rule: an exclusion of one of its names is not an
// address subtraction. A wider one is bounded and cut like any range.
// Pieces inherit the range's inventory asset entry.
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
		// A range that also matches by other names keeps the whole-target
		// rule only while it is small enough to go as typed. A wider one
		// (a group's network asset, say) is refused or cut like any other
		// range, its pieces inheriting the asset entry, AlsoMatch included,
		// so a name exclusion still applies to every piece.
		if a, has := assetOf(in.Assets, t); has && len(a.AlsoMatch) > 0 {
			if n, full := r.Size(); !full && n <= MaxRangeAddresses {
				continue
			}
		}
		idx[i] = r
	}
	if len(idx) == 0 {
		return targets, nil
	}
	src, ok := s.scopeExclusions.(ExclusionAddressSource)
	if !ok {
		// No address filter: ranges go as typed, so none may be wider than
		// the default bound (fail closed for a large range).
		kept := make([]string, 0, len(targets))
		for i, t := range targets {
			if r, isRange := idx[i]; isRange {
				if n, full := r.Size(); full || n > MaxRangeAddresses {
					out.Refused = append(out.Refused, RefusedTarget{Target: t, Reason: ReasonRangeTooLarge, Code: scopedom.RefusalInvalidTarget})
					continue
				}
			}
			kept = append(kept, t)
		}
		return kept, nil
	}
	excluded, err := src.ExcludedAddressSet(ctx, in.TenantID.String())
	if err != nil {
		return nil, fmt.Errorf("scope exclusion check failed, nothing dispatched: %w", err)
	}
	remove := ipset.Of(append(excluded.Ranges(), denySet.Ranges()...)...)
	maxAddrs := rangeBound(in.rangeHostBits())

	kept := make([]string, 0, len(targets))
	budget := MaxRangePieces
	var inScope *ipset.Set
	for i, t := range targets {
		r, isRange := idx[i]
		if !isRange {
			kept = append(kept, t)
			continue
		}
		n, full := r.Size()
		if full || n > maxAddrs {
			out.Refused = append(out.Refused, RefusedTarget{Target: t, Reason: ReasonRangeTooLarge, Code: scopedom.RefusalInvalidTarget})
			continue
		}
		whole := ipset.Of(r)
		cut, pieceBits := whole, MaxPieceBits
		var outOfScope uint64
		if n > MaxRangeAddresses {
			// A large range: only its in-scope addresses, in /16 chunks.
			if inScope == nil {
				set, err := s.inScopeAddresses(ctx, in.TenantID)
				if err != nil {
					return nil, err
				}
				inScope = &set
			}
			cut = whole.Intersect(*inScope)
			if cut.Empty() {
				out.Refused = append(out.Refused, RefusedTarget{Target: t, Reason: ReasonRangeOutOfScope, Code: scopedom.RefusalNoEntry})
				continue
			}
			left, _ := cut.Size()
			outOfScope = n - left
			pieceBits = LargePieceBits
		}
		rest := cut.Subtract(remove)
		if rest.Equal(whole) && fitsOnePiece(r) {
			kept = append(kept, t)
			continue
		}
		if rest.Empty() {
			if cut.Subtract(denySet).Empty() {
				out.Refused = append(out.Refused, RefusedTarget{Target: t, Reason: ReasonRangeDenied, Code: scopedom.RefusalDenyList})
			} else {
				out.Excluded = append(out.Excluded, t)
			}
			continue
		}
		prefixes, err := rest.Prefixes(pieceBits, budget)
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
		left, _ := rest.Size()
		out.Split = append(out.Split, SplitTarget{Target: t, Pieces: pieces, Removed: n - left, OutOfScope: outOfScope})
		kept = append(kept, pieces...)
	}
	return dedupeTargets(kept), nil
}

// rangeBound is the most addresses one range target may hold for a dispatch
// that allows hostBits (0: the default /16).
func rangeBound(hostBits int) uint64 {
	if hostBits <= 0 {
		return MaxRangeAddresses
	}
	return 1 << min(hostBits, validator.MaxCIDRHostBitsLimit)
}

// inScopeAddresses is the tenant's in-scope address set. No source fails
// closed: a large range is never dispatched without the scope cut.
func (s *Service) inScopeAddresses(ctx context.Context, tenantID shared.ID) (ipset.Set, error) {
	src, ok := s.scopeExclusions.(InScopeAddressSource)
	if !ok {
		return ipset.Set{}, errors.New("scope address lookup unavailable, a large range is not dispatched")
	}
	set, err := src.InScopeAddressSet(ctx, tenantID.String())
	if err != nil {
		return ipset.Set{}, fmt.Errorf("scope entry check failed, nothing dispatched: %w", err)
	}
	return set, nil
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

// MaxJobExclusions bounds the exclusions one job carries (the sensor SDK
// refuses a job with more).
const MaxJobExclusions = 4096

// PayloadKeyExclusions is the job payload key of the exclusions that touch
// the job's ranges. The job signature covers the payload, so a relay cannot
// add or drop one.
const PayloadKeyExclusions = "exclusions"

// rangeBucket widens r to the /24 (IPv4) or /120 (IPv6) buckets that hold
// it: the neighborhood whose exclusions a sensor is told about.
func rangeBucket(r ipset.Range) ipset.Range {
	bits := MaxPieceBits.V4
	if !r.Lo.Is4() {
		bits = MaxPieceBits.V6
	}
	return ipset.Range{
		Lo: netip.PrefixFrom(r.Lo, bits).Masked().Addr(),
		Hi: ipset.LastAddr(netip.PrefixFrom(r.Hi, bits)),
	}
}

// JobExclusions are the tenant's active exclusions of an address kind that
// touch the range targets of one job: every range widened to its /24 or
// /120 buckets, intersected with the excluded addresses, written as the
// fewest prefixes. The pieces the gate dispatches already leave these
// addresses out; the sensor cuts its ranges around them again, address by
// address, so a planning mistake cannot reach an excluded address. nil when
// the job has no range target or no exclusion is near one. A lookup error is
// returned (fail closed: the job is not created), and more than
// MaxJobExclusions prefixes is RANGE_TOO_FRAGMENTED.
func (s *Service) JobExclusions(ctx context.Context, tenantID shared.ID, targets []string) ([]string, error) {
	var near []ipset.Range
	for _, t := range targets {
		if r, ok := rangeTarget(strings.TrimSpace(t)); ok {
			near = append(near, rangeBucket(r))
		}
	}
	if len(near) == 0 {
		return nil, nil
	}
	src, ok := s.scopeExclusions.(ExclusionAddressSource)
	if !ok {
		return nil, nil
	}
	excluded, err := src.ExcludedAddressSet(ctx, tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("scope exclusion check failed, nothing dispatched: %w", err)
	}
	touching := excluded.Intersect(ipset.Of(near...))
	if touching.Empty() {
		return nil, nil
	}
	prefixes, err := touching.Prefixes(ipset.PieceBits{}, MaxJobExclusions)
	if err != nil {
		if errors.Is(err, ipset.ErrTooManyPieces) {
			return nil, rangeTooFragmentedError()
		}
		return nil, err
	}
	out := make([]string, len(prefixes))
	for i, p := range prefixes {
		out[i] = p.String()
	}
	return out, nil
}

// attachJobExclusions adds the exclusions that touch the job's range
// targets to its payload (JobExclusions).
func (s *Service) attachJobExclusions(ctx context.Context, tenantID shared.ID, payload map[string]any, targets []string) error {
	excl, err := s.JobExclusions(ctx, tenantID, targets)
	if err != nil {
		return err
	}
	if len(excl) > 0 {
		payload[PayloadKeyExclusions] = excl
	}
	return nil
}
