// Package scanzone defines scan zones: tenant-owned address ranges and the
// sensors that may scan them. Design: docs/rfcs/RFC-023-scan-zones-and-scanners.md
// (D3-D6, §5, §11); architecture: docs/architecture/scan-zones.md.
package scanzone

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// Limits on a zone. They bound what one zone can describe so a typo cannot
// turn a zone into "the whole internet" and a scanner's assignment stays
// reviewable.
const (
	MaxNameLength        = 100
	MaxDescriptionLength = 1000
	// MaxRangesPerZone bounds the normalized prefix list of one zone.
	MaxRangesPerZone = 256
	// MinIPv4PrefixLen and MinIPv6PrefixLen bound the size of one range: an
	// IPv4 /8 (10.0.0.0/8) and an IPv6 /32 are the widest accepted.
	MinIPv4PrefixLen = 8
	MinIPv6PrefixLen = 32
	// MaxRangeExpansion bounds how many prefixes one "a-b" range may expand
	// into; an arbitrary unaligned range is better written as CIDRs.
	MaxRangeExpansion = 16
)

// denyRanges can never be part of a zone, whatever the tenant asks for:
// scanning them from a sensor reaches the sensor itself (loopback), cloud
// metadata services (link-local / IMDS), every host on a segment (multicast,
// broadcast) or nothing meaningful (unspecified, reserved). RFC-023 §11.
var denyRanges = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),          // "this" network, incl. unspecified
	netip.MustParsePrefix("127.0.0.0/8"),        // loopback
	netip.MustParsePrefix("169.254.0.0/16"),     // link-local, incl. cloud IMDS
	netip.MustParsePrefix("224.0.0.0/4"),        // multicast
	netip.MustParsePrefix("240.0.0.0/4"),        // reserved, incl. broadcast
	netip.MustParsePrefix("::/128"),             // IPv6 unspecified
	netip.MustParsePrefix("::1/128"),            // IPv6 loopback
	netip.MustParsePrefix("fe80::/10"),          // IPv6 link-local
	netip.MustParsePrefix("ff00::/8"),           // IPv6 multicast
	netip.MustParsePrefix("255.255.255.255/32"), // broadcast (inside 240/4, listed for clarity)
}

// privateRanges are the address spaces that, once a tenant has zones, are
// scanned only through a zone (RFC-023 D6): RFC 1918, carrier-grade NAT and
// IPv6 unique-local.
var privateRanges = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("fc00::/7"),
}

// IsPrivate reports whether a is in private address space (RFC 1918, CGNAT,
// IPv6 ULA).
func IsPrivate(a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range privateRanges {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// IsDenied reports whether a lies in the built-in deny list.
func IsDenied(a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range denyRanges {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// prefixIsPrivate reports whether p overlaps private address space.
func prefixIsPrivate(p netip.Prefix) bool {
	for _, q := range privateRanges {
		if q.Overlaps(p) {
			return true
		}
	}
	return false
}

// Zone is a tenant-owned set of address ranges and the sensors assigned to
// scan them. A tenant has at most one default zone: it receives public targets
// and domains that no other zone's ranges cover (RFC-023 D6), so it may have
// no ranges of its own.
type Zone struct {
	ID          shared.ID
	TenantID    shared.ID
	Name        string
	Description string
	IsDefault   bool
	Ranges      []netip.Prefix
	SensorIDs   []shared.ID // assigned sensors; filled by the repository
	CreatedBy   *shared.ID
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// NewZone validates and creates a zone. Ranges are parsed and normalized with
// ParseRanges.
func NewZone(tenantID shared.ID, name, description string, isDefault bool, ranges []string, createdBy *shared.ID) (*Zone, error) {
	if tenantID.IsZero() {
		return nil, fmt.Errorf("%w: tenant is required", shared.ErrValidation)
	}
	now := time.Now().UTC()
	z := &Zone{
		ID:        shared.NewID(),
		TenantID:  tenantID,
		IsDefault: isDefault,
		CreatedBy: createdBy,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := z.setName(name); err != nil {
		return nil, err
	}
	if err := z.setDescription(description); err != nil {
		return nil, err
	}
	if err := z.setRanges(ranges); err != nil {
		return nil, err
	}
	return z, nil
}

// Update changes the given fields; nil leaves a field as it is. The zone is
// unchanged when any field is invalid.
func (z *Zone) Update(name, description *string, isDefault *bool, ranges *[]string) error {
	next := *z
	if name != nil {
		if err := next.setName(*name); err != nil {
			return err
		}
	}
	if description != nil {
		if err := next.setDescription(*description); err != nil {
			return err
		}
	}
	if isDefault != nil {
		next.IsDefault = *isDefault
	}
	if ranges != nil {
		if err := next.setRanges(*ranges); err != nil {
			return err
		}
	} else if !next.IsDefault && len(next.Ranges) == 0 {
		return fmt.Errorf("%w: a zone that is not the default zone needs at least one range", shared.ErrValidation)
	}
	next.UpdatedAt = time.Now().UTC()
	*z = next
	return nil
}

func (z *Zone) setName(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("%w: name is required", shared.ErrValidation)
	}
	if len(name) > MaxNameLength {
		return fmt.Errorf("%w: name must be at most %d characters", shared.ErrValidation, MaxNameLength)
	}
	z.Name = name
	return nil
}

func (z *Zone) setDescription(description string) error {
	description = strings.TrimSpace(description)
	if len(description) > MaxDescriptionLength {
		return fmt.Errorf("%w: description must be at most %d characters", shared.ErrValidation, MaxDescriptionLength)
	}
	z.Description = description
	return nil
}

func (z *Zone) setRanges(ranges []string) error {
	parsed, err := ParseRanges(ranges)
	if err != nil {
		return err
	}
	if len(parsed) == 0 && !z.IsDefault {
		return fmt.Errorf("%w: a zone that is not the default zone needs at least one range", shared.ErrValidation)
	}
	z.Ranges = parsed
	return nil
}

// RangeStrings returns the ranges in their canonical text form.
func (z *Zone) RangeStrings() []string {
	out := make([]string, len(z.Ranges))
	for i, p := range z.Ranges {
		out[i] = p.String()
	}
	return out
}

// HasPrivateRange reports whether any range overlaps private address space.
func (z *Zone) HasPrivateRange() bool {
	for _, p := range z.Ranges {
		if prefixIsPrivate(p) {
			return true
		}
	}
	return false
}

// HasSensor reports whether the sensor is assigned to the zone.
func (z *Zone) HasSensor(id shared.ID) bool {
	return slices.Contains(z.SensorIDs, id)
}

// Covers returns the prefix length of the narrowest zone range that contains
// all of p, or -1 when no range does.
func (z *Zone) Covers(p netip.Prefix) int {
	best := -1
	p = unmapPrefix(p)
	for _, r := range z.Ranges {
		if r.Addr().Is4() != p.Addr().Is4() {
			continue
		}
		if r.Bits() <= p.Bits() && r.Contains(p.Addr()) && r.Bits() > best {
			best = r.Bits()
		}
	}
	return best
}

// ParseRanges validates and normalizes zone ranges. Accepted forms: an
// address (10.0.0.5, fd00::5), a CIDR (10.1.0.0/16; host bits are masked) and
// an inclusive address range (10.0.0.1-10.0.0.200, expanded to CIDRs).
// IPv4-mapped IPv6 is converted to IPv4. The result is sorted, without
// duplicates and without prefixes contained in another. Rejected: anything
// overlapping the built-in deny list (so 0.0.0.0/0 and ::/0 too), IPv4 wider
// than /8, IPv6 wider than /32, and more than MaxRangesPerZone prefixes.
func ParseRanges(in []string) ([]netip.Prefix, error) {
	var all []netip.Prefix
	for _, raw := range in {
		ps, err := parseRange(raw)
		if err != nil {
			return nil, err
		}
		all = append(all, ps...)
		if len(all) > MaxRangesPerZone*MaxRangeExpansion {
			break // the final count check below rejects it
		}
	}
	for _, p := range all {
		if err := checkPrefix(p); err != nil {
			return nil, err
		}
	}
	out := normalize(all)
	if len(out) > MaxRangesPerZone {
		return nil, fmt.Errorf("%w: a zone may hold at most %d ranges", shared.ErrValidation, MaxRangesPerZone)
	}
	return out, nil
}

func parseRange(raw string) ([]netip.Prefix, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return nil, fmt.Errorf("%w: invalid range: empty", shared.ErrValidation)
	}
	if lo, hi, ok := strings.Cut(s, "-"); ok {
		return parseAddrRange(s, strings.TrimSpace(lo), strings.TrimSpace(hi))
	}
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid range %q: not an address, CIDR or address range", shared.ErrValidation, s)
		}
		return []netip.Prefix{unmapPrefix(p).Masked()}, nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" {
		return nil, fmt.Errorf("%w: invalid range %q: not an address, CIDR or address range", shared.ErrValidation, s)
	}
	a = a.Unmap()
	return []netip.Prefix{netip.PrefixFrom(a, a.BitLen())}, nil
}

func parseAddrRange(s, lo, hi string) ([]netip.Prefix, error) {
	a, errA := netip.ParseAddr(lo)
	b, errB := netip.ParseAddr(hi)
	if errA != nil || errB != nil || a.Zone() != "" || b.Zone() != "" {
		return nil, fmt.Errorf("%w: invalid range %q: not an address range", shared.ErrValidation, s)
	}
	a, b = a.Unmap(), b.Unmap()
	if a.Is4() != b.Is4() {
		return nil, fmt.Errorf("%w: invalid range %q: mixes IPv4 and IPv6", shared.ErrValidation, s)
	}
	if b.Less(a) {
		return nil, fmt.Errorf("%w: invalid range %q: end is before start", shared.ErrValidation, s)
	}
	out := rangeToPrefixes(a, b, MaxRangeExpansion+1)
	if len(out) > MaxRangeExpansion {
		return nil, fmt.Errorf("%w: range %q expands to too many CIDRs (max %d); write it as CIDRs",
			shared.ErrValidation, s, MaxRangeExpansion)
	}
	return out, nil
}

// rangeToPrefixes splits [a, b] into the minimal list of prefixes, stopping
// once limit prefixes have been produced.
func rangeToPrefixes(a, b netip.Addr, limit int) []netip.Prefix {
	var out []netip.Prefix
	bits := a.BitLen()
	for len(out) < limit {
		// Widest prefix starting at a that stays within [a, b].
		n := bits
		for n > 0 {
			p := netip.PrefixFrom(a, n-1)
			if p.Masked().Addr() != a || lastAddr(p).Compare(b) > 0 {
				break
			}
			n--
		}
		p := netip.PrefixFrom(a, n)
		out = append(out, p)
		last := lastAddr(p)
		if last.Compare(b) >= 0 {
			break
		}
		a = last.Next()
	}
	return out
}

// lastAddr returns the highest address in p.
func lastAddr(p netip.Prefix) netip.Addr {
	p = p.Masked()
	b := p.Addr().AsSlice()
	for i := p.Bits(); i < len(b)*8; i++ {
		b[i/8] |= byte(0x80) >> (i % 8)
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}

func checkPrefix(p netip.Prefix) error {
	for _, d := range denyRanges {
		if d.Overlaps(p) {
			return fmt.Errorf("%w: range %s overlaps the built-in deny list (%s): loopback, link-local/metadata, multicast, unspecified and reserved addresses are never scanned",
				shared.ErrValidation, p, d)
		}
	}
	minBits := MinIPv6PrefixLen
	if p.Addr().Is4() {
		minBits = MinIPv4PrefixLen
	}
	if p.Bits() < minBits {
		return fmt.Errorf("%w: range %s is too large (widest allowed is /%d)", shared.ErrValidation, p, minBits)
	}
	return nil
}

// normalize sorts, dedupes and drops prefixes contained in another.
func normalize(in []netip.Prefix) []netip.Prefix {
	ps := slices.Clone(in)
	slices.SortFunc(ps, func(a, b netip.Prefix) int {
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c
		}
		return a.Bits() - b.Bits()
	})
	out := make([]netip.Prefix, 0, len(ps))
	for _, p := range ps {
		if len(out) > 0 {
			last := out[len(out)-1]
			if last.Addr().Is4() == p.Addr().Is4() && last.Bits() <= p.Bits() && last.Contains(p.Addr()) {
				continue
			}
		}
		out = append(out, p)
	}
	return out
}

func unmapPrefix(p netip.Prefix) netip.Prefix {
	if !p.Addr().Is4In6() {
		return p
	}
	bits := p.Bits() - 96
	if bits < 0 {
		bits = 0
	}
	return netip.PrefixFrom(p.Addr().Unmap(), bits)
}
