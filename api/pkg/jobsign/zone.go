package jobsign

// Instance scan zones on signed jobs (docs/rfcs/RFC-100-shared-sensors.md
// §6.1): a shared sensor reaches a private address only inside the ranges
// of the instance scan zone its job statement names, and the signer signs
// such a statement only for a zone in its own zone ledger that is assigned
// to the job's organization and served by the claiming sensor.

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// LedgerZonesPath is the signer route that records an instance scan zone
// (POST: put or delete).
const LedgerZonesPath = "/v1/ledger/zones"

// Limits of one instance scan zone in the signer's zone ledger.
const (
	MaxZoneRanges  = 256
	MaxZoneTenants = 10000
	MaxZoneSensors = 1000
	MaxZones       = 10000
)

// StatementZone is the instance scan zone a shared job's statement names.
type StatementZone struct {
	// ID is the instance scan zone's id.
	ID string `json:"id"`
	// Ranges are the zone's ranges (canonical CIDR text, sorted): the only
	// private addresses the job may reach.
	Ranges []string `json:"ranges"`
}

// LedgerZone is one instance scan zone as the signer records it: its
// ranges, the organizations it is assigned to and the shared sensors that
// serve it.
type LedgerZone struct {
	ID      string   `json:"id"`
	Ranges  []string `json:"ranges"`
	Tenants []string `json:"tenants"`
	Sensors []string `json:"sensors"`
}

// ZoneChange is the body of POST /v1/ledger/zones: Put records (or
// replaces) a zone, DeleteID removes one. Exactly one is set. Requester is
// the console administrator who made the change (recorded in the ledger
// log).
type ZoneChange struct {
	Requester string      `json:"requester"`
	Put       *LedgerZone `json:"put,omitempty"`
	DeleteID  string      `json:"delete_id,omitempty"`
}

// ZoneChangeResult is the signer's answer to a zone change.
type ZoneChangeResult struct {
	Zones int `json:"zones"`
}

// privateZoneRanges are the ranges an instance scan zone may cover:
// RFC 1918 and IPv6 unique local addresses. Loopback, link-local, metadata,
// CGNAT and public ranges are never part of a zone.
var privateZoneRanges = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("fc00::/7"),
}

// ParseZoneRange reads one zone range: a CIDR (or a single address) wholly
// inside one private range, IPv4-mapped forms as IPv4, masked.
func ParseZoneRange(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	p, err := netip.ParsePrefix(s)
	if err != nil {
		a, aerr := netip.ParseAddr(s)
		if aerr != nil || a.Zone() != "" {
			return netip.Prefix{}, fmt.Errorf("%q is not a range", s)
		}
		p = netip.PrefixFrom(a, a.BitLen())
	}
	if p.Addr().Is4In6() {
		if p.Bits() < 96 {
			return netip.Prefix{}, fmt.Errorf("%q is not a range", s)
		}
		p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
	}
	p = p.Masked()
	for _, r := range privateZoneRanges {
		if r.Bits() <= p.Bits() && r.Contains(p.Addr()) {
			return p, nil
		}
	}
	return netip.Prefix{}, fmt.Errorf("%s is not wholly inside a private range (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7)", p)
}

// CanonicalZoneRanges parses, de-duplicates and sorts zone ranges, and
// returns their canonical text. It refuses an empty list, a list over
// MaxZoneRanges and any range that is not private.
func CanonicalZoneRanges(ranges []string) ([]string, error) {
	if len(ranges) == 0 {
		return nil, fmt.Errorf("a zone needs at least one range")
	}
	if len(ranges) > MaxZoneRanges {
		return nil, fmt.Errorf("a zone has at most %d ranges", MaxZoneRanges)
	}
	seen := make(map[string]bool, len(ranges))
	out := make([]string, 0, len(ranges))
	for _, r := range ranges {
		p, err := ParseZoneRange(r)
		if err != nil {
			return nil, err
		}
		if s := p.String(); !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out, nil
}

// ZoneContains reports whether the address or range target lies wholly
// inside one of ranges (canonical zone ranges). A target that is not an
// address or a range is not contained.
func ZoneContains(ranges []string, target netip.Prefix) bool {
	target = target.Masked()
	if target.Addr().Is4In6() && target.Bits() >= 96 {
		target = netip.PrefixFrom(target.Addr().Unmap(), target.Bits()-96)
	}
	for _, r := range ranges {
		p, err := netip.ParsePrefix(r)
		if err != nil {
			continue
		}
		if p.Bits() <= target.Bits() && p.Contains(target.Addr()) {
			return true
		}
	}
	return false
}
