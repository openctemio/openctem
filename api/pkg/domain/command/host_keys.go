package command

// Host keys of a chunk and when two chunks conflict. Design:
// docs/rfcs/RFC-088-scope-aware-target-allocation.md (§6).

import (
	"net/netip"
	"slices"
	"strings"
)

// Prefixes of the bucket host keys. Addresses fall in buckets of one IPv4
// /24 or one IPv6 /120.
const (
	// HostKeyAddrInBucket marks a chunk that sends traffic to one or more
	// addresses of the bucket ("in:203.0.113.0/24").
	HostKeyAddrInBucket = "in:"
	// HostKeyRangeBucket marks a chunk that scans (part of) the bucket as a
	// range ("net:203.0.113.0/24").
	HostKeyRangeBucket = "net:"
)

// BucketBits are the bucket sizes: an IPv4 /24, an IPv6 /120.
const (
	BucketBitsV4 = 24
	BucketBitsV6 = 120
)

// AddrBucket is the bucket prefix an address falls in.
func AddrBucket(a netip.Addr) netip.Prefix {
	a = a.Unmap().WithZone("")
	bits := BucketBitsV6
	if a.Is4() {
		bits = BucketBitsV4
	}
	p, _ := a.Prefix(bits)
	return p
}

// HostKeyConflicts returns the keys that conflict with a chunk holding keys:
// a plain key (a name or an address) conflicts with itself; an address in a
// bucket conflicts with a range scan of that bucket; a range scan of a
// bucket conflicts with both. Two chunks conflict when one's stored keys
// share an element with the other's conflict keys (the relation is
// symmetric). Two addresses of one bucket do not conflict.
func HostKeyConflicts(keys []string) []string {
	out := make([]string, 0, len(keys)+2)
	for _, k := range keys {
		switch {
		case strings.HasPrefix(k, HostKeyAddrInBucket):
			out = append(out, HostKeyRangeBucket+strings.TrimPrefix(k, HostKeyAddrInBucket))
		case strings.HasPrefix(k, HostKeyRangeBucket):
			b := strings.TrimPrefix(k, HostKeyRangeBucket)
			out = append(out, k, HostKeyAddrInBucket+b)
		default:
			out = append(out, k)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// HostKeyLock is the advisory lock name of a key: a bucket marker and a
// bucket range key share one lock, so a claim of an address chunk and a
// claim of a range chunk of the same bucket run one after the other.
func HostKeyLock(k string) string {
	switch {
	case strings.HasPrefix(k, HostKeyAddrInBucket):
		return "b:" + strings.TrimPrefix(k, HostKeyAddrInBucket)
	case strings.HasPrefix(k, HostKeyRangeBucket):
		return "b:" + strings.TrimPrefix(k, HostKeyRangeBucket)
	}
	return k
}
