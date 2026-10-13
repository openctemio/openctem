package command

// Host keys of a chunk and when two chunks conflict. The keys are defined
// once, in github.com/openctemio/sdk-go/pkg/politeness, which the sensor
// runtime uses too: the platform holds and sends the keys the sensor admits
// the work under (docs/rfcs/RFC-090-work-pool.md, RFC-088 §6).

import (
	"net/netip"

	"github.com/openctemio/sdk-go/pkg/politeness"
)

// Prefixes of the bucket host keys. Addresses fall in buckets of one IPv4
// /24 or one IPv6 /120.
const (
	// HostKeyAddrInBucket marks a chunk that sends traffic to one or more
	// addresses of the bucket ("in:203.0.113.0/24").
	HostKeyAddrInBucket = politeness.AddrInBucket
	// HostKeyRangeBucket marks a chunk that scans (part of) the bucket as a
	// range ("net:203.0.113.0/24").
	HostKeyRangeBucket = politeness.RangeBucket
)

// BucketBits are the bucket sizes: an IPv4 /24, an IPv6 /120.
const (
	BucketBitsV4 = politeness.BucketBitsV4
	BucketBitsV6 = politeness.BucketBitsV6
)

// AddrBucket is the bucket prefix an address falls in.
func AddrBucket(a netip.Addr) netip.Prefix { return politeness.AddrBucket(a) }

// HostKeyConflicts returns the keys that conflict with a chunk holding keys:
// a plain key (a name or an address) conflicts with itself; an address in a
// bucket conflicts with a range scan of that bucket; a range scan of a
// bucket conflicts with both. Two chunks conflict when one's stored keys
// share an element with the other's conflict keys (the relation is
// symmetric). Two addresses of one bucket do not conflict.
func HostKeyConflicts(keys []string) []string { return politeness.Conflicts(keys) }

// HostKeyLock is the advisory lock name of a key: a bucket marker and a
// bucket range key share one lock, so a claim of an address chunk and a
// claim of a range chunk of the same bucket run one after the other.
func HostKeyLock(k string) string { return politeness.Lock(k) }
