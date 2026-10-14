package command

// Host keys of a chunk and when two chunks conflict. The keys are defined
// once, in github.com/openctemio/ctis/politeness, which the sensor
// runtime uses too: the platform holds and sends the keys the sensor admits
// the work under (docs/rfcs/RFC-090-work-pool.md, RFC-088 §6).

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/openctemio/ctis/politeness"
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

// AssignHostKeys gives cmd the politeness keys of the hosts it sends
// traffic to, and writes them into its payload ("host_keys"), so the
// sensor admits the command under exactly the keys the platform holds for
// it and never hands back what it was just offered. CommandRepository.Create
// calls it for every command, whatever path built it:
//
//   - keys the caller set (cmd.HostKeys, a scan run's stage-aware keys) win;
//   - else the payload's own "host_keys" (an empty list: a command that
//     touches no target host);
//   - else the keys of the payload's "target" and "targets" in its
//     "network_id", by politeness.Keys: the keys a sensor computes when no
//     keys are sent.
//
// A payload that names no target and carries no keys is left as it is
// (the command holds no host). Sent keys are bounded like the sensor
// bounds them (politeness.MaxKeys, maxHostKeyLen).
func AssignHostKeys(cmd *Command) error {
	if cmd == nil || len(cmd.Payload) == 0 {
		return nil
	}
	if !bytes.HasPrefix(bytes.TrimSpace(cmd.Payload), []byte("{")) {
		// Not an object: a sensor reads no targets from it either.
		return nil
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(cmd.Payload, &fields); err != nil {
		return fmt.Errorf("command payload: %w", err)
	}
	if cmd.HostKeys == nil {
		if raw, ok := fields["host_keys"]; ok {
			var sent []string
			if err := json.Unmarshal(raw, &sent); err != nil {
				return fmt.Errorf("command payload host_keys: %w", err)
			}
			cmd.HostKeys = boundKeys(sent)
			return nil
		}
		m := payloadHostMeta(fields)
		if len(m.targets) == 0 {
			return nil
		}
		cmd.HostKeys = remoteKeys(politeness.Keys(m.targets, m.network))
	}
	keys := cmd.HostKeys
	if keys == nil {
		keys = []string{}
	}
	b, err := json.Marshal(keys)
	if err != nil {
		return err
	}
	fields["host_keys"] = b
	payload, err := json.Marshal(fields)
	if err != nil {
		return err
	}
	cmd.Payload = payload
	return nil
}

// remoteKeys drops the keys of local filesystem paths ("." or "/src" of a
// code scan): such a path is a place on the running sensor's own disk, not
// a host other sensors of the tenant could also hit, so it never holds
// another sensor's work back. Nil when none is left.
func remoteKeys(keys []string) []string {
	out := keys[:0:0]
	for _, k := range keys {
		if !isLocalPathKey(k) {
			out = append(out, k)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// isLocalPathKey reports a politeness key that is a local filesystem path
// (the paths politeness.TargetKeys keys as given: absolute, "./", "../",
// ".", or a Windows drive path).
func isLocalPathKey(k string) bool {
	switch {
	case strings.HasPrefix(k, "/"), strings.HasPrefix(k, "./"), strings.HasPrefix(k, "../"), k == ".":
		return true
	case len(k) > 2 && k[1] == ':' && (k[2] == '\\' || k[2] == '/'):
		c := k[0] | 0x20
		return c >= 'a' && c <= 'z'
	}
	return false
}

// maxHostKeyLen bounds one politeness key (the sensor's bound).
const maxHostKeyLen = 512

// boundKeys is keys sorted, without duplicates or empty or over-long
// keys, at most politeness.MaxKeys; nil when none is left.
func boundKeys(keys []string) []string {
	out := make([]string, 0, min(len(keys), politeness.MaxKeys))
	for _, k := range keys {
		if k != "" && len(k) <= maxHostKeyLen {
			out = append(out, k)
		}
	}
	slices.Sort(out)
	out = slices.Compact(out)
	if len(out) > politeness.MaxKeys {
		out = out[:politeness.MaxKeys]
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// hostMeta is what a payload says about the hosts it touches, read the
// way the sensor reads it: "target" then "targets", and "network_id".
type hostMeta struct {
	targets []string
	network string
}

func payloadHostMeta(fields map[string]json.RawMessage) hostMeta {
	var m hostMeta
	var one string
	if raw, ok := fields["target"]; ok && json.Unmarshal(raw, &one) == nil && one != "" {
		m.targets = append(m.targets, one)
	}
	var list []string
	if raw, ok := fields["targets"]; ok && json.Unmarshal(raw, &list) == nil {
		m.targets = append(m.targets, list...)
	}
	if raw, ok := fields["network_id"]; ok {
		_ = json.Unmarshal(raw, &m.network)
	}
	return m
}

// followUpHostKeys is the keys of a follow-up's remaining targets among
// the keys its parent held: a follow-up never holds more than its parent,
// and stops holding the hosts of the targets that already settled. A key
// is kept when a remaining target produces it with or without the
// payload's network (a scan run computes its keys without one). A parent
// that held no host gives none; an empty list stays empty (a command that
// touches no target host).
func followUpHostKeys(parent []string, remaining []string, network string) []string {
	if parent == nil {
		return nil
	}
	produced := map[string]bool{}
	for _, k := range politeness.Keys(remaining, "") {
		produced[k] = true
	}
	if network != "" {
		for _, k := range politeness.Keys(remaining, network) {
			produced[k] = true
		}
	}
	out := make([]string, 0, len(parent))
	for _, k := range parent {
		if produced[k] {
			out = append(out, k)
		}
	}
	return out
}
