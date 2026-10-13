package scanrun

import (
	"net"
	"net/netip"
	"net/url"
	"slices"
	"strings"

	scanapp "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/scope/ipset"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
)

// maxHostKeys bounds the host keys one chunk carries (a chunk has at most a
// few hundred targets; anything beyond is not limited per host).
const maxHostKeys = 500

// chunkHostKeys is the hosts a chunk of an active stage sends traffic to,
// one key per host (lower-case name or address, without scheme, port or
// path), sorted and without duplicates. A passive (T0) stage touches no
// target host and gets none, so it is never held back.
func chunkHostKeys(st stage.Stage, hasStage bool, targets []string) []string {
	if !hasStage || st.Tier.Passive() || len(targets) == 0 {
		return nil
	}
	keys := make([]string, 0, 2*len(targets))
	for _, t := range targets {
		keys = append(keys, targetHostKeys(t)...)
	}
	slices.Sort(keys)
	keys = slices.Compact(keys)
	if len(keys) > maxHostKeys {
		keys = keys[:maxHostKeys]
	}
	if len(keys) == 0 {
		return nil
	}
	return keys
}

// chunkTargets is the targets a chunk's command carries: the chunk's own,
// else the run's target list (a step the target gate did not filter).
func chunkTargets(chunk *scanapp.StepTargets, runContext map[string]any) []string {
	if chunk != nil && chunk.Targets != nil {
		return chunk.Targets
	}
	switch ts := runContext["targets"].(type) {
	case []string:
		return ts
	case []any:
		out := make([]string, 0, len(ts))
		for _, v := range ts {
			if str, ok := v.(string); ok {
				out = append(out, str)
			}
		}
		return out
	}
	return nil
}

// targetHostKeys are the keys of one target: for a range, the range key of
// every /24 (IPv6 /120) bucket it covers; for an address (also the host of a
// URL or a service), the address and the bucket marker of its bucket; for a
// name, the name. A range and an address inside it then conflict, two
// addresses of one bucket do not (command.HostKeyConflicts).
func targetHostKeys(target string) []string {
	if r, ok := ipset.Parse(strings.TrimSpace(target)); ok && r.Lo != r.Hi {
		ps, err := ipset.Of(r).Prefixes(ipset.PieceBits{V4: command.BucketBitsV4, V6: command.BucketBitsV6}, maxHostKeys)
		if err != nil {
			// Wider than maxHostKeys buckets: hold the widest bucket keys
			// instead (never fewer keys than the range touches).
			ps, _ = ipset.Of(r).Prefixes(ipset.PieceBits{}, maxHostKeys)
		}
		out := make([]string, 0, len(ps))
		seen := map[string]bool{}
		for _, p := range ps {
			b, _ := p.Addr().Prefix(min(p.Bits(), bucketBits(p.Addr())))
			k := command.HostKeyRangeBucket + b.String()
			if !seen[k] {
				seen[k] = true
				out = append(out, k)
			}
		}
		return out
	}
	k := hostKey(target)
	if k == "" {
		return nil
	}
	if a, err := netip.ParseAddr(k); err == nil {
		return []string{k, command.HostKeyAddrInBucket + command.AddrBucket(a).String()}
	}
	return []string{k}
}

func bucketBits(a netip.Addr) int {
	if a.Is4() {
		return command.BucketBitsV4
	}
	return command.BucketBitsV6
}

// hostKey is the host a target names: the host of a URL, a host:port
// without its port, an address, a name (ranges: targetHostKeys). Empty when
// nothing can be read.
func hostKey(target string) string {
	t := strings.ToLower(strings.TrimSpace(target))
	if t == "" {
		return ""
	}
	if strings.Contains(t, "://") {
		u, err := url.Parse(t)
		if err != nil {
			return ""
		}
		return strings.TrimSuffix(u.Hostname(), ".")
	}
	if h, _, _, ok := asset.SplitServiceName(t); ok {
		return h // a service in any name form leases its host
	}
	if strings.Contains(t, "/") {
		if _, _, err := net.ParseCIDR(t); err == nil {
			return t
		}
		t, _, _ = strings.Cut(t, "/")
	}
	if host, _, err := net.SplitHostPort(t); err == nil {
		t = host
	}
	t = strings.Trim(t, "[]")
	return strings.TrimSuffix(t, ".")
}
