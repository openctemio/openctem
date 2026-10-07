package scanrun

import (
	"net"
	"net/url"
	"slices"
	"strings"

	scanapp "github.com/openctemio/openctem/api/internal/app/scan"
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
	keys := make([]string, 0, len(targets))
	for _, t := range targets {
		if k := hostKey(t); k != "" {
			keys = append(keys, k)
		}
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

// hostKey is the host a target names: the host of a URL, a host:port
// without its port, an address, a name. A range (CIDR) is its own key.
// Empty when nothing can be read.
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
