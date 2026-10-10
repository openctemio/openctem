package stage

// Where a stage's tools send traffic, and the tier a step counts at against
// a scan's intensity: docs/rfcs/RFC-071-scan-intensity.md.
//
// A passive (T0) stage must never send packets from our sensors to the
// target hosts. Its tools reach only third-party sources (through the
// sensor's egress proxy), recursive DNS resolvers, a vendor API, or nothing
// on the network at all (code and image analysis). The platform's
// classification below is authoritative for the tools it knows; a sensor's
// tool contract can only narrow it.

import "strings"

// Network is what a tool's traffic reaches.
type Network string

const (
	// NetworkNone: no network traffic for the scan itself (code, images).
	NetworkNone Network = "none"
	// NetworkResolver: DNS queries through recursive resolvers only; the
	// target's own hosts receive nothing from the sensor.
	NetworkResolver Network = "resolver"
	// NetworkEgressProxy: third-party data sources (certificate logs,
	// passive DNS, search APIs) through the sensor's egress proxy.
	NetworkEgressProxy Network = "egress-proxy"
	// NetworkVendor: a vendor or code-host API (a registry, a repository).
	NetworkVendor Network = "vendor"
	// NetworkTargets: packets to the target hosts (ports, HTTP, templates).
	NetworkTargets Network = "targets"
)

// TouchesTargets reports whether the network reaches the target hosts. An
// unknown value counts as reaching them (fail closed).
func (n Network) TouchesTargets() bool {
	switch n {
	case NetworkNone, NetworkResolver, NetworkEgressProxy, NetworkVendor:
		return false
	}
	return true
}

// stageNetworks are the networks of the passive stages; every other stage
// reaches its targets.
var stageNetworks = map[Key]Network{
	DiscoverSubdomains: NetworkEgressProxy,
	ResolveDNS:         NetworkResolver,
	SecretsCode:        NetworkVendor,
	SASTCode:           NetworkVendor,
	SCADeps:            NetworkVendor,
	IaCMisconfig:       NetworkVendor,
	ContainerImage:     NetworkVendor,
}

// NetworkOf is what the stage's tools reach.
func (s Stage) NetworkOf() Network {
	if n, ok := stageNetworks[s.Key]; ok {
		return n
	}
	return NetworkTargets
}

// ToolNetwork is what a run of the tool may reach: NetworkTargets when any
// stage it implements reaches its targets, or when the catalog does not know
// the tool; else the network of its stages (the first, in catalog order).
func ToolNetwork(tool string) Network {
	stages := ForTool(tool)
	if len(stages) == 0 {
		return NetworkTargets
	}
	for _, s := range stages {
		if s.NetworkOf().TouchesTargets() {
			return NetworkTargets
		}
	}
	return stages[0].NetworkOf()
}

// resolverConfigKeys are the step or scanner settings that point a DNS
// tool at resolvers of the caller's choosing. A custom resolver can be the
// target's own name server, so the step is not passive any more.
var resolverConfigKeys = []string{"resolver", "resolvers", "r", "rl", "resolver_list", "resolvers_file"}

// IntensityTier is the tier a step (or a single-scanner scan) counts at
// against a scan's intensity: the highest of the tool's tier (the highest
// tier among the stages it implements), the tier of the stage its
// capabilities name, and T1 for a resolver tool told to use custom
// resolvers. A step the catalog cannot place is T1, never passive.
func IntensityTier(tool string, caps []string, config map[string]any) Tier {
	tool = strings.TrimSpace(tool)
	var t Tier
	known := false
	if tool != "" {
		t, known = ProbeTier(tool), true
	}
	if s, err := ForCapabilities(caps); err == nil {
		if !known || s.Tier > t {
			t = s.Tier
		}
		known = true
	}
	if !known {
		return TierActive
	}
	if t < TierActive && customResolvers(tool, caps, config) {
		t = TierActive
	}
	return t
}

// customResolvers reports whether a DNS-resolution step's settings name its
// own resolvers.
func customResolvers(tool string, caps []string, config map[string]any) bool {
	if len(config) == 0 {
		return false
	}
	resolver := tool != "" && ToolNetwork(tool) == NetworkResolver
	if !resolver {
		if s, err := ForCapabilities(caps); err == nil && s.NetworkOf() == NetworkResolver {
			resolver = true
		}
	}
	if !resolver {
		return false
	}
	for k, v := range config {
		if !containsFold(resolverConfigKeys, k) {
			continue
		}
		switch x := v.(type) {
		case nil:
		case string:
			if strings.TrimSpace(x) != "" {
				return true
			}
		case []any:
			if len(x) > 0 {
				return true
			}
		case []string:
			if len(x) > 0 {
				return true
			}
		default:
			return true
		}
	}
	return false
}

func containsFold(list []string, s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
