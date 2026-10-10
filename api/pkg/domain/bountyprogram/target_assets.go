package bountyprogram

// Program targets as inventory assets (RFC-065 §16.8,
// docs/rfcs/RFC-065-bug-bounty-programs.md): which asset each in-scope item
// of a program becomes when it goes through the platform's standard asset
// ingest. An asset is inventory, never permission to test: what may be
// scanned is still decided by the program's scope entries and their limits.

import (
	"strconv"
	"strings"
)

// Asset types a program target becomes (CTIS asset type names).
const (
	TargetAssetDomain    = "domain"
	TargetAssetIP        = "ip_address"
	TargetAssetNetwork   = "network"
	TargetAssetService   = "service"
	TargetAssetWebApp    = "web_application"
	TargetAssetAPI       = "api"
	TargetAssetMobileApp = "mobile_app"
	TargetAssetRepo      = "repository"
)

// MaxServicesPerTarget bounds the service assets one port-limited target
// makes (one per listed port; ranges make none).
const MaxServicesPerTarget = 32

// TargetAsset is one asset a program item becomes.
type TargetAsset struct {
	// Key is the item it comes from (its raw identifier), so the platform
	// records which program target an asset is.
	Key   string
	Type  string
	Value string
}

// TargetAssets maps a program's items to assets: in-scope items only, and
// not the inferred targets nobody confirmed (ItemsFor leaves those not
// scannable, with no published confidence). Out-of-scope items make none.
//
//   - a name: a domain asset (a wildcard: its base name);
//   - an address: an ip_address asset; a CIDR or range: a network asset;
//   - a name or address limited to ports: the host asset and one service
//     asset per listed port ("host:port/protocol");
//   - a URL limited to a path: a web_application asset (an api asset when
//     the program says the target is an API);
//   - a mobile app or a source repository the program publishes: a
//     mobile_app or repository asset (never scanned: no entry covers it);
//   - executables, hardware, smart contracts, AI models and anything else:
//     no asset; they stay program targets.
func TargetAssets(items []Item) []TargetAsset {
	var out []TargetAsset
	seen := map[string]bool{}
	add := func(key, typ, value string) {
		if value == "" {
			return
		}
		k := typ + "|" + strings.ToLower(value)
		if seen[k] {
			return
		}
		seen[k] = true
		out = append(out, TargetAsset{Key: key, Type: typ, Value: value})
	}
	for _, it := range items {
		if !it.InScope {
			continue
		}
		if !it.Scannable() {
			if it.Confidence != "" && it.Confidence != ConfidencePublished {
				continue // a suggestion
			}
			if typ := nonNetworkAssetType(it.AssetType); typ != "" {
				add(it.Raw, typ, strings.TrimSpace(it.Raw))
			}
			continue
		}
		api := isAPIType(it.AssetType)
		switch it.Kind {
		case KindDomain, KindIP:
			typ := TargetAssetDomain
			if it.Kind == KindIP {
				typ = TargetAssetIP
			}
			add(it.Raw, typ, it.Pattern)
			for _, port := range singlePorts(it.Ports) {
				proto := it.Protocol
				if proto == "" {
					proto = "tcp"
				}
				host := it.Pattern
				if strings.Contains(host, ":") {
					host = "[" + host + "]"
				}
				add(it.Raw, TargetAssetService, host+":"+port+"/"+proto)
			}
		case KindWildcard:
			add(it.Raw, TargetAssetDomain, strings.TrimPrefix(it.Pattern, "*."))
		case KindCIDR:
			add(it.Raw, TargetAssetNetwork, it.Pattern)
		case KindURL:
			typ := TargetAssetWebApp
			if api {
				typ = TargetAssetAPI
			}
			add(it.Raw, typ, strings.TrimSuffix(it.Pattern, "*"))
		}
	}
	return out
}

// singlePorts lists the single ports of a canonical port list (ranges are
// left out: a range is a limit, not a list of services).
func singlePorts(ports string) []string {
	if ports == "" {
		return nil
	}
	parts := strings.Split(ports, ",")
	out := make([]string, 0, min(len(parts), MaxServicesPerTarget))
	for _, p := range parts {
		if strings.Contains(p, "-") {
			continue
		}
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
			continue
		}
		out = append(out, p)
		if len(out) == MaxServicesPerTarget {
			break
		}
	}
	return out
}

func normalizedType(t string) string {
	return strings.ReplaceAll(strings.ToLower(strings.TrimSpace(t)), "-", "_")
}

func isAPIType(t string) bool { return normalizedType(t) == "api" }

// nonNetworkAssetType is the asset type of a target that is not a network
// target, "" when the platform has none for it.
func nonNetworkAssetType(t string) string {
	switch normalizedType(t) {
	case "mobile_app", "android_app", "ios_app":
		return TargetAssetMobileApp
	case "source_code", "source_repo", "repository":
		return TargetAssetRepo
	}
	return ""
}
