package ingest

// Properties on the wrong asset (RFC-042 §6.3.9,
// docs/rfcs/RFC-042-asset-inventory-v2.md).
//
// The property schema restricts some keys to the classes they describe: a
// `port` (and the service keys that come with it) belongs to a service, not
// to the domain, host or address a scanner named. A nuclei result, for
// example, names its host and adds the port it reached, and that port used to
// be stored on the domain. Before the report's assets are stored:
//
//   - a port on a domain, subdomain, host or IP address becomes an open_port
//     service asset "<host>:<port>/<proto>" carrying the moved keys (with
//     the port's protocol and transport), linked
//     from the asset by an `exposes` edge (a related_assets link, so the edge
//     follows the same rules as any other report link);
//   - any other misplaced key (an HTTP status code, which an open port does
//     not hold), or a port that is not a port, is dropped.
//
// The routed service is an ordinary report asset: exclusions, attribution and
// the bound command's targets apply to it as to the rest of the report, so
// routing never lets a report write anything it could not have reported
// directly. Each report asset adds at most one routed service.

import (
	"fmt"
	"net"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
)

// protoTCP is the transport a routed port gets when the report names none.
const protoTCP = "tcp"

// portCompanionKeys move with a misplaced port.
var portCompanionKeys = []string{"protocol", "transport"}

// maxUnknownKeysLogged bounds the property keys one report's warning lists.
const maxUnknownKeysLogged = 20

// portHolderTypes are the stored types whose misplaced port is routed to a
// service they expose.
var portHolderTypes = map[asset.AssetType]bool{
	asset.AssetTypeDomain:    true,
	asset.AssetTypeSubdomain: true,
	asset.AssetTypeHost:      true,
	asset.AssetTypeIPAddress: true,
}

// routeMisplacedProperties applies the rules above to every asset the report
// carries. It also folds property synonyms, so the checks see canonical keys.
// It returns the number of services it added, the number of keys it dropped
// and, sorted, the keys outside their type's schema (kept, for a warning).
func routeMisplacedProperties(report *ctis.Report) (added, dropped int, unknown []string) {
	if report == nil {
		return 0, 0, nil
	}
	present := map[string]bool{}
	for i := range report.Assets {
		if report.Assets[i].Type == ctis.AssetTypeOpenPort {
			present[portKey(getAssetName(&report.Assets[i]))] = true
		}
	}
	tool := ""
	if report.Tool != nil {
		tool = report.Tool.Name
	}
	unknownSet := map[string]bool{}
	n := len(report.Assets)
	for i := 0; i < n; i++ {
		a := &report.Assets[i]
		if len(a.Properties) == 0 {
			continue
		}
		asset.NormalizeProperties(a.Properties)
		stored := resolveCTISAssetType(a).stored
		for _, k := range asset.UnknownPropertyKeys(stored.Type, stored.SubType, a.Properties) {
			unknownSet[k] = true
		}
		keys := asset.MisplacedPropertyKeys(stored.Type, stored.SubType, a.Properties)
		if len(keys) == 0 {
			continue
		}
		// The protocol and transport of a misplaced port describe that port:
		// they go with it.
		if slices.Contains(keys, "port") {
			for _, k := range portCompanionKeys {
				if _, ok := a.Properties[k]; ok {
					keys = append(keys, k)
				}
			}
		}
		moved := make(map[string]any, len(keys))
		for _, k := range keys {
			moved[k] = a.Properties[k]
			delete(a.Properties, k)
		}
		svc, kept := routedPortAsset(a, stored.Type, moved, tool)
		dropped += len(keys) - kept
		if svc == nil {
			continue
		}
		if key := portKey(svc.Name); !present[key] {
			present[key] = true
			report.Assets = append(report.Assets, *svc)
			added++
			a = &report.Assets[i] // the append may have moved the slice
		}
		if a.ID == "" {
			a.ID = fmt.Sprintf("routed-src-%d", i)
		}
		a.RelatedAssets = append(a.RelatedAssets, svc.ID)
	}
	for k := range unknownSet {
		unknown = append(unknown, k)
	}
	sort.Strings(unknown)
	if len(unknown) > maxUnknownKeysLogged {
		unknown = unknown[:maxUnknownKeysLogged]
	}
	return added, dropped, unknown
}

// routedPortAsset builds the open_port asset a misplaced port belongs to,
// with the moved keys an open port may hold, and says how many it kept. It
// is nil when there is none: the holder is not a domain, host or address,
// or the port is not a port.
func routedPortAsset(a *ctis.Asset, storedType asset.AssetType, moved map[string]any, tool string) (*ctis.Asset, int) {
	if !portHolderTypes[storedType] {
		return nil, 0
	}
	port, ok := portNumber(moved["port"])
	if !ok {
		return nil, 0
	}
	host := hostOf(getAssetName(a))
	if host == "" {
		return nil, 0
	}
	proto := protoTCP
	for _, k := range []string{"protocol", "transport"} {
		if s, ok := moved[k].(string); ok {
			if s = strings.ToLower(strings.TrimSpace(s)); s == protoTCP || s == "udp" || s == "sctp" {
				proto = s
				break
			}
		}
	}
	name := portAssetName(host, port, proto)
	allowed := asset.PropertyKeysOf(asset.AssetTypeService, "open_port")
	props := ctis.Properties{}
	kept := 0
	for k, v := range moved {
		if allowed[k] {
			props[k] = v
			kept++
		}
	}
	props["host"] = host
	props["port"] = port
	props["protocol"] = proto
	if tool != "" {
		props[asset.PropKeyDiscoveryTool] = tool
	}
	return &ctis.Asset{
		ID:           "routed-port-" + strings.NewReplacer(":", "-", "/", "-", "[", "", "]", "").Replace(name),
		Type:         ctis.AssetTypeOpenPort,
		Value:        name,
		Name:         name,
		Criticality:  a.Criticality,
		Confidence:   a.Confidence,
		DiscoveredAt: a.DiscoveredAt,
		Properties:   props,
	}, kept
}

// portNumber reads a port a scanner sent as a number or a string.
func portNumber(v any) (int, bool) {
	var n int
	switch x := v.(type) {
	case int:
		n = x
	case int64:
		n = int(x)
	case float64:
		if x != float64(int(x)) {
			return 0, false
		}
		n = int(x)
	case string:
		i, err := strconv.Atoi(strings.TrimSpace(x))
		if err != nil {
			return 0, false
		}
		n = i
	default:
		return 0, false
	}
	return n, n >= 1 && n <= 65535
}

// hostOf is the host a report asset names: the host of a URL, an address,
// or a DNS name ("" when it is none of them).
func hostOf(name string) string {
	name = asset.HostOf(name)
	if net.ParseIP(name) != nil {
		return name
	}
	if !isValidDomainName(name) {
		return ""
	}
	return name
}
