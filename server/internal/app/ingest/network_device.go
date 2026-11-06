package ingest

// Network device matching (docs/architecture/asset-identity-resolution.md):
// network devices (firewalls, routers, switches, access points...) are
// reported by monitoring and log collectors under different names, one by
// the device name and another by its management address. A reported device
// is matched to an existing device of the tenant that records the same
// address, inside the same trust window as hosts, and only when exactly one
// device matches. Only devices match devices: a host or an address asset
// with the same IP is never turned into a device, and network segments
// (subnets, VLANs) are never matched by address.

import (
	"context"
	"sort"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// isNetworkDevice reports whether a stored (type, sub-type) is a network device.
func isNetworkDevice(t asset.AssetType, subType string) bool {
	return t == asset.AssetTypeNetwork && asset.IsNetworkDeviceSubType(subType)
}

// CorrelateNetworkDevice finds the existing network device of the tenant
// that records one of the incoming device's addresses (its name when that
// is an address, and its ip_addresses). A device last seen outside the trust
// window does not count; several matching devices are ambiguous (no match).
func (c *AssetCorrelator) CorrelateNetworkDevice(ctx context.Context, tenantID shared.ID, incomingName string,
	properties map[string]any, cfg CorrelationConfig,
) (*CorrelationResult, error) {
	if cfg.StaleAssetDays <= 0 {
		cfg.StaleAssetDays = DefaultIPTrustWindowDays
	}
	if cfg.MaxIPsPerAsset <= 0 {
		cfg.MaxIPsPerAsset = DefaultMaxIPsPerAsset
	}
	ips := ExtractAllIPs(properties, incomingName)
	if len(ips) == 0 {
		return &CorrelationResult{}, nil
	}
	if len(ips) > cfg.MaxIPsPerAsset {
		c.logger.Warn("network device has too many IPs, skipping correlation",
			"name", logger.SanitizeValue(incomingName), "ip_count", len(ips))
		return &CorrelationResult{}, nil
	}
	matched, err := c.repo.FindNetworkDevicesByIPs(ctx, tenantID, ips)
	if err != nil {
		return nil, err
	}
	window := time.Duration(cfg.StaleAssetDays) * 24 * time.Hour
	seen := map[shared.ID]*asset.Asset{}
	for _, devices := range matched {
		for _, a := range devices {
			if a.TenantID() != tenantID || !isNetworkDevice(a.Type(), a.SubType()) {
				continue
			}
			if a.Name() != incomingName && time.Since(a.LastSeen()) > window {
				continue
			}
			seen[a.ID()] = a
		}
	}
	if len(seen) == 0 {
		return &CorrelationResult{}, nil
	}
	devices := make([]*asset.Asset, 0, len(seen))
	for _, a := range seen {
		devices = append(devices, a)
	}
	sort.Slice(devices, func(i, j int) bool { return devices[i].CreatedAt().Before(devices[j].CreatedAt()) })
	if len(devices) > 1 {
		return &CorrelationResult{Ambiguous: devices, CorrelationType: "ip"}, nil
	}
	res := &CorrelationResult{Matched: devices[0], CorrelationType: "ip"}
	if shouldAdoptName(devices[0], incomingName, true) {
		res.ShouldRename, res.NewName = true, incomingName
	}
	return res, nil
}
