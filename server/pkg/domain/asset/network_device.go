package asset

import "slices"

// networkDeviceSubTypes are the network sub-types that are devices, the
// second family of the network type in configs/asset-types.yaml (the first
// is segments: VPCs, subnets, address blocks, VLANs, security groups).
var networkDeviceSubTypes = []string{
	"access_point", "firewall", "ids_ips", "load_balancer", "router", "switch", "vpn_gateway", "wireless_controller",
}

// NetworkDeviceSubTypes lists the network device sub-types, sorted.
func NetworkDeviceSubTypes() []string { return slices.Clone(networkDeviceSubTypes) }

// IsNetworkDeviceSubType reports whether a network sub-type is a device.
func IsNetworkDeviceSubType(subType string) bool {
	return slices.Contains(networkDeviceSubTypes, subType)
}
