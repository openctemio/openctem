package asset

import (
	"slices"
	"testing"
)

// Every network device sub-type is a sub-type of the network type in the
// registry, and segments are not devices.
func TestNetworkDeviceSubTypes(t *testing.T) {
	d, ok := LookupType(AssetTypeNetwork)
	if !ok {
		t.Fatal("network type missing from the registry")
	}
	for _, s := range NetworkDeviceSubTypes() {
		if !slices.Contains(d.SubTypes, s) {
			t.Errorf("device sub-type %q is not a network sub-type %v", s, d.SubTypes)
		}
	}
	for _, s := range []string{"vpc", "subnet", "ip_block", "vlan", "security_group", ""} {
		if IsNetworkDeviceSubType(s) {
			t.Errorf("%q counted as a device", s)
		}
	}
}
