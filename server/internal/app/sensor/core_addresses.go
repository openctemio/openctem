package sensor

// Core infrastructure addresses of a tenant's sensors: what each sensor
// reported in its config report's network.core_addresses check (its DNS
// resolvers, gateways, its own address as the platform saw it, the
// platform's addresses). The scan form warns when a scan's targets cover
// one of them: an intrusive scan of a sensor's resolver or gateway can cut
// the sensor off its platform.
//
// Security: read-only, the tenant's own active sensors only (the query is
// tenant-scoped), and only what the sensors reported. Every value is
// re-parsed as an IP address here, so a sensor cannot slip other text into
// the scan form; nothing is resolved or contacted.

import (
	"context"
	"net/netip"

	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// CoreAddressesCheckID is the config check the addresses come from;
// ControlDNSCheckID is the control channel's DNS check.
const (
	CoreAddressesCheckID = "network.core_addresses"
	ControlDNSCheckID    = "runtime.control_dns"
)

// MaxCoreAddressSensors bounds how many sensors the answer covers.
const MaxCoreAddressSensors = 500

// Core address roles (the check's parameter names, singular).
const (
	CoreRoleResolver     = "resolver"
	CoreRoleToolResolver = "tool_resolver"
	CoreRoleGateway      = "gateway"
	CoreRoleHost         = "host"
	CoreRolePlatform     = "platform"
)

// coreParamRoles maps the check's parameters to roles, in display order.
var coreParamRoles = []struct{ param, role string }{
	{"resolvers", CoreRoleResolver},
	{"tool_resolvers", CoreRoleToolResolver},
	{"gateways", CoreRoleGateway},
	{"host_addrs", CoreRoleHost},
	{"platform_addrs", CoreRolePlatform},
}

// CoreAddress is one address and what it is to the sensor.
type CoreAddress struct {
	Address string
	Role    string
}

// SensorCoreAddresses are one sensor's core addresses.
type SensorCoreAddresses struct {
	SensorID   string
	SensorName string
	Addresses  []CoreAddress
}

// CoreAddresses returns the core infrastructure addresses the tenant's
// active sensors reported; empty when none did or reports are not stored.
func (s *SensorService) CoreAddresses(ctx context.Context, tenantID string) ([]SensorCoreAddresses, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, shared.ErrNotFound
	}
	lister, ok := s.repo.(sensordom.ConfigCheckLister)
	if !ok {
		return []SensorCoreAddresses{}, nil
	}
	checks, err := lister.ListConfigChecks(ctx, tid, CoreAddressesCheckID, MaxCoreAddressSensors)
	if err != nil {
		return nil, err
	}
	out := make([]SensorCoreAddresses, 0, len(checks))
	for _, c := range checks {
		if c.Check.Status != sensordom.CheckPass {
			continue
		}
		item := SensorCoreAddresses{SensorID: c.SensorID.String(), SensorName: c.SensorName}
		seen := map[string]bool{}
		for _, pr := range coreParamRoles {
			for _, v := range c.Check.Params[pr.param].Names {
				a, err := netip.ParseAddr(v)
				if err != nil || a.Zone() != "" {
					continue
				}
				a = a.Unmap()
				key := a.String() + " " + pr.role
				if seen[key] {
					continue
				}
				seen[key] = true
				item.Addresses = append(item.Addresses, CoreAddress{Address: a.String(), Role: pr.role})
			}
		}
		if len(item.Addresses) > 0 {
			out = append(out, item)
		}
	}
	return out, nil
}
