package proxypool

// Scanner addresses (docs/architecture/sensor-proxies.md, "Scanner
// addresses"): the addresses an organization's scans leave from, for a
// target owner to allowlist at a WAF or edge protection.
//
// Only addresses the platform observed itself are listed:
//   - a proxy endpoint's exit: the platform's echo records every address it
//     answers for a live proxy test (RecordTestEcho); when the test
//     finishes, the exit the sensor reports for an endpoint is kept only if
//     the echo saw that address for the same test (VerifiedExits). A sensor
//     cannot make the platform list an address that never reached the echo
//     with the test's secret, tenant-bound token;
//   - a sensor's own address: the client address of its heartbeats and
//     authenticated requests (trusted-proxy rule, never a header it sets);
//   - shared sensors: the egress the instance administrator published, for
//     an organization allowed to use them.

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	pooldom "github.com/openctemio/openctem/api/pkg/domain/proxypool"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Kinds of scanner address.
const (
	AddressKindProxyExit = "proxy_exit"
	AddressKindSensor    = "sensor"
	AddressKindPlatform  = "platform"
)

// PlatformEgress is a published list of shared-sensor egress addresses (IP
// or CIDR); Region empty for the global list.
type PlatformEgress struct {
	Region    string
	Addresses []string
}

// PlatformEgressSource returns the shared-sensor egress an organization may
// allowlist: nothing when it may not use shared sensors.
type PlatformEgressSource func(ctx context.Context, tenantID shared.ID) ([]PlatformEgress, error)

// ScannerAddress is one address scans of the organization leave from.
type ScannerAddress struct {
	// Address is an IP address, or a CIDR for a published platform range.
	Address string
	// CIDR is Address as a prefix (/32 or /128 for an address).
	CIDR string
	Kind string
	// Private: not a public address (a self-managed install on an internal
	// network sees private addresses).
	Private       bool
	PoolID        string
	PoolName      string
	EndpointID    string
	EndpointLabel string
	SensorID      string
	SensorName    string
	Region        string
	LastSeenAt    *time.Time
}

// ScannerAddresses is the organization's scanner addresses and the unique
// prefixes to allowlist, sorted.
type ScannerAddresses struct {
	Items []ScannerAddress
	CIDRs []string
}

// EnableScannerAddresses wires the exit store and, optionally, the shared
// sensors' published egress. Without the store RecordTestEcho does nothing
// and ScannerAddresses lists only the platform egress.
func (s *Service) EnableScannerAddresses(store pooldom.ExitStore, platform PlatformEgressSource) {
	s.exits = store
	s.platformEgress = platform
}

// RecordTestEcho records the address the echo answered for a verified live
// proxy_test command. Errors are logged, never returned to the echo caller.
func (s *Service) RecordTestEcho(ctx context.Context, tenantID, commandID, address string) {
	if s.exits == nil {
		return
	}
	tid, err1 := shared.IDFromString(tenantID)
	cid, err2 := shared.IDFromString(commandID)
	addr, err3 := netip.ParseAddr(strings.TrimSpace(address))
	if err1 != nil || err2 != nil || err3 != nil || addr.Zone() != "" {
		return
	}
	if err := s.exits.RecordEchoObservation(ctx, tid, cid, addr.Unmap(), s.now()); err != nil {
		s.logger.Warn("proxy test echo not recorded", "tenant_id", tenantID, "command_id", commandID, "error", err)
	}
}

// recordVerifiedExits keeps the exits a finished test reports where the
// echo saw the same address for this test, and returns how many were kept
// and how many claims were dropped.
func (s *Service) recordVerifiedExits(ctx context.Context, c *commanddom.Command) (kept, dropped int) {
	if s.exits == nil || c == nil || c.Status != commanddom.CommandStatusCompleted {
		return 0, 0
	}
	poolID, ok := testPoolOf(c)
	if !ok {
		return 0, 0
	}
	p, err := s.testPoolFor(ctx, c, poolID)
	if err != nil {
		return 0, 0
	}
	byID := make(map[string]*pooldom.Endpoint, len(p.Endpoints))
	for _, e := range p.Endpoints {
		byID[e.ID.String()] = e
	}
	results := testResultsOf(c, byID)
	claimed := make([]pooldom.EndpointExit, 0, len(results))
	for _, r := range results {
		if !r.OK || r.ExitIP == "" {
			continue
		}
		a, err := netip.ParseAddr(r.ExitIP)
		if err != nil {
			continue
		}
		claimed = append(claimed, pooldom.EndpointExit{EndpointID: shared.MustIDFromString(r.EndpointID), Address: a})
	}
	observed, err := s.exits.EchoObservations(ctx, c.TenantID, c.ID)
	if err != nil {
		s.logger.Warn("proxy test echo observations not read", "tenant_id", c.TenantID.String(), "error", err)
		return 0, len(claimed)
	}
	verified := pooldom.VerifiedExits(claimed, observed)
	if err := s.exits.RecordEndpointExits(ctx, c.TenantID, p.ID, c.ID, verified, s.now()); err != nil {
		s.logger.Warn("proxy endpoint exits not recorded", "tenant_id", c.TenantID.String(), "error", err)
		return 0, len(claimed)
	}
	return len(verified), len(claimed) - len(verified)
}

// ScannerAddresses lists the addresses the organization's scans leave from.
func (s *Service) ScannerAddresses(ctx context.Context, tenantID string) (*ScannerAddresses, error) {
	tid, err := parseTenant(tenantID)
	if err != nil {
		return nil, err
	}
	out := &ScannerAddresses{Items: []ScannerAddress{}, CIDRs: []string{}}
	now := s.now()
	if s.exits != nil {
		exits, err := s.exits.ListEndpointExits(ctx, tid, now.Add(-pooldom.ExitRetention))
		if err != nil {
			return nil, fmt.Errorf("read proxy exit addresses: %w", err)
		}
		for _, x := range exits {
			seen := x.LastSeenAt
			out.Items = append(out.Items, ScannerAddress{Address: x.Address.String(), CIDR: hostPrefix(x.Address),
				Kind: AddressKindProxyExit, Private: !publicAddr(x.Address), PoolID: x.PoolID.String(), PoolName: x.PoolName,
				EndpointID: x.EndpointID.String(), EndpointLabel: x.EndpointLabel, LastSeenAt: &seen})
		}
		sensors, err := s.exits.ListSensorEgress(ctx, tid, now.Add(-pooldom.SensorEgressWindow))
		if err != nil {
			return nil, fmt.Errorf("read sensor addresses: %w", err)
		}
		for _, x := range sensors {
			out.Items = append(out.Items, ScannerAddress{Address: x.Address.String(), CIDR: hostPrefix(x.Address),
				Kind: AddressKindSensor, Private: !publicAddr(x.Address), SensorID: x.SensorID.String(),
				SensorName: x.SensorName, LastSeenAt: x.LastSeenAt})
		}
	}
	if s.platformEgress != nil {
		groups, err := s.platformEgress(ctx, tid)
		if err != nil {
			return nil, fmt.Errorf("read shared sensor addresses: %w", err)
		}
		for _, g := range groups {
			for _, raw := range g.Addresses {
				cidr, priv, ok := parseEgress(raw)
				if !ok {
					continue
				}
				out.Items = append(out.Items, ScannerAddress{Address: strings.TrimSpace(raw), CIDR: cidr,
					Kind: AddressKindPlatform, Private: priv, Region: g.Region})
			}
		}
	}
	for _, it := range out.Items {
		if !slices.Contains(out.CIDRs, it.CIDR) {
			out.CIDRs = append(out.CIDRs, it.CIDR)
		}
	}
	slices.SortFunc(out.CIDRs, comparePrefixes)
	return out, nil
}

func hostPrefix(a netip.Addr) string {
	return netip.PrefixFrom(a, a.BitLen()).String()
}

// publicAddr: a global unicast address that is not private.
func publicAddr(a netip.Addr) bool {
	return a.IsGlobalUnicast() && !a.IsPrivate()
}

// parseEgress reads a published address or CIDR as a masked prefix.
func parseEgress(raw string) (cidr string, private, ok bool) {
	raw = strings.TrimSpace(raw)
	if a, err := netip.ParseAddr(raw); err == nil && a.Zone() == "" {
		a = a.Unmap()
		return hostPrefix(a), !publicAddr(a), true
	}
	if p, err := netip.ParsePrefix(raw); err == nil {
		p = p.Masked()
		return p.String(), !publicAddr(p.Addr()), true
	}
	return "", false, false
}

// comparePrefixes orders IPv4 before IPv6, then by address and length.
func comparePrefixes(a, b string) int {
	pa, errA := netip.ParsePrefix(a)
	pb, errB := netip.ParsePrefix(b)
	if errA != nil || errB != nil {
		return strings.Compare(a, b)
	}
	if c := pa.Addr().Compare(pb.Addr()); c != 0 {
		return c
	}
	return pa.Bits() - pb.Bits()
}
