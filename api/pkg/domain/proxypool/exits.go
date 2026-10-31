package proxypool

// Scanner addresses (docs/architecture/sensor-proxies.md, "Scanner
// addresses"): the addresses an organization's scans leave from, so a
// target owner can allowlist them at a WAF or edge protection.
//
// Every address here is one the platform observed itself: a proxy
// endpoint's exit as the platform's proxy-test echo saw it, and a sensor's
// own address as the platform saw its authenticated requests. A sensor's
// report alone never adds an address: an allowlist built from a value a
// sensor (or the tool it runs) chose could be made to trust any address.

import (
	"context"
	"net/netip"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Bounds of the scanner addresses.
const (
	// MaxEchoObservationsPerTest bounds the addresses one test's echo
	// records (every endpoint, both families, plus the second port).
	MaxEchoObservationsPerTest = 4 * MaxEndpointsPerPool
	// ExitRetention is how long an exit address stays listed after it was
	// last seen.
	ExitRetention = 30 * 24 * time.Hour
	// SensorEgressWindow is how recently a sensor must have been seen for
	// its address to be listed.
	SensorEgressWindow = 30 * 24 * time.Hour
	// EchoObservationTTL is how long an echo observation is kept when its
	// test never finishes.
	EchoObservationTTL = 24 * time.Hour
)

// EndpointExit is an exit address of one endpoint.
type EndpointExit struct {
	EndpointID shared.ID
	Address    netip.Addr
}

// ExitRow is an exit address as listed.
type ExitRow struct {
	PoolID        shared.ID
	PoolName      string
	EndpointID    shared.ID
	EndpointLabel string
	Address       netip.Addr
	FirstSeenAt   time.Time
	LastSeenAt    time.Time
}

// SensorEgressRow is an address the platform saw one of the tenant's own
// sensors connect from.
type SensorEgressRow struct {
	SensorID   shared.ID
	SensorName string
	Address    netip.Addr
	LastSeenAt *time.Time
}

// ExitStore persists echo observations and endpoint exits. Every method is
// tenant-scoped in SQL.
type ExitStore interface {
	// RecordEchoObservation stores an address the echo answered for a
	// proxy_test command of the tenant; a command of another tenant or type
	// stores nothing, and at most MaxEchoObservationsPerTest addresses are
	// kept per command.
	RecordEchoObservation(ctx context.Context, tenantID, commandID shared.ID, addr netip.Addr, at time.Time) error
	// EchoObservations returns the addresses the echo answered for a command.
	EchoObservations(ctx context.Context, tenantID, commandID shared.ID) ([]netip.Addr, error)
	// RecordEndpointExits stores exit addresses of endpoints of a pool (an
	// endpoint that is not the pool's is refused by the schema and skipped),
	// then removes the command's observations and stale ones.
	RecordEndpointExits(ctx context.Context, tenantID, poolID, commandID shared.ID, exits []EndpointExit, at time.Time) error
	// ListEndpointExits returns the tenant's exit addresses last seen since a time.
	ListEndpointExits(ctx context.Context, tenantID shared.ID, since time.Time) ([]ExitRow, error)
	// ListSensorEgress returns the addresses the platform saw the tenant's
	// own active sensors (never shared ones) connect from, for sensors seen
	// since a time.
	ListSensorEgress(ctx context.Context, tenantID shared.ID, since time.Time) ([]SensorEgressRow, error)
}

// VerifiedExits keeps the exits a sensor claimed only where the platform's
// echo observed the address for the same test. Anything else is dropped.
func VerifiedExits(claimed []EndpointExit, observed []netip.Addr) []EndpointExit {
	seen := make(map[netip.Addr]bool, len(observed))
	for _, a := range observed {
		seen[a.Unmap()] = true
	}
	out := make([]EndpointExit, 0, len(claimed))
	dup := map[EndpointExit]bool{}
	for _, c := range claimed {
		c.Address = c.Address.Unmap()
		if !c.Address.IsValid() || c.Address.Zone() != "" || !seen[c.Address] || dup[c] {
			continue
		}
		dup[c] = true
		out = append(out, c)
	}
	return out
}
