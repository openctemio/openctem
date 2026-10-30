package asset

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ResolvedPort is one open port of an address that a host name resolves to:
// name -resolves_to-> address -exposes-> open_port. A port scan of a name
// stores its open ports on the addresses it found them on, so this is how a
// domain or subdomain shows the ports it answers on.
type ResolvedPort struct {
	AddressID shared.ID
	Address   string
	PortID    shared.ID
	Port      int
	// Transport is tcp, udp or sctp ("" when unknown).
	Transport string
	// Service is the service name a scanner identified ("" when unknown).
	Service  string
	Product  string
	Version  string
	LastSeen *time.Time
}

// ResolvedPorts is the answer for one name.
type ResolvedPorts struct {
	Items []ResolvedPort
	// HiddenCount counts open ports left out because the address or the
	// port is outside the caller's data scope.
	HiddenCount int64
	// Truncated is set when more ports exist than Items holds.
	Truncated bool
}

// ResolvedPortReader reads the open ports of the addresses a name resolves
// to. Every table is bound to the tenant; with a restricted scope only rows
// whose address and port are both in it are returned.
type ResolvedPortReader interface {
	ResolvedPorts(ctx context.Context, tenantID, assetID shared.ID, scope *shared.DataScope, limit int) (*ResolvedPorts, error)
}
