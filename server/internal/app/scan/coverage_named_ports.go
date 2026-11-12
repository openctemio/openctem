package scan

// Named ports in continuous coverage: a port scan of a host name stores each
// open port on the address it was found on ("<address>:<port>", the name
// resolves_to the address). The coverage HTTP probe of the name alone covers
// only the scheme's default ports, and a probe of "<address>:<port>" misses a
// virtual host, CDN or load balancer that routes by name (TLS SNI, the Host
// header). So a coverage batch of the HTTP probe also probes
// "<name>:<port>" for each other open TCP port of the addresses each name of
// the batch resolves to. The same rule applies to workflows
// (scanrun/hop_named_ports.go).
//
// Security: the name is one the batch already kept (it passed the gate as a
// coverage target), never a new one; the ports come from the tenant's own
// inventory (a tenant-scoped lookup). Every "<name>:<port>" goes through the
// same gate call as the batch (validator, exclusions in host:port form, name
// ownership, scope entries and tier, zones) and only the ones it allows are
// added. A failed lookup or a refusal of the derived set as a whole leaves
// the batch exactly as it was.

import (
	"context"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// maxNamedPortsPerName caps the ports added for one name.
const maxNamedPortsPerName = 20

// maxNamedPortNames caps the names one lookup asks about.
const maxNamedPortNames = maxCoverageTargets

// NamePortReader reads the open TCP ports of the live addresses each of
// the tenant's live domain or subdomain assets of the given names (matched
// case-insensitively, keyed lower-case) resolves to. Tenant-scoped on every
// table; a name with none is absent.
type NamePortReader interface {
	OpenPortsOfNames(ctx context.Context, tenantID shared.ID, names []string) (map[string][]int, error)
}

// SetNamePorts wires the lookup of a name's open ports. Unset, a coverage
// batch probes the names alone.
func (s *Service) SetNamePorts(r NamePortReader) { s.namePorts = r }

// probeDefaultPorts are the ports the probe of a bare name already tries.
var probeDefaultPorts = map[int]bool{80: true, 443: true}

// namedPortCandidates returns "<name>:<port>" for the open ports of the
// addresses each host name among kept resolves to, other than the probe's
// default ports, at most maxNamedPortsPerName per name and room in all, in a
// stable order. Only the HTTP probe takes them. A failed lookup is logged
// and yields none.
func (s *Service) namedPortCandidates(ctx context.Context, tenantID shared.ID, capability string, kept []string, room int) []string {
	if s.namePorts == nil || stage.Key(capability) != stage.ProbeHTTP || room <= 0 {
		return nil
	}
	seen := map[string]bool{}
	names := make([]string, 0, len(kept))
	for _, t := range kept {
		n := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(t), "."))
		if n == "" || seen[n] || strings.ContainsAny(n, ":/[]@ ") {
			continue // an address with a port, a URL, an IPv6 literal
		}
		if _, err := netip.ParseAddr(n); err == nil {
			continue // an address: its ports are probed by address
		}
		seen[n] = true
		names = append(names, n)
	}
	if len(names) == 0 || len(names) > maxNamedPortNames {
		return nil
	}
	ports, err := s.namePorts.OpenPortsOfNames(ctx, tenantID, names)
	if err != nil {
		s.logger.Warn("coverage: open ports of names could not be read; names are probed alone",
			"tenant_id", tenantID.String(), "error", logger.SanitizeError(err))
		return nil
	}
	sort.Strings(names)
	var out []string
	for _, n := range names {
		ps := append([]int(nil), ports[n]...)
		sort.Ints(ps)
		added := 0
		last := 0
		for _, p := range ps {
			if p < 1 || p > 65535 || p == last || probeDefaultPorts[p] {
				continue
			}
			last = p
			if added >= maxNamedPortsPerName {
				break
			}
			out = append(out, net.JoinHostPort(n, strconv.Itoa(p)))
			added++
			if len(out) >= room {
				return out
			}
		}
	}
	return out
}

// withNamedPorts returns kept plus the named ports of its names that the
// gate allows (gateIn: the batch's own gate input). A refusal of the derived
// set as a whole is logged and changes nothing.
func (s *Service) withNamedPorts(ctx context.Context, in CoverageInput, gateIn DispatchTargetsInput, kept []string) []string {
	named := s.namedPortCandidates(ctx, in.TenantID, in.Capability, kept, maxCoverageTargets-len(kept))
	if len(named) == 0 {
		return kept
	}
	gateIn.Targets = named
	gateIn.MaxTargets = len(named)
	more, err := s.ResolveDispatchTargets(ctx, gateIn)
	if err != nil {
		s.logger.Warn("coverage: named ports not checked, names are probed alone",
			"tenant_id", in.TenantID.String(), "error", logger.SanitizeError(err))
		return kept
	}
	ok := make(map[string]bool, len(more.Allowed))
	for _, t := range more.Allowed {
		ok[strings.ToLower(t)] = true
	}
	for _, t := range named {
		if ok[t] {
			kept = append(kept, t)
		}
	}
	return kept
}
