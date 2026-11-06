package scanrun

// Named open ports: a port scan of a host name reports each open port on
// the address it found it on (ingest stores "<address>:<port>"), so a
// chained HTTP probe used to receive only the bare "address:port". A
// virtual host, a CDN or a load balancer routes by name (TLS SNI, the Host
// header): probed by address, the service answers with a default page, a
// certificate error or nothing, and the probe of the name alone covers only
// the scheme's default ports. Now the probe also receives "<name>:<port>"
// for each open port on an address that a name the port scan scanned
// resolves to (the inventory's resolves_to relation).
//
// Security: the name is one the predecessor step planned in this run (a
// seed or a target that already passed the gate), never a new one, and
// every "<name>:<port>" candidate goes through the same target gate as any
// derived target (validator, exclusions in host:port form, ownership of the
// name, act scope, tier, zone). The sensor's local policy checks every
// address the name resolves to before it probes. The relation lookup is
// tenant-scoped (AttributionRepository.AddressesOf).

import (
	"context"
	"net"
	"net/netip"
	"sort"
	"strconv"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
)

var openPortRef = asset.TypeRef{Type: asset.AssetTypeService, SubType: "open_port"}

// namedPortOutputs returns outputs plus one "<name>:<port>" open port for
// each open port output on an address that a name among parents (the
// predecessors' planned targets) resolves to. The added outputs name no
// asset (they are checked by name at the gate). Stages that do not take
// open ports, and the web consumers (their open ports become endpoint
// lists by asset), get outputs unchanged. Best effort: a failed lookup is
// logged and the bare address ports still feed the stage.
func (s *Service) namedPortOutputs(ctx context.Context, tenantID shared.ID, st stage.Stage,
	outputs []scanrun.StepOutput, parents []scanrun.RunTarget,
) []scanrun.StepOutput {
	if s.nameAddresses == nil || !st.Accepts(openPortRef) || webConsumers[st.Key] {
		return outputs
	}
	type portOut struct {
		port string
		run  shared.ID
	}
	byAddr := map[string][]portOut{}
	for _, o := range outputs {
		if o.Type != string(asset.AssetTypeService) || o.SubType != "open_port" {
			continue
		}
		h, _, port, ok := openPortHostPort(o.Name)
		if !ok {
			continue
		}
		a, err := netip.ParseAddr(h)
		if err != nil {
			continue // already a named port
		}
		k := a.Unmap().WithZone("").String()
		byAddr[k] = append(byAddr[k], portOut{port: strconv.Itoa(port), run: o.StepRunID})
	}
	if len(byAddr) == 0 {
		return outputs
	}
	seen := map[string]bool{}
	names := make([]string, 0, len(parents))
	for _, p := range parents {
		h := keyHost(p.TargetKey)
		if h == "" || seen[h] {
			continue
		}
		if _, err := netip.ParseAddr(h); err == nil {
			continue
		}
		seen[h] = true
		names = append(names, h)
	}
	if len(names) == 0 || len(names) > maxAliasNames {
		return outputs
	}
	addrsOf, err := s.nameAddresses.AddressesOf(ctx, tenantID, names)
	if err != nil {
		s.logger.Warn("chained stage: resolution relations could not be read; open ports go by address only",
			"tenant_id", tenantID.String(), "error", err)
		return outputs
	}
	sort.Strings(names)
	added := map[string]bool{}
	out := outputs
	for _, n := range names {
		for _, a := range addrsOf[n] {
			addr, err := netip.ParseAddr(a)
			if err != nil {
				continue
			}
			for _, p := range byAddr[addr.Unmap().WithZone("").String()] {
				name := net.JoinHostPort(n, p.port)
				if added[name] {
					continue
				}
				if len(added) >= stage.RunFanoutCap {
					return out
				}
				added[name] = true
				out = append(out, scanrun.StepOutput{StepRunID: p.run, Name: name,
					Type: string(asset.AssetTypeService), SubType: "open_port"})
			}
		}
	}
	return out
}
