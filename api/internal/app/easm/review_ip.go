package easm

// Review rows for addresses (RFC-054 §4.3, §6.6): an IP address never
// inherits from the names that resolve to it, so it stays in review even
// when every such name is in scope. The row says why and offers the fix:
//
//   - resolved_from: the caller's in-scope names that resolve to the address;
//   - network: the ASN and its organization we already hold (no network
//     call at request time) and whether it is shared CDN or cloud space;
//   - fixes: "add this IP" (and "add the /24 or /48 around it" only when the
//     ASN organization matches the organization's name), through the normal
//     scope entry path (POST /scope/targets: approvers with step-up and the
//     approval count; a member requests a one-off). Shared CDN or cloud
//     addresses get no fix: they serve other organizations too.
//
// Everything is tenant-scoped and limited to the caller's data scope (the
// store applies it); the fixes are only the ones the caller may take.

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ReviewNetwork is what we hold about the network of an address.
type ReviewNetwork struct {
	ASN string `json:"asn,omitempty"`
	// Org is the ASN organization (the address owner as routed).
	Org string `json:"org,omitempty"`
	// Shared: CDN or cloud-provider space that serves many organizations.
	Shared         bool   `json:"shared"`
	SharedProvider string `json:"shared_provider,omitempty"`
	// OrgMatches: the ASN organization matches this organization's name, so
	// the range around the address is offered as a fix.
	OrgMatches bool `json:"org_matches"`
}

// ReviewCaller is what the caller may do with a fix (set by the handler from
// the token; never from the request).
type ReviewCaller struct {
	CanApprove bool // attack_surface:scope:approve
	CanRequest bool // attack_surface:scope:write
}

// AddressFacts are the stored facts of the tenant's address assets.
type AddressFacts struct {
	Props map[string]any
}

// ReviewAddressStore reads what explains an address row
// (*postgres.AttributionRepository).
type ReviewAddressStore interface {
	// ResolvedFrom maps each address to the tenant's names that resolve to
	// it (resolves_to edges), only names in the caller's data scope.
	ResolvedFrom(ctx context.Context, tenantID shared.ID, scope *shared.DataScope, addrs []string) (map[string][]string, error)
	// AddressProps maps each address to the properties of its ip_address
	// asset in the tenant (asn, asn_org, cdn).
	AddressProps(ctx context.Context, tenantID shared.ID, addrs []string) (map[string]map[string]any, error)
}

// OrgNamer returns the organization's display name.
type OrgNamer func(ctx context.Context, tenantID shared.ID) (string, error)

// SetAddressExplainer wires the address rows' explanation. Without it the
// rows carry no resolved_from, network or fixes.
func (s *ReviewService) SetAddressExplainer(st ReviewAddressStore, org OrgNamer) {
	s.addrs, s.orgName = st, org
}

// HintIPNeedsIPEntry is the review hint of an address row: names never
// grant their addresses; an IP, range or CIDR scope entry must cover it.
const HintIPNeedsIPEntry = "ip_needs_ip_entry"

// maxResolvedFrom bounds resolved_from per row.
const maxResolvedFrom = 10

// explainAddresses fills resolved_from, network, hint and fixes on the
// page's address rows (an ip_address, or a service on an address).
func (s *ReviewService) explainAddresses(ctx context.Context, tenantID shared.ID, scope *shared.DataScope, caller ReviewCaller, page *ReviewPage) error {
	if s.addrs == nil || page == nil {
		return nil
	}
	rows := map[string][]int{}
	addrs := []string{}
	for i, it := range page.Items {
		a, err := netip.ParseAddr(asset.HostOf(it.Name))
		if err != nil {
			continue
		}
		key := a.Unmap().String()
		if _, seen := rows[key]; !seen {
			addrs = append(addrs, key)
		}
		rows[key] = append(rows[key], i)
	}
	if len(addrs) == 0 {
		return nil
	}
	resolved, err := s.addrs.ResolvedFrom(ctx, tenantID, scope, addrs)
	if err != nil {
		return fmt.Errorf("names that resolve to review addresses: %w", err)
	}
	props, err := s.addrs.AddressProps(ctx, tenantID, addrs)
	if err != nil {
		return fmt.Errorf("review address facts: %w", err)
	}
	// Only in-scope names explain the row ("these names are yours, the
	// address still needs its own entry").
	inScope := map[string]bool{}
	if s.coverage != nil {
		names := []string{}
		for _, ns := range resolved {
			names = append(names, ns...)
		}
		if len(names) > 0 {
			cover, err := s.coverage.CoverOf(ctx, tenantID, names)
			if err != nil {
				return fmt.Errorf("review coverage of resolving names: %w", err)
			}
			for n := range cover {
				inScope[n] = true
			}
		}
	}
	org := ""
	if s.orgName != nil {
		if org, err = s.orgName(ctx, tenantID); err != nil {
			return fmt.Errorf("organization name: %w", err)
		}
	}
	for _, addr := range addrs {
		from := make([]string, 0, maxResolvedFrom)
		for _, n := range resolved[addr] {
			if inScope[n] && len(from) < maxResolvedFrom {
				from = append(from, n)
			}
		}
		net := addressNetwork(props[addr], org)
		for _, i := range rows[addr] {
			it := &page.Items[i]
			it.ResolvedFrom = from
			it.Network = net
			if it.CoveredBy != nil {
				continue // already covered: nothing to fix
			}
			it.Hint = HintIPNeedsIPEntry
			it.Fixes = addressFixes(addr, net, caller)
		}
	}
	return nil
}

func addressNetwork(props map[string]any, org string) *ReviewNetwork {
	n := &ReviewNetwork{}
	if props != nil {
		n.ASN = strings.TrimSpace(asnHint(map[string]any{"asn": props["asn"]}))
		n.Org, _ = props["asn_org"].(string)
		n.Shared, n.SharedProvider = sharedAddress(props)
	}
	n.OrgMatches = !n.Shared && orgMatches(org, n.Org)
	return n
}

// addressFixes are the scope entry fixes the caller may take for addr.
func addressFixes(addr string, net *ReviewNetwork, caller ReviewCaller) []scopedom.Fix {
	if net != nil && net.Shared {
		return []scopedom.Fix{} // shared space: never offered (other organizations' hosts)
	}
	out := []scopedom.Fix{}
	switch {
	case caller.CanApprove:
		out = append(out, scopedom.Fix{Action: scopedom.FixAddEntry, TargetType: string(scopedom.TargetTypeIPAddress),
			Pattern: addr, Requires: permission.ScopeApprove.String()})
		if net != nil && net.OrgMatches {
			if r := rangeAround(addr); r != "" {
				out = append(out, scopedom.Fix{Action: scopedom.FixAddEntry, TargetType: string(scopedom.TargetTypeCIDR),
					Pattern: r, Requires: permission.ScopeApprove.String()})
			}
		}
	case caller.CanRequest:
		out = append(out, scopedom.Fix{Action: scopedom.FixRequestAccess, TargetType: string(scopedom.TargetTypeIPAddress),
			Pattern: addr, Days: 7, Requires: permission.ScopeWrite.String()})
	}
	return out
}

// rangeAround is the /24 (IPv4) or /48 (IPv6) that holds addr.
func rangeAround(addr string) string {
	a, err := netip.ParseAddr(addr)
	if err != nil {
		return ""
	}
	bits := 48
	if a.Is4() {
		bits = 24
	}
	p, err := a.Prefix(bits)
	if err != nil {
		return ""
	}
	return p.String()
}

// orgNoise are words that say nothing about which organization it is.
var orgNoise = func() map[string]bool {
	m := map[string]bool{}
	for _, w := range strings.Fields("the and company corporation corp inc ltd limited llc joint stock group holding holdings " +
		"jsc plc gmbh network networks services service technology technologies telecom communications internet " +
		"vietnam viet nam international global online") {
		m[w] = true
	}
	return m
}()

// orgMatches reports whether the ASN organization names this organization:
// a distinctive word (4+ letters or digits, not a generic company word) of
// the organization's name appears among the ASN organization's words.
func orgMatches(org, asnOrg string) bool {
	words := func(s string) []string {
		return strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
			return (r < 'a' || r > 'z') && (r < '0' || r > '9')
		})
	}
	have := map[string]bool{}
	for _, w := range words(asnOrg) {
		have[w] = true
	}
	for _, w := range words(org) {
		if len(w) >= 4 && !orgNoise[w] && have[w] {
			return true
		}
	}
	return false
}
