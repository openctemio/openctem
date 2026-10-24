package easm

// Platform guardrails for unclassified assets (docs/rfcs/RFC-054-scope-model.md
// §16). An unclassified asset is one no scope entry covers and nobody
// excluded or rejected; while the organization's unclassified-scans
// setting is not off it may get active checks, unless a guardrail keeps it
// passive. The guardrails are platform hazards, not review steps, and no
// tenant setting turns them off:
//
//   - an address in a CDN, shared-hosting or cloud-provider network (its
//     own record says CDN, its network's holder is a provider, or it sits in
//     a published CDN edge range). Neither the organization's name nor a
//     network seed overrides this: both are the tenant's own assertions,
//     and an organization renamed after a CDN must not reach its edges;
//   - an address nothing is known about (no network data): unknown is
//     never read as safe;
//   - an address names of three or more registrable domains resolve to
//     (shared hosting);
//   - a name under none of the organization's registrable domains (its scope
//     entries and verified domains): a third party's name found in a
//     certificate or next to an address;
//   - anything the classifier cannot place (no host, an unreadable name),
//     and every asset when a lookup fails (fail closed).
//
// Wildcard-only names, the platform deny list, exclusions and rejections
// are refused before this check, by the gate itself.

import (
	"context"
	"net/netip"
	"strings"

	"golang.org/x/net/publicsuffix"

	"github.com/openctemio/openctem/api/internal/app/scopeauth"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Guardrail reasons.
const (
	GuardrailSharedNetwork  = "shared_network"
	GuardrailNetworkUnknown = "network_unknown"
	GuardrailSharedHosting  = "shared_hosting"
	GuardrailForeignDomain  = "foreign_domain"
	GuardrailUnplaceable    = "unplaceable"
	GuardrailUnavailable    = "unavailable"
)

// GuardrailNames reads the names that resolve to addresses
// (*postgres.AttributionRepository).
type GuardrailNames interface {
	// NamesResolvingTo maps each of the tenant's address asset ids to the
	// names of the tenant's domain and subdomain assets that resolve to it.
	NamesResolvingTo(ctx context.Context, tenantID shared.ID, addressIDs []string) (map[string][]string, error)
	// AddressesOf maps each of the given names (lower-case) to the
	// addresses the tenant's asset of that name resolves to.
	AddressesOf(ctx context.Context, tenantID shared.ID, names []string) (map[string][]string, error)
}

// UnclassifiedPolicy answers the unclassified-scans mode in force for a
// tenant: tenant.UnclassifiedOff, UnclassifiedLowImpact or UnclassifiedFull
// (off under the Strict scan approval mode). An error is read as off.
type UnclassifiedPolicy func(ctx context.Context, tenantID shared.ID) (string, error)

// Unclassified-scans modes as the gate reads them.
const (
	unclassifiedOff       = "off"
	unclassifiedLowImpact = "low_impact"
	unclassifiedFull      = "full"
)

// SetUnclassified lets active checks reach unclassified assets that pass
// the guardrails (RFC-054 §16): policy answers the tenant's mode; names
// tells shared hosting (nil: an address cannot be told apart from shared
// hosting, so every address is guardrailed). Without a policy the gate
// keeps the rule before §16 (an active check needs a scope entry).
func (g *ActiveGate) SetUnclassified(policy UnclassifiedPolicy, names GuardrailNames) {
	g.unclassified = policy
	g.resolving = names
}

// unclassifiedMode is the tenant's mode; anything unreadable is off.
func (g *ActiveGate) unclassifiedMode(ctx context.Context, tenantID shared.ID) string {
	if g.unclassified == nil {
		return unclassifiedOff
	}
	m, err := g.unclassified(ctx, tenantID)
	if err != nil {
		return unclassifiedOff
	}
	switch m {
	case unclassifiedLowImpact, unclassifiedFull:
		return m
	}
	return unclassifiedOff
}

// guardrailReasons answers, for each asset id in ids (assets already
// loaded, the tenant's), the guardrail that keeps it passive ("" when none
// does). A failed lookup marks every one of them unavailable (fail
// closed). auth is the tenant's loaded authority.
func (g *ActiveGate) guardrailReasons(ctx context.Context, tenantID shared.ID, auth *scopeauth.Authority, ids []string, assets map[string]*asset.Asset) map[string]string {
	out := make(map[string]string, len(ids))
	if len(ids) == 0 {
		return out
	}
	failAll := func() map[string]string {
		for _, id := range ids {
			out[id] = GuardrailUnavailable
		}
		return out
	}
	roots := auth.RegistrableRoots()
	// An asset on an address host (a service "203.0.113.5:443", a URL on an
	// address) is judged by the address asset's network data.
	hostAsset := map[string]*asset.Asset{} // address -> its asset
	var hostNames []string
	addrOf := map[string]string{} // asset id -> address it sits on
	for _, id := range ids {
		a := assets[id]
		if a == nil {
			continue
		}
		h := normalizeHost(asset.HostOf(a.Name()))
		ip, err := netip.ParseAddr(strings.Trim(h, "[]"))
		if err != nil {
			continue
		}
		addr := ip.Unmap().String()
		addrOf[id] = addr
		if a.Type() == asset.AssetTypeIPAddress && normalizeHost(a.Name()) == h {
			hostAsset[addr] = a
		} else {
			hostNames = append(hostNames, h)
		}
	}
	if len(hostNames) > 0 {
		found, err := g.assets.GetByNames(ctx, tenantID, hostNames)
		if err != nil {
			return failAll()
		}
		for n, a := range found {
			if a == nil {
				continue
			}
			if ip, err := netip.ParseAddr(strings.Trim(n, "[]")); err == nil {
				hostAsset[ip.Unmap().String()] = a
			}
		}
	}
	// Names resolving to each address asset (shared hosting).
	resolving := map[string][]string{}
	if len(hostAsset) > 0 && g.resolving != nil {
		addrIDs := make([]string, 0, len(hostAsset))
		for _, a := range hostAsset {
			addrIDs = append(addrIDs, a.ID().String())
		}
		var err error
		if resolving, err = g.resolving.NamesResolvingTo(ctx, tenantID, addrIDs); err != nil {
			return failAll()
		}
	}
	for _, id := range ids {
		a := assets[id]
		if a == nil {
			out[id] = GuardrailUnplaceable
			continue
		}
		if addr, ok := addrOf[id]; ok {
			ha := hostAsset[addr]
			var names []string
			if ha != nil {
				names = resolving[ha.ID().String()]
			}
			out[id] = addressGuardrail(addr, ha, names, g.resolving != nil)
			continue
		}
		out[id] = nameGuardrail(a.Name(), roots)
	}
	return out
}

// addressGuardrail is the guardrail for an address ("" when none applies):
// ha is its asset (nil: nothing is known about it), names the names that
// resolve to it, namesKnown whether those could be read at all.
func addressGuardrail(addr string, ha *asset.Asset, names []string, namesKnown bool) string {
	if edgeRangeProvider(addr) != "" {
		return GuardrailSharedNetwork
	}
	if ha == nil {
		return GuardrailNetworkUnknown
	}
	props := ha.Properties()
	if shared, _ := sharedAddress(props); shared {
		return GuardrailSharedNetwork
	}
	asn := strings.TrimSpace(asnHint(map[string]any{"asn": props["asn"]}))
	org, _ := props["asn_org"].(string)
	if asn == "" && strings.TrimSpace(org) == "" {
		return GuardrailNetworkUnknown
	}
	if !namesKnown {
		return GuardrailSharedHosting // cannot tell: fail closed
	}
	if registrableDomains(names) >= sharedDomainThreshold {
		return GuardrailSharedHosting
	}
	return ""
}

// nameGuardrail is the guardrail for a named asset ("" when none applies):
// its host must sit under one of the organization's registrable domains.
func nameGuardrail(name string, roots map[string]bool) string {
	h := scopeauth.Host(name)
	if h == "" {
		return GuardrailUnplaceable
	}
	reg, err := publicsuffix.EffectiveTLDPlusOne(h)
	if err != nil || !roots[reg] {
		return GuardrailForeignDomain
	}
	return ""
}

// GuardrailOf answers why each given asset is kept passive by a guardrail
// (RFC-054 §16): the reason for an unclassified asset a guardrail holds,
// nothing for an asset a scope entry covers, one a guardrail does not hold,
// and another tenant's or an unknown id. For the asset page badge and the
// suggestion cards; the gate itself decides with ActiveCheckBlocked.
func (g *ActiveGate) GuardrailOf(ctx context.Context, tenantID shared.ID, ids []shared.ID) (map[string]string, error) {
	if err := g.ready(); err != nil {
		return nil, err
	}
	out := map[string]string{}
	if len(ids) == 0 {
		return out, nil
	}
	if len(ids) > maxGateItems {
		return nil, shared.NewDomainError("TOO_MANY", "too many assets for one guardrail lookup", shared.ErrValidation)
	}
	assets, err := g.assets.GetByIDs(ctx, tenantID, ids)
	if err != nil {
		return nil, err
	}
	auth, err := scopeauth.Load(ctx, tenantID, g.scope, g.roots)
	if err != nil {
		return nil, err
	}
	candidates := make([]string, 0, len(ids))
	var certs []*asset.Asset
	for _, id := range ids {
		a := assets[id.String()]
		if a == nil { // another tenant's or unknown (the lookup is tenant-scoped)
			continue
		}
		if a.Type() == asset.AssetTypeCertificate {
			certs = append(certs, a)
			continue
		}
		if _, ok := auth.Covers(a.Name()); ok {
			continue
		}
		candidates = append(candidates, id.String())
	}
	// A certificate is held only as far as every endpoint that served it
	// is: it shows the guardrail of its strongest-refused endpoint.
	judged, err := g.judgeCertificates(ctx, tenantID, certs)
	if err != nil {
		return nil, err
	}
	for id, j := range judged {
		if h := j.standing.HeldBy; h != nil && h.Guardrail != "" {
			out[id] = h.Guardrail
		}
	}
	for id, reason := range g.guardrailReasons(ctx, tenantID, auth, candidates, assets) {
		if reason != "" {
			out[id] = reason
		}
	}
	return out, nil
}
