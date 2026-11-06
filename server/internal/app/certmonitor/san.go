package certmonitor

// Certificate SAN promotion: the names in a TLS certificate a report put in
// the inventory become candidate subdomains of the tenant, through the same
// promotion path as CT names (promote.go). Design: docs/architecture/easm.md
// ("Certificate SAN promotion"), research/333 D5.
//
// Rules:
//   - only a name strictly below one of the tenant's domain roots (attributed
//     domain assets, verified domains, permanent scope entries with discovery
//     on) is proposed; a shared certificate (CDN, hosting) never creates an
//     asset for a foreign name;
//   - a wildcard SAN ("*.dev.example.com") is skipped, as in CT promotion: it
//     proves no host of the base name exists;
//   - addresses, junk and names of a certificate that lapsed more than
//     promoteLookback ago are skipped;
//   - the evidence rule is certificate_san (weak): a new name is a candidate
//     and is never confirmed or scoped by a certificate alone. A permanent
//     scope entry covering the name still confirms it through the scope join,
//     exactly as for CT names;
//   - excluded names, names under an excluded root, names whose known
//     dedicated address is excluded, and rejected names (any tombstone) are
//     not proposed, and an existing asset gets no evidence for them;
//   - an existing asset keeps its standing (automation only raises a state);
//   - one call creates at most maxPromotions new assets.

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/internal/app/ingest"
	scopeapp "github.com/openctemio/openctem/api/internal/app/scope"
	assetdom "github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

const (
	// SourceCertificateSAN is the evidence source of a certificate SAN.
	SourceCertificateSAN = "certificate_san"
	// maxSANCandidates bounds the names one call looks up.
	maxSANCandidates = 5000
)

// sanKind is the certificate SAN promotion.
var sanKind = promoteKind{
	technique:    assetdom.DiscoverySourceCertificate,
	tool:         "certificate-san",
	reportID:     "cert-san-promotion",
	logLabel:     "certificate SAN promotion",
	rule:         attribution.RuleCertificateSAN,
	anyTombstone: true,
}

// NameAddressReader maps names (lower-case) to the addresses the tenant's
// asset of that name resolves to (*postgres.AttributionRepository).
type NameAddressReader interface {
	AddressesOf(ctx context.Context, tenantID shared.ID, names []string) (map[string][]string, error)
}

// SetNameAddresses makes CT and certificate SAN promotion skip a known name
// whose dedicated address is excluded (nil: only the name is matched).
func (s *Service) SetNameAddresses(r NameAddressReader) { s.nameAddresses = r }

// PromoteCertificateNames proposes the names of the given certificates (of
// tenantID, written by one report of tool) as candidate subdomains. It
// returns how many assets it created. Implements
// ingest.CertificateNamePromoter. A failed lookup of roots, exclusions,
// addresses or tombstones promotes nothing (fail closed).
func (s *Service) PromoteCertificateNames(ctx context.Context, tenantID shared.ID, tool string, certs []ingest.CertificateNames) (int, error) {
	if s == nil || !s.promotionEnabled() || tenantID.IsZero() || len(certs) == 0 {
		return 0, nil
	}
	roots, _, err := s.gatherRoots(ctx, tenantID)
	if err != nil {
		return 0, err
	}
	var excl *scopeapp.ExclusionMatcher
	if s.exclusions != nil {
		if excl, err = s.exclusions.LoadExclusionMatcher(ctx, tenantID); err != nil {
			return 0, fmt.Errorf("failed to load scope exclusions: %w", err)
		}
	}
	roots, _ = withoutExcludedRoots(roots, excl)
	if len(roots) == 0 {
		return 0, nil
	}
	cands := sanCandidates(certs, roots, excl, s.now(), tool)
	if len(cands) == 0 {
		return 0, nil
	}
	kind := sanKind
	kind.keep = s.withoutExcludedAddresses(excl)
	return s.promote(ctx, tenantID, cands, kind)
}

// sanCandidates turns certificate names into promotions: one per name (the
// first certificate naming it), under the strongest root that covers it.
func sanCandidates(certs []ingest.CertificateNames, roots []rootDomain, excl *scopeapp.ExclusionMatcher, now time.Time, tool string) []promotion {
	seen := map[string]bool{}
	var out []promotion
	for _, c := range certs {
		if c.NotAfter != nil && now.Sub(*c.NotAfter) > promoteLookback {
			continue
		}
		for _, raw := range c.Names {
			name, ok := sanName(raw)
			if !ok || seen[name] {
				continue
			}
			root, ok := rootOf(name, roots)
			if !ok || excl.Excluded(name) {
				continue
			}
			seen[name] = true
			out = append(out, sanPromotion(c, name, root, now, tool))
			if len(out) == maxSANCandidates {
				return out
			}
		}
	}
	return out
}

// sanName normalizes one certificate name: lower case, no trailing dot. A
// wildcard, an address or anything that is not a plain hostname is refused.
func sanName(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if strings.Contains(raw, "*") {
		return "", false
	}
	name := normalizeDomain(raw)
	if name == "" || !strings.Contains(name, ".") || !validHostname(name) {
		return "", false
	}
	if _, err := netip.ParseAddr(name); err == nil {
		return "", false
	}
	return name, true
}

// rootOf is the root strictly above name: the strongest origin, then the
// closest. A name equal to a root is not a new subdomain.
func rootOf(name string, roots []rootDomain) (rootDomain, bool) {
	var best rootDomain
	found := false
	for _, r := range roots {
		if !strings.HasSuffix(name, "."+r.name) {
			continue
		}
		if !found || originRank(r.origin) > originRank(best.origin) ||
			(originRank(r.origin) == originRank(best.origin) && len(r.name) > len(best.name)) {
			best, found = r, true
		}
	}
	return best, found
}

func sanPromotion(c ingest.CertificateNames, name string, root rootDomain, now time.Time, tool string) promotion {
	observed := map[string]any{
		"root":                 root.name,
		"root_origin":          root.origin,
		"certificate_asset_id": c.AssetID.String(),
		"certificate":          truncate(c.Name, 200),
		"first_seen":           now.UTC().Format(time.RFC3339),
	}
	if c.Issuer != "" {
		observed["issuer"] = truncate(c.Issuer, 200)
	}
	if c.NotAfter != nil {
		observed["not_after"] = c.NotAfter.UTC().Format(time.RFC3339)
	}
	if tool != "" {
		observed["tool"] = truncate(tool, 100)
	}
	host := ctHost{Name: name, FirstSeen: now}
	if c.NotAfter != nil {
		host.NotAfter = *c.NotAfter
	}
	host.Issuer = c.Issuer
	if tool == "" {
		tool = SourceCertificateSAN
	}
	return promotion{host: host, root: root, source: SourceCertificateSAN, tool: truncate(tool, 50), observed: observed}
}

// withoutExcludedAddresses drops the names whose existing asset is excluded
// by an address it is known to have: its address properties or the
// addresses its resolution relations name (an exclusion of a dedicated
// address reaches the names resolving to it; shared front ends never
// propagate, scope.PropagatingAddresses). A new name has no known address;
// ingest matches its name again before creating it.
func (s *Service) withoutExcludedAddresses(m *scopeapp.ExclusionMatcher) func(context.Context, shared.ID, []string, map[string]*assetdom.Asset) ([]string, error) {
	return func(ctx context.Context, tenantID shared.ID, names []string, existing map[string]*assetdom.Asset) ([]string, error) {
		if m.Empty() {
			return names, nil
		}
		var known []string
		for _, n := range names {
			if existing[n] != nil {
				known = append(known, n)
			}
		}
		addrs := map[string][]string{}
		if s.nameAddresses != nil && len(known) > 0 {
			var err error
			if addrs, err = s.nameAddresses.AddressesOf(ctx, tenantID, known); err != nil {
				return nil, fmt.Errorf("addresses behind names: %w", err)
			}
		}
		kept := make([]string, 0, len(names))
		for _, n := range names {
			if a := existing[n]; a != nil {
				if m.ExcludedAsset(a) {
					continue
				}
				if via := scopeapp.PropagatingAddresses(addrs[n]); len(via) > 0 && m.Excluded(via...) {
					continue
				}
			}
			kept = append(kept, n)
		}
		return kept, nil
	}
}
