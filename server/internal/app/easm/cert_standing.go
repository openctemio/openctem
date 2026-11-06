package easm

// A certificate's standing in the tenant's scope (RFC-054 §19).
//
// A certificate is evidence that a probe of an endpoint produced. No scan
// stage takes it as input, and its name is a fingerprint, so no scope entry
// can ever match it. The gate therefore never judges a certificate by its
// own name. It judges it by the endpoints that served it, each through the
// full gate (deny list, rejections, exclusions, record state, scope entries,
// guardrails):
//
//   - some endpoint passes: the certificate passes, and the entry that
//     covers that endpoint is the reason (served_by);
//   - no endpoint passes: the certificate shows the strongest refusal among
//     its endpoints (held);
//   - no endpoint is known: nothing to probe (not_applicable).
//
// Ownership is a separate signal. A name in the certificate (a SAN or the
// subject CN) under one of the tenant's domain roots marks the certificate
// "yours"; foreign names only, on an endpoint of ours, make it a third-party
// certificate. Ownership authorizes nothing: inheritance flows from an
// endpoint to the certificate it served, never the other way, so a
// certificate (which anyone can mint with any names) never brings an
// address or a name into scope.
//
// Every lookup is pinned to the tenant on both sides of the edge, and a
// lookup error fails the whole call (nothing is dispatched).

import (
	"cmp"
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/openctemio/openctem/api/internal/app/scopeauth"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ActiveGateCertificates reads which of the tenant's assets served a
// certificate (*postgres.AssetRelationshipRepository).
type ActiveGateCertificates interface {
	// ServingEndpoints returns, per certificate id, the ids of the
	// tenant's live assets that have a serves_certificate relationship to
	// it. Both ends belong to the tenant.
	ServingEndpoints(ctx context.Context, tenantID shared.ID, certificateIDs []shared.ID) (map[string][]shared.ID, error)
}

// SetCertificates makes certificates judged by the endpoints that served
// them. Without it a certificate has no known endpoint and is refused.
func (g *ActiveGate) SetCertificates(c ActiveGateCertificates) { g.certs = c }

// Standings of a certificate.
const (
	CertStandingInScope       = "in_scope"       // an endpoint that serves it is covered by a scope entry
	CertStandingLowImpact     = "low_impact"     // an endpoint passes with no entry (unclassified checks)
	CertStandingHeld          = "held"           // every endpoint that serves it is refused
	CertStandingNotApplicable = "not_applicable" // no known endpoint serves it
	CertOwnershipYours        = "yours"          // a name in it sits under a domain root of the tenant
	CertOwnershipThirdParty   = "third_party"    // on an endpoint of ours, but every name in it is foreign
	CertOwnershipNone         = "none"           // no ownership signal
	maxCertEndpoints          = 200              // endpoints judged per certificate
	maxCertEndpointsShown     = 10               // endpoints listed in the answer
	maxCertNames              = 100              // names read from one certificate
	certNameMaxLen            = 253
)

// CertEndpoint is one endpoint that served a certificate and how the gate
// judges it.
type CertEndpoint struct {
	AssetID string `json:"asset_id"`
	Name    string `json:"name"`
	// State is the gate's refusal for the endpoint; empty when probes may
	// reach it.
	State string `json:"state,omitempty"`
	// Guardrail is the guardrail reason when State is guardrailed.
	Guardrail string `json:"guardrail,omitempty"`
	// CoveredBy is the scope entry that covers the endpoint.
	CoveredBy *scopeauth.Via `json:"covered_by,omitempty"`
}

// CertStanding is the answer for one certificate.
type CertStanding struct {
	// Standing: in_scope, low_impact, held or not_applicable.
	Standing string `json:"standing"`
	// ServedBy is the first endpoint covered by a scope entry (kind
	// served_by, with the endpoint and the entry).
	ServedBy *scopeauth.Via `json:"served_by,omitempty"`
	// HeldBy is the endpoint with the strongest refusal when held.
	HeldBy *CertEndpoint `json:"held_by,omitempty"`
	// Endpoints lists up to ten endpoints; EndpointCount is all of them.
	Endpoints     []CertEndpoint `json:"endpoints"`
	EndpointCount int            `json:"endpoint_count"`
	// Ownership: yours, third_party or none. OwnedBy names the matching
	// name and the entry or verified domain it sits under.
	Ownership string         `json:"ownership"`
	OwnedBy   *scopeauth.Via `json:"owned_by,omitempty"`
}

// certJudgement is a standing plus the state the gate decides with: empty
// when probes may reach the certificate's endpoints.
type certJudgement struct {
	standing CertStanding
	state    attribution.State
}

// CertificateStandings answers the standing of each given certificate asset
// of the tenant. Ids that are not the tenant's live certificates are absent.
func (g *ActiveGate) CertificateStandings(ctx context.Context, tenantID shared.ID, ids []shared.ID) (map[string]CertStanding, error) {
	if err := g.ready(); err != nil {
		return nil, err
	}
	out := map[string]CertStanding{}
	if len(ids) == 0 {
		return out, nil
	}
	if len(ids) > maxGateItems {
		return nil, fmt.Errorf("%w: too many assets for one lookup", shared.ErrValidation)
	}
	assets, err := g.assets.GetByIDs(ctx, tenantID, ids)
	if err != nil {
		return nil, fmt.Errorf("load certificates: %w", err)
	}
	certs := make([]*asset.Asset, 0, len(ids))
	for _, id := range ids {
		if a := assets[id.String()]; a != nil && a.Type() == asset.AssetTypeCertificate {
			certs = append(certs, a)
		}
	}
	judged, err := g.judgeCertificates(ctx, tenantID, certs)
	if err != nil {
		return nil, err
	}
	for id, j := range judged {
		out[id] = j.standing
	}
	return out, nil
}

// judgeCertificates is the one place a certificate is judged: by its
// endpoints (each through decide) and, separately, by the names in it.
func (g *ActiveGate) judgeCertificates(ctx context.Context, tenantID shared.ID, certs []*asset.Asset) (map[string]certJudgement, error) {
	out := make(map[string]certJudgement, len(certs))
	if len(certs) == 0 {
		return out, nil
	}
	certIDs := make([]shared.ID, 0, len(certs))
	for _, c := range certs {
		certIDs = append(certIDs, c.ID())
	}
	var serving map[string][]shared.ID
	if g.certs != nil {
		var err error
		if serving, err = g.certs.ServingEndpoints(ctx, tenantID, certIDs); err != nil {
			return nil, fmt.Errorf("load the endpoints that serve certificates: %w", err)
		}
	}
	// Endpoints: the tenant's live assets only, never a certificate itself
	// (a crafted edge between two certificates must not recurse).
	var endpointIDs []shared.ID
	seen := map[string]bool{}
	for _, c := range certs {
		list := serving[c.ID().String()]
		if len(list) > maxCertEndpoints {
			list = list[:maxCertEndpoints]
		}
		for _, id := range list {
			if !seen[id.String()] {
				seen[id.String()] = true
				endpointIDs = append(endpointIDs, id)
			}
		}
	}
	endpoints, err := g.assets.GetByIDs(ctx, tenantID, endpointIDs)
	if err != nil {
		return nil, fmt.Errorf("load certificate endpoints: %w", err)
	}
	judgeIDs := make([]string, 0, len(endpoints))
	for id, a := range endpoints {
		if a == nil || a.Type() == asset.AssetTypeCertificate {
			delete(endpoints, id)
			continue
		}
		judgeIDs = append(judgeIDs, id)
	}
	slices.Sort(judgeIDs)
	blocked, err := g.decide(ctx, tenantID, judgeIDs, endpoints)
	if err != nil {
		return nil, err
	}
	auth, err := scopeauth.Load(ctx, tenantID, g.scope, g.roots)
	if err != nil {
		return nil, err
	}
	var guardrailed []string
	for id, st := range blocked {
		if st == attribution.StateGuardrailed {
			guardrailed = append(guardrailed, id)
		}
	}
	reasons := g.guardrailReasons(ctx, tenantID, auth, guardrailed, endpoints)

	// Names in all the certificates, judged once for rejection.
	namesOf := make(map[string][]string, len(certs))
	var allNames []string
	for _, c := range certs {
		n := certificateNames(c)
		namesOf[c.ID().String()] = n
		allNames = append(allNames, n...)
	}
	rejected, err := g.rejectedNames(ctx, tenantID, allNames)
	if err != nil {
		return nil, err
	}

	for _, c := range certs {
		cid := c.ID().String()
		var eps []CertEndpoint
		for _, id := range serving[cid] {
			a := endpoints[id.String()]
			if a == nil {
				continue
			}
			ep := CertEndpoint{AssetID: id.String(), Name: a.Name()}
			if st, no := blocked[id.String()]; no {
				ep.State = string(st)
				ep.Guardrail = reasons[id.String()]
			} else if v, ok := auth.Covers(a.Name()); ok {
				ep.CoveredBy = &v
			}
			eps = append(eps, ep)
		}
		j, covered := standingOf(eps)
		names := namesOf[cid]
		j.standing.Ownership, j.standing.OwnedBy = g.ownership(auth, names, rejected, covered)
		out[cid] = j
	}
	return out, nil
}

// standingOf folds a certificate's endpoints into its standing and the state
// the gate decides with. covered reports an endpoint a scope entry covers.
func standingOf(eps []CertEndpoint) (j certJudgement, covered bool) {
	slices.SortFunc(eps, func(a, b CertEndpoint) int {
		return cmp.Or(cmp.Compare(a.Name, b.Name), cmp.Compare(a.AssetID, b.AssetID))
	})
	j = certJudgement{standing: CertStanding{Endpoints: []CertEndpoint{}, EndpointCount: len(eps), Ownership: CertOwnershipNone}}
	var passing, cov, worst *CertEndpoint
	for i := range eps {
		ep := &eps[i]
		switch {
		case ep.State == "":
			if passing == nil {
				passing = ep
			}
			if ep.CoveredBy != nil && cov == nil {
				cov = ep
			}
		case worst == nil || stateRank(attribution.State(ep.State)) < stateRank(attribution.State(worst.State)):
			worst = ep
		}
	}
	switch {
	case cov != nil:
		j.standing.Standing = CertStandingInScope
		j.standing.ServedBy = &scopeauth.Via{
			Kind: scopeauth.KindServedBy, ID: cov.CoveredBy.ID, Pattern: cov.CoveredBy.Pattern,
			Proof: cov.CoveredBy.Proof, Endpoint: cov.AssetID, Name: cov.Name,
		}
	case passing != nil:
		j.standing.Standing = CertStandingLowImpact
	case worst != nil:
		j.standing.Standing = CertStandingHeld
		held := *worst
		j.standing.HeldBy = &held
		j.state = attribution.State(worst.State)
	default:
		j.standing.Standing = CertStandingNotApplicable
		j.state = attribution.StateUnattributed
	}
	if len(eps) > maxCertEndpointsShown {
		j.standing.Endpoints = eps[:maxCertEndpointsShown]
	} else if len(eps) > 0 {
		j.standing.Endpoints = eps
	}
	return j, cov != nil
}

// ownership is the ownership signal of a certificate's names: yours when one
// sits under a domain root of the tenant, third_party when the certificate
// is on an endpoint of ours (onOurEndpoint) and every name is foreign.
func (g *ActiveGate) ownership(auth *scopeauth.Authority, names []string, rejected map[string]bool, onOurEndpoint bool) (string, *scopeauth.Via) {
	for _, n := range names {
		if g.denied(n) || underAny(n, rejected) {
			continue
		}
		if v, ok := auth.OwnedName(n); ok {
			v.Kind = scopeauth.KindSAN
			return CertOwnershipYours, &v
		}
	}
	if onOurEndpoint && len(names) > 0 {
		return CertOwnershipThirdParty, nil
	}
	return CertOwnershipNone, nil
}

// stateRank orders refusals, strongest first: what the person must clear
// first to let probes reach the certificate's endpoints.
func stateRank(s attribution.State) int {
	switch s {
	case attribution.StatePlatformDenied:
		return 0
	case attribution.StateRejected:
		return 1
	case attribution.StateDependency:
		return 2
	case attribution.StateMonitorOnly:
		return 3
	case attribution.StateWildcardOnly:
		return 4
	case attribution.StateGuardrailed:
		return 5
	default:
		return 6
	}
}

// certificateNames are the names a certificate carries (the subject CN and
// the SANs, at most maxCertNames), normalized: lower case, no wildcard label
// and no trailing dot. Addresses, empty and over-long values are dropped. A
// wildcard "*.example.com" reads as its root "example.com".
func certificateNames(a *asset.Asset) []string {
	props := a.Properties()
	var raw []string
	if s, ok := props["subject_cn"].(string); ok {
		raw = append(raw, s)
	}
	switch v := props["sans"].(type) {
	case []any:
		for _, e := range v {
			if s, ok := e.(string); ok {
				raw = append(raw, s)
			}
		}
	case []string:
		raw = append(raw, v...)
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(raw))
	for _, s := range raw {
		n := strings.TrimSuffix(strings.TrimPrefix(strings.ToLower(strings.TrimSpace(s)), "*."), ".")
		if n == "" || len(n) > certNameMaxLen || !strings.Contains(n, ".") || strings.ContainsAny(n, "*/:@ \t\r\n[]") || seen[n] {
			continue
		}
		if _, err := netip.ParseAddr(n); err == nil {
			continue
		}
		seen[n] = true
		out = append(out, n)
		if len(out) == maxCertNames {
			break
		}
	}
	return out
}

// certificateScope is ScopeOfAsset for a certificate: in_scope when an
// endpoint that served it is covered by a scope entry (the entry is the
// authority, via served_by), not_applicable when no endpoint is known, and
// out_of_scope otherwise.
func (g *ActiveGate) certificateScope(ctx context.Context, tenantID shared.ID, a *asset.Asset) (string, *scopeauth.Via, error) {
	judged, err := g.judgeCertificates(ctx, tenantID, []*asset.Asset{a})
	if err != nil {
		return "", nil, err
	}
	j := judged[a.ID().String()]
	switch j.standing.Standing {
	case CertStandingInScope:
		return ScopeStatusInScope, j.standing.ServedBy, nil
	case CertStandingNotApplicable:
		return ScopeStatusNotApplicable, nil, nil
	}
	return ScopeStatusOutOfScope, nil, nil
}
