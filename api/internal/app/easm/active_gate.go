package easm

// The active-scan ownership gate: may a sensor actively probe this asset or
// typed target? Design: docs/rfcs/RFC-036-easm.md §6.3 (active_allowed);
// architecture: docs/architecture/active-probe-gate.md.
//
// An asset is actively scannable only when:
//
//   - nobody said it is not the tenant's: no rejection tombstone and no
//     rejected asset on its name or on any parent domain of it (unless a
//     person confirmed this very asset);
//   - its attribution record, if any, is confirmed (needs_review, candidate,
//     dependency, monitor_only and rejected are refused);
//   - an internet-facing asset, or typed text naming an internet host or
//     address, is covered by the tenant's scope authority (scopeauth: an
//     active scope target, or a name at or under a root-domain seed or
//     verified domain; RFC-054 §4.2). A confirmed record does not replace
//     that: a person confirming an asset on its Ownership tab records
//     ownership, it does not authorize active probes outside every scope
//     entry (out_of_scope). Without a record it is "unattributed".
//
// Every lookup is tenant-scoped, and every lookup error refuses (the caller
// dispatches nothing). Another tenant's assets, records, tombstones, scope
// targets and seeds never allow or refuse anything here.

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"

	"github.com/openctemio/openctem/api/internal/app/actscope"
	scopeapp "github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/internal/app/scopeauth"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ActiveGateRecords reads attribution records and rejection tombstones
// (*postgres.AttributionRepository).
type ActiveGateRecords interface {
	Records(ctx context.Context, tenantID shared.ID, assetIDs []string) (map[string]attribution.Record, error)
	Tombstoned(ctx context.Context, tenantID shared.ID, names []string) (map[string][]attribution.Rule, error)
}

// ActiveGateAssets loads the tenant's assets (*postgres.AssetRepository).
type ActiveGateAssets interface {
	GetByIDs(ctx context.Context, tenantID shared.ID, ids []shared.ID) (map[string]*asset.Asset, error)
	GetByNames(ctx context.Context, tenantID shared.ID, names []string) (map[string]*asset.Asset, error)
}

// ActiveGateScope lists the tenant's active scope targets (*scope.Service).
type ActiveGateScope interface {
	ListActiveTargets(ctx context.Context, tenantID string) ([]*scopedom.Target, error)
}

// ActiveGateRoots lists the tenant's root-domain seeds and verified domains
// (*postgres.EASMSeedRepository).
type ActiveGateRoots interface {
	RootDomainSeedNames(ctx context.Context, tenantID shared.ID) ([]string, error)
	VerifiedDomainNames(ctx context.Context, tenantID shared.ID) ([]string, error)
}

// ActiveGate implements scan.AttributionGate.
type ActiveGate struct {
	records ActiveGateRecords
	assets  ActiveGateAssets
	scope   ActiveGateScope
	roots   ActiveGateRoots
	// dangling backs the takeover exception (takeover_gate.go); nil admits
	// nothing.
	dangling ActiveGateDangling
	// guardrails deny targets the platform does not allow (RFC-054 §8.2);
	// proofAll requires a verified domain for every active probe (§8.1).
	guardrails *scopedom.Guardrails
	proofAll   bool
}

// WithPlatformPolicy sets the operator's guardrails and whether every active
// probe needs a verified domain (SCOPE_ACTIVE_PROOF=all).
func (g *ActiveGate) WithPlatformPolicy(gr scopedom.Guardrails, proofAll bool) *ActiveGate {
	g.guardrails, g.proofAll = &gr, proofAll
	return g
}

func (g *ActiveGate) denied(name string) bool {
	return g.guardrails != nil && g.guardrails.Denies(name)
}

// CoverOf answers which of the tenant's authorities covers each target
// (the dry run's "via"); a target nothing covers is absent.
func (g *ActiveGate) CoverOf(ctx context.Context, tenantID shared.ID, targets []string) (map[string]scopeauth.Via, error) {
	if err := g.ready(); err != nil {
		return nil, err
	}
	auth, err := scopeauth.Load(ctx, tenantID, g.scope, g.roots)
	if err != nil {
		return nil, err
	}
	out := make(map[string]scopeauth.Via, len(targets))
	for _, t := range targets {
		if v, ok := auth.Covers(t); ok {
			if auth.Verified(t) {
				v.Proof = scopeauth.ProofVerified
			}
			out[t] = v
		}
	}
	return out, nil
}

// AssetTargets names what a probe of each asset targets (the dry run's
// asset_ids, RFC-054 §6.4): the asset name first, then the other values an
// exclusion of the asset also matches. Only the tenant's live assets are
// answered; another tenant's, a deleted or an unknown id is absent.
// Implements scan.AssetTargetResolver.
func (g *ActiveGate) AssetTargets(ctx context.Context, tenantID shared.ID, ids []shared.ID) (map[shared.ID][]string, error) {
	if err := g.ready(); err != nil {
		return nil, err
	}
	out := make(map[shared.ID][]string, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	if len(ids) > maxGateItems {
		return nil, fmt.Errorf("%w: too many assets for one lookup", shared.ErrValidation)
	}
	found, err := g.assets.GetByIDs(ctx, tenantID, ids)
	if err != nil {
		return nil, fmt.Errorf("load assets: %w", err)
	}
	for _, id := range ids {
		a := found[id.String()]
		if a == nil || !a.TenantID().Equals(tenantID) || strings.TrimSpace(a.Name()) == "" {
			continue
		}
		values := []string{a.Name()}
		for _, v := range scopeapp.AssetExclusionValues(string(a.Type()), a.Name(), a.Properties()) {
			if v = strings.TrimSpace(v); v != "" && !strings.EqualFold(v, a.Name()) {
				values = append(values, v)
			}
		}
		out[id] = values
	}
	return out, nil
}

// Scope statuses of an asset (RFC-054 §6.6).
const (
	ScopeStatusInScope       = "in_scope"
	ScopeStatusOutOfScope    = "out_of_scope"
	ScopeStatusInternal      = "internal"
	ScopeStatusNotApplicable = "not_applicable"
)

// ScopeOfAsset answers whether the tenant's scope covers one asset and what
// covers it: in_scope (with the authority), out_of_scope, internal (a
// private or internal name, gated by scan zones) or not_applicable (a type
// the scope authority does not judge). An unknown asset is out_of_scope.
func (g *ActiveGate) ScopeOfAsset(ctx context.Context, tenantID shared.ID, assetID string) (string, *scopeauth.Via, error) {
	if err := g.ready(); err != nil {
		return "", nil, err
	}
	id, err := shared.IDFromString(assetID)
	if err != nil {
		return "", nil, fmt.Errorf("%w: invalid asset id", shared.ErrValidation)
	}
	assets, err := g.assets.GetByIDs(ctx, tenantID, []shared.ID{id})
	if err != nil {
		return "", nil, err
	}
	a := assets[assetID]
	if a == nil {
		return ScopeStatusOutOfScope, nil, nil
	}
	if isInternalName(a.Name()) {
		return ScopeStatusInternal, nil, nil
	}
	if !internetFacing(a.Type(), a.SubType()) {
		return ScopeStatusNotApplicable, nil, nil
	}
	cover, err := g.CoverOf(ctx, tenantID, []string{a.Name()})
	if err != nil {
		return "", nil, err
	}
	if v, ok := cover[a.Name()]; ok {
		return ScopeStatusInScope, &v, nil
	}
	return ScopeStatusOutOfScope, nil, nil
}

// UnverifiedTargets returns the targets naming an internet host or public
// address that are not at or under a verified domain of the tenant (an
// address never is: there is no address proof yet). Implements
// scan.ProofVerifier.
func (g *ActiveGate) UnverifiedTargets(ctx context.Context, tenantID shared.ID, targets []string) ([]string, error) {
	if err := g.ready(); err != nil {
		return nil, err
	}
	var auth *scopeauth.Authority
	var out []string
	for _, t := range targets {
		if !needsAuthority(t) {
			continue
		}
		if auth == nil {
			var err error
			if auth, err = scopeauth.Load(ctx, tenantID, g.scope, g.roots); err != nil {
				return nil, err
			}
		}
		if !auth.Verified(t) {
			out = append(out, t)
		}
	}
	return out, nil
}

// NewActiveGate wires the gate. Every dependency is required; a nil one
// makes every check fail (fail closed).
func NewActiveGate(records ActiveGateRecords, assets ActiveGateAssets, scope ActiveGateScope, roots ActiveGateRoots) *ActiveGate {
	return &ActiveGate{records: records, assets: assets, scope: scope, roots: roots}
}

// maxGateItems bounds one call (a scan run dispatches at most 10 000).
const maxGateItems = 20000

func (g *ActiveGate) ready() error {
	if g == nil || g.records == nil || g.assets == nil || g.scope == nil || g.roots == nil {
		return fmt.Errorf("active-scan ownership gate is not configured; nothing dispatched")
	}
	return nil
}

// ActiveCheckBlocked returns the given assets that may not be probed, with
// the reason: their recorded state, attribution.StateRejected for a name
// under a rejected name, or attribution.StateUnattributed.
func (g *ActiveGate) ActiveCheckBlocked(ctx context.Context, tenantID shared.ID, assetIDs []string) (map[string]attribution.State, error) {
	if err := g.ready(); err != nil {
		return nil, err
	}
	out := map[string]attribution.State{}
	if len(assetIDs) == 0 {
		return out, nil
	}
	if len(assetIDs) > maxGateItems {
		return nil, fmt.Errorf("%w: too many assets for one ownership check", shared.ErrValidation)
	}
	ids := make([]shared.ID, 0, len(assetIDs))
	for _, raw := range assetIDs {
		id, err := shared.IDFromString(raw)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid asset id", shared.ErrValidation)
		}
		ids = append(ids, id)
	}
	assets, err := g.assets.GetByIDs(ctx, tenantID, ids)
	if err != nil {
		return nil, fmt.Errorf("load assets for the ownership check: %w", err)
	}
	return g.decide(ctx, tenantID, assetIDs, assets)
}

// BlockedTargets returns the typed targets that may not be probed: a target
// that names one of the tenant's assets (as typed, lower-cased, or the host
// of a URL or host:port) is decided as that asset; any other target is
// refused when it, or a parent domain of it, is a name the tenant rejected,
// and otherwise (an internet host or address) when the scope authority does
// not cover it (unattributed): the same answer an inventory asset gets.
func (g *ActiveGate) BlockedTargets(ctx context.Context, tenantID shared.ID, targets []string) (map[string]attribution.State, error) {
	if err := g.ready(); err != nil {
		return nil, err
	}
	out := map[string]attribution.State{}
	if len(targets) == 0 {
		return out, nil
	}
	if len(targets) > maxGateItems {
		return nil, fmt.Errorf("%w: too many targets for one ownership check", shared.ErrValidation)
	}
	forms := make(map[string][]string, len(targets))
	names := make([]string, 0, len(targets)*2)
	for _, t := range targets {
		f := actscope.MatchForms(t)
		forms[t] = f
		names = append(names, f...)
	}
	found, err := g.assets.GetByNames(ctx, tenantID, names)
	if err != nil {
		return nil, fmt.Errorf("resolve targets for the ownership check: %w", err)
	}
	byTarget := map[string]string{} // target -> asset id
	assets := map[string]*asset.Asset{}
	ids := make([]string, 0, len(targets))
	var free []string
	for _, t := range targets {
		var hit *asset.Asset
		for _, f := range forms[t] {
			if a, ok := found[f]; ok && a != nil {
				hit = a
				break
			}
		}
		if hit == nil {
			free = append(free, t)
			continue
		}
		id := hit.ID().String()
		byTarget[t] = id
		if _, dup := assets[id]; !dup {
			assets[id] = hit
			ids = append(ids, id)
		}
	}
	blocked, err := g.decide(ctx, tenantID, ids, assets)
	if err != nil {
		return nil, err
	}
	for t, id := range byTarget {
		if s, no := blocked[id]; no {
			out[t] = s
		}
	}
	if len(free) > 0 {
		hosts := make(map[string]string, len(free))
		for _, t := range free {
			if h := dnsHost(t); h != "" {
				hosts[t] = h
			}
		}
		rejected, err := g.rejectedNames(ctx, tenantID, hostValues(hosts))
		if err != nil {
			return nil, err
		}
		for t, h := range hosts {
			if underAny(h, rejected) {
				out[t] = attribution.StateRejected
			}
		}
		var auth *scopeauth.Authority
		for _, t := range free {
			if g.denied(t) {
				out[t] = attribution.StatePlatformDenied
				continue
			}
			if _, no := out[t]; no || !needsAuthority(t) {
				continue
			}
			if auth == nil {
				if auth, err = scopeauth.Load(ctx, tenantID, g.scope, g.roots); err != nil {
					return nil, err
				}
			}
			switch _, ok := auth.Covers(t); {
			case !ok:
				out[t] = attribution.StateUnattributed
			case g.proofAll && !auth.Verified(t):
				out[t] = attribution.StateProofRequired
			}
		}
	}
	return out, nil
}

// needsAuthority reports whether typed text names an internet host or a
// public address or range, which the scope authority must cover (a host with
// a path, such as a repository URL, counts as its host unless a scope target
// matches the whole text). Private and internal names are gated by scan
// zones; anything else (an identifier) is left to the act-scope check.
func needsAuthority(t string) bool {
	if isInternalName(t) {
		return false
	}
	if dnsHost(t) != "" {
		return true
	}
	h := strings.Trim(strings.TrimSpace(t), "[]")
	if _, err := netip.ParsePrefix(h); err == nil {
		return true
	}
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = strings.Trim(host, "[]")
	}
	_, err := netip.ParseAddr(h)
	return err == nil
}

// decide applies the rule to assets already loaded (ids not in assets are
// not the tenant's or are deleted: nothing to probe, refused as
// unattributed).
func (g *ActiveGate) decide(ctx context.Context, tenantID shared.ID, ids []string, assets map[string]*asset.Asset) (map[string]attribution.State, error) {
	out := map[string]attribution.State{}
	if len(ids) == 0 {
		return out, nil
	}
	records, err := g.records.Records(ctx, tenantID, ids)
	if err != nil {
		return nil, fmt.Errorf("load attribution for the ownership check: %w", err)
	}

	hostOf := map[string]string{}
	for _, id := range ids {
		if a := assets[id]; a != nil {
			if h := dnsHost(a.Name()); h != "" {
				hostOf[id] = h
			}
		}
	}
	rejected, err := g.rejectedNames(ctx, tenantID, hostValues(hostOf))
	if err != nil {
		return nil, err
	}

	var auth *scopeauth.Authority
	for _, id := range ids {
		a := assets[id]
		if a == nil {
			out[id] = attribution.StateUnattributed
			continue
		}
		if g.denied(a.Name()) {
			out[id] = attribution.StatePlatformDenied
			continue
		}
		rec, recorded := records[id]
		humanConfirmed := recorded && rec.State == attribution.StateConfirmed && rec.HumanDecided
		// A person confirming this very asset overrides a rejected parent;
		// nothing else does.
		if h, ok := hostOf[id]; ok && !humanConfirmed && underAny(h, rejected) {
			out[id] = attribution.StateRejected
			continue
		}
		if recorded && rec.State != attribution.StateConfirmed {
			out[id] = rec.State
			continue
		}
		if !internetFacing(a.Type(), a.SubType()) || isInternalName(a.Name()) {
			continue
		}
		if auth == nil {
			if auth, err = scopeauth.Load(ctx, tenantID, g.scope, g.roots); err != nil {
				return nil, err
			}
		}
		if _, ok := auth.Covers(a.Name()); ok {
			if g.proofAll && !auth.Verified(a.Name()) {
				out[id] = attribution.StateProofRequired
			}
			continue
		}
		if recorded {
			// Confirmed (by a person or a rule) but no scope entry, seed or
			// verified domain covers it any more, or never did.
			out[id] = attribution.StateOutOfScope
		} else {
			out[id] = attribution.StateUnattributed
		}
	}
	return out, nil
}

// rejectedNames returns the names among the given hosts and their parent
// domains that the tenant rejected: a live tombstone, or an asset of that
// name whose attribution is rejected.
func (g *ActiveGate) rejectedNames(ctx context.Context, tenantID shared.ID, hosts []string) (map[string]bool, error) {
	out := map[string]bool{}
	if len(hosts) == 0 {
		return out, nil
	}
	seen := map[string]bool{}
	var names []string
	for _, h := range hosts {
		for _, n := range selfAndParents(h) {
			if !seen[n] {
				seen[n] = true
				names = append(names, n)
			}
		}
	}
	tombs, err := g.records.Tombstoned(ctx, tenantID, names)
	if err != nil {
		return nil, fmt.Errorf("load rejection tombstones: %w", err)
	}
	for n := range tombs {
		out[n] = true
	}
	named, err := g.assets.GetByNames(ctx, tenantID, names)
	if err != nil {
		return nil, fmt.Errorf("load rejected names: %w", err)
	}
	if len(named) == 0 {
		return out, nil
	}
	ids := make([]string, 0, len(named))
	nameOf := make(map[string]string, len(named))
	for n, a := range named {
		if a != nil {
			ids = append(ids, a.ID().String())
			nameOf[a.ID().String()] = n
		}
	}
	recs, err := g.records.Records(ctx, tenantID, ids)
	if err != nil {
		return nil, fmt.Errorf("load attribution of parent names: %w", err)
	}
	for id, r := range recs {
		if r.State == attribution.StateRejected {
			out[nameOf[id]] = true
		}
	}
	return out, nil
}

// dnsHost is the lower-case DNS name a target or asset name points at ("" for
// an address, a CIDR or something that is not a host name).
func dnsHost(s string) string {
	h := strings.TrimSpace(s)
	if strings.Contains(h, "://") {
		u, err := url.Parse(h)
		if err != nil {
			return ""
		}
		h = u.Hostname()
	} else {
		if i := strings.IndexAny(h, "/?#"); i >= 0 {
			h = h[:i]
		}
		if host, _, err := net.SplitHostPort(h); err == nil {
			h = host
		}
	}
	h = normalizeHost(h)
	if h == "" || !strings.Contains(h, ".") {
		return ""
	}
	if _, err := netip.ParseAddr(strings.Trim(h, "[]")); err == nil {
		return ""
	}
	return h
}

func normalizeHost(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimPrefix(s, "*.")
	return strings.TrimSuffix(s, ".")
}

// selfAndParents is the name and every parent with at least two labels:
// a.b.example.com -> a.b.example.com, b.example.com, example.com.
func selfAndParents(h string) []string {
	out := []string{h}
	for {
		i := strings.IndexByte(h, '.')
		if i < 0 {
			break
		}
		h = h[i+1:]
		if !strings.Contains(h, ".") {
			break
		}
		out = append(out, h)
	}
	return out
}

func underAny(h string, names map[string]bool) bool {
	if len(names) == 0 {
		return false
	}
	for _, n := range selfAndParents(h) {
		if names[n] {
			return true
		}
	}
	return false
}

func hostValues(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	return out
}

// isInternalName reports whether an asset name is a private, loopback,
// link-local or CGNAT address (or range), or an internal-only host name.
// Those are gated by scan zones (a private address is scanned only inside a
// zone), not by EASM attribution.
func isInternalName(name string) bool {
	h := strings.TrimSpace(name)
	if strings.Contains(h, "://") {
		if u, err := url.Parse(h); err == nil {
			h = u.Hostname()
		}
	}
	if p, err := netip.ParsePrefix(h); err == nil {
		return internalAddr(p.Addr())
	}
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	h = strings.Trim(h, "[]")
	if a, err := netip.ParseAddr(h); err == nil {
		return internalAddr(a)
	}
	l := strings.ToLower(strings.TrimSuffix(h, "."))
	return l == "localhost" || strings.HasSuffix(l, ".localhost") ||
		strings.HasSuffix(l, ".local") || strings.HasSuffix(l, ".internal") || strings.HasSuffix(l, ".lan")
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

func internalAddr(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() ||
		a.IsUnspecified() || cgnat.Contains(a)
}
