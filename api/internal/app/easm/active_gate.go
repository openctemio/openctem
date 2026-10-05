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
//   - an internet-facing asset with no record sits inside an active scope
//     target of the tenant, or at or under one of its root-domain seeds or
//     verified domains. Otherwise it is "unattributed": a person confirms it
//     (assets:write, audited) or adds a scope target first.
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
// refused only when it, or a parent domain of it, is a name the tenant
// rejected. Whether free text matches a scope target is the act-scope
// check's job.
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
	}
	return out, nil
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

	var auth *authority
	for _, id := range ids {
		a := assets[id]
		if a == nil {
			out[id] = attribution.StateUnattributed
			continue
		}
		rec, recorded := records[id]
		if recorded && rec.State == attribution.StateConfirmed && rec.HumanDecided {
			continue // a person confirmed this very asset
		}
		if h, ok := hostOf[id]; ok && underAny(h, rejected) {
			out[id] = attribution.StateRejected
			continue
		}
		if recorded {
			if rec.State != attribution.StateConfirmed {
				out[id] = rec.State
			}
			continue
		}
		if !internetFacing(a.Type(), a.SubType()) || isInternalName(a.Name()) {
			continue
		}
		if auth == nil {
			if auth, err = g.loadAuthority(ctx, tenantID); err != nil {
				return nil, err
			}
		}
		if !auth.covers(a.Name()) {
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

// authority is what the tenant authorized for active checks without a
// per-asset decision: its active scope targets and the names at or under
// its root-domain seeds and verified domains.
type authority struct {
	targets []*scopedom.Target
	roots   []string
}

func (g *ActiveGate) loadAuthority(ctx context.Context, tenantID shared.ID) (*authority, error) {
	targets, err := g.scope.ListActiveTargets(ctx, tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("list scope targets: %w", err)
	}
	seeds, err := g.roots.RootDomainSeedNames(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	verified, err := g.roots.VerifiedDomainNames(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	a := &authority{targets: targets}
	for _, r := range append(seeds, verified...) {
		if r = normalizeHost(r); r != "" {
			a.roots = append(a.roots, r)
		}
	}
	return a, nil
}

// covers reports whether an asset name is inside a scope target or at or
// under a seed or verified domain.
func (a *authority) covers(name string) bool {
	for _, f := range actscope.MatchForms(name) {
		for _, t := range a.targets {
			if t != nil && t.Matches(f) {
				return true
			}
		}
	}
	if h := dnsHost(name); h != "" {
		for _, r := range a.roots {
			if h == r || strings.HasSuffix(h, "."+r) {
				return true
			}
		}
	}
	return false
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
