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
//   - its attribution record, if any, is confirmed (dependency, monitor_only
//     and rejected are refused). A pending record (discovered, needs_review
//     or candidate) written by automation is no decision: an active scope
//     entry that covers the asset, a one-off entry included, lets probes
//     reach it (the entry is the authority; research/117 F4). A discovered
//     asset is in the inventory, and that grants nothing: without an entry
//     it gets passive checks only (research/124). A pending record a person
//     set, a rejection and an exclusion still refuse;
//   - an internet-facing asset, or typed text naming an internet host or
//     address, is covered by the tenant's scope authority (scopeauth: an
//     active scope target, or a name at or under a root-domain seed or
//     verified domain; RFC-054 §4.2). A confirmed record does not replace
//     that: a person confirming an asset on its Ownership tab records
//     ownership, it does not authorize active probes outside every scope
//     entry (out_of_scope). Without a record it is "unattributed";
//   - a name that resolves only through a wildcard DNS record (a filtered
//     resolution did not report it; RFC-088 decision A4), or a service or
//     URL on such a host, is passive only (wildcard_only) until a person
//     confirms it or a filtered resolution reports it.
//
// Every lookup is tenant-scoped, and every lookup error refuses (the caller
// dispatches nothing). Another tenant's assets, records, tombstones, scope
// targets and seeds never allow or refuse anything here.

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/openctemio/openctem/api/internal/app/actscope"
	scopeapp "github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/internal/app/scopeauth"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/assetfreshness"
	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/jobsign"
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

// ActiveGateRoots lists the tenant's verified domains, the proof of control
// (*postgres.VerifiedDomainNameRepository).
type ActiveGateRoots interface {
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
	// guardrails deny targets the platform does not allow (RFC-054 §8.2).
	guardrails *scopedom.Guardrails
	// tiers answers whether a tenant's entry tier ceilings are in force
	// (only in the Strict scan approval mode, RFC-073 §6); nil enforces
	// them for every tenant.
	tiers TierPolicy
	// wildcard reports the names that resolve only through a wildcard
	// record; nil checks none.
	wildcard assetfreshness.WildcardDNSReader
	// unclassified answers the tenant's unclassified-scans mode
	// (guardrail.go); nil keeps every unclassified asset passive.
	unclassified UnclassifiedPolicy
	// resolving reads the names behind addresses (shared hosting).
	resolving GuardrailNames
}

// SetWildcardDNS makes names that resolve only through a wildcard record
// (and their services and URLs) passive only.
func (g *ActiveGate) SetWildcardDNS(r assetfreshness.WildcardDNSReader) { g.wildcard = r }

// wildcardOnly reports which of the given assets are marked; a read error
// refuses (the caller dispatches nothing).
func (g *ActiveGate) wildcardOnly(ctx context.Context, tenantID shared.ID, ids []string) (map[string]bool, error) {
	out := map[string]bool{}
	if g.wildcard == nil || len(ids) == 0 {
		return out, nil
	}
	parsed := make([]shared.ID, 0, len(ids))
	for _, raw := range ids {
		if id, err := shared.IDFromString(raw); err == nil {
			parsed = append(parsed, id)
		}
	}
	marked, err := g.wildcard.WildcardOnly(ctx, tenantID, parsed)
	if err != nil {
		return nil, fmt.Errorf("load wildcard-DNS marks for the ownership check: %w", err)
	}
	for id, m := range marked {
		if m {
			out[id.String()] = true
		}
	}
	return out, nil
}

// TierPolicy answers whether a tenant's scope entry tier ceilings are in
// force (*scanpolicy.Service). It fails closed (enforced).
type TierPolicy interface {
	TierCeilingsEnforced(ctx context.Context, tenantID shared.ID) bool
}

// SetTierPolicy wires the scan approval mode: outside Strict a scope entry
// covers its targets at every tier.
func (g *ActiveGate) SetTierPolicy(p TierPolicy) { g.tiers = p }

// WithPlatformPolicy sets the operator's guardrails.
func (g *ActiveGate) WithPlatformPolicy(gr scopedom.Guardrails) *ActiveGate {
	g.guardrails = &gr
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
// the scope authority does not judge). A repository is always judged: by a
// repository entry or an entry for its code host. An unknown asset is
// out_of_scope.
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
	if a.Type() == asset.AssetTypeRepository {
		return g.repositoryScope(ctx, tenantID, a.Name())
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

// repositoryScope judges a repository by repository entries
// ("host/namespace/*"). On a self-hosted code host an entry for the host
// (a domain entry) covers its repositories too; on a code host many
// organizations share (scopedom.Guardrails.PublicCodeHost) only repository
// entries do, so a domain entry "github.com" claims nobody's repositories.
func (g *ActiveGate) repositoryScope(ctx context.Context, tenantID shared.ID, name string) (string, *scopeauth.Via, error) {
	gr := scopedom.DefaultGuardrails()
	if g.guardrails != nil {
		gr = *g.guardrails
	}
	if gr.PublicCodeHost(scopedom.RepositoryPatternHost(name)) {
		auth, err := scopeauth.Load(ctx, tenantID, g.scope, g.roots)
		if err != nil {
			return "", nil, err
		}
		if v, ok := auth.CoversRepository(name); ok {
			return ScopeStatusInScope, &v, nil
		}
		return ScopeStatusOutOfScope, nil, nil
	}
	cover, err := g.CoverOf(ctx, tenantID, []string{name})
	if err != nil {
		return "", nil, err
	}
	if v, ok := cover[name]; ok {
		return ScopeStatusInScope, &v, nil
	}
	return ScopeStatusOutOfScope, nil, nil
}

// ProgramOnlyTargets returns the targets that only program entries cover
// (RFC-065 §8): a bug-bounty program's scope is not the organization's, and
// such a target is never probed from platform sensors. Implements
// scan.ProgramTargetChecker.
func (g *ActiveGate) ProgramOnlyTargets(ctx context.Context, tenantID shared.ID, targets []string) ([]string, error) {
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
		if auth.ProgramOnly(t) {
			out = append(out, t)
		}
	}
	return out, nil
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

// ConstraintRefused returns the targets that only port- or path-limited
// entries cover at tier and that the job may not probe within those limits
// (scopedom.ConstrainedJobRefusal), with the refusal reason. Targets nothing
// covers, and internal ones, are left to the other checks. Part of
// scan.ConstraintGate.
func (g *ActiveGate) ConstraintRefused(ctx context.Context, tenantID shared.ID, targets []string, tier scopedom.Tier, job scopedom.JobShape) (map[string]string, error) {
	if err := g.ready(); err != nil {
		return nil, err
	}
	out := map[string]string{}
	if tier <= scopedom.TierPassive || len(targets) == 0 {
		return out, nil
	}
	if len(targets) > maxGateItems {
		return nil, fmt.Errorf("%w: too many targets for one constraint check", shared.ErrValidation)
	}
	var auth *scopeauth.Authority
	mode := ""
	portChecked := make([]string, 0, len(targets)) // names whose port scan depends on their addresses
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
		free, ports, path, covered := auth.Limits(t, tier)
		if !covered {
			// No entry covers it: only an unclassified asset the ownership
			// gate admitted gets here (RFC-054 §16). Its jobs stay inside the
			// low-impact profile unless the organization chose full. This
			// holds for every sensor, enforcing ones too: the signed limits
			// carry ports, not the template and rate caps.
			if mode == "" {
				mode = g.unclassifiedMode(ctx, tenantID)
			}
			switch {
			case mode == unclassifiedFull:
			case mode != unclassifiedLowImpact:
				out[t] = scopedom.RefusalLowImpact // the ownership gate refuses it first
			case tier > scopedom.TierActive:
				out[t] = scopedom.RefusalTierExceeds
			case scopedom.LowImpactRefusal(job.LowImpactJob()) != "":
				out[t] = scopedom.RefusalLowImpact
			}
			if _, no := out[t]; !no {
				portChecked = append(portChecked, t)
			}
			continue
		}
		if free || job.LimitsEnforced {
			// A sensor that enforces the limits gets them in the signed job
			// (StatementLimits) and may run any tool inside them.
			portChecked = append(portChecked, t)
			continue
		}
		if reason := scopedom.ConstrainedJobRefusal(job, ports, path); reason != "" {
			out[t] = reason
			continue
		}
		portChecked = append(portChecked, t)
	}
	if !job.PortScan() || len(portChecked) == 0 {
		return out, nil
	}
	if mode == "" {
		mode = g.unclassifiedMode(ctx, tenantID)
	}
	caps, err := g.namePortCaps(ctx, tenantID, auth, portChecked, mode)
	if err != nil {
		return nil, err
	}
	for t, cap := range caps {
		if job.TopPorts || strings.TrimSpace(job.Ports) == "" ||
			!scopedom.PortsWithin(job.Ports, []scopedom.Constraint{{Ports: cap}}) {
			out[t] = scopedom.RefusalWebPortsOnly
		}
	}
	return out, nil
}

// namePortCaps answers, for each name among targets, the ports a port scan
// of it may reach when that is not every port (RFC-054 §16.4): the web
// ports while any address it resolves to may not be probed on its own (a
// guardrail or a decision holds it) or nothing is known about its
// addresses; the low-impact ports while one is only an unclassified address
// in low_impact mode. An address a scope entry covers, or an unclassified
// one in full mode, lends the name every port. Addresses are never
// authorized by the name: this only narrows.
func (g *ActiveGate) namePortCaps(ctx context.Context, tenantID shared.ID, auth *scopeauth.Authority, targets []string, mode string) (map[string]string, error) {
	out := map[string]string{}
	hostOf := map[string]string{}
	hosts := make([]string, 0, len(targets))
	for _, t := range targets {
		h := scopeauth.Host(t)
		if h == "" {
			continue // an address or range: the gate judged it itself
		}
		hostOf[t] = h
		hosts = append(hosts, h)
	}
	if len(hosts) == 0 {
		return out, nil
	}
	addrsOf := map[string][]string{}
	if g.resolving != nil {
		var err error
		if addrsOf, err = g.resolving.AddressesOf(ctx, tenantID, hosts); err != nil {
			return nil, fmt.Errorf("load the addresses behind names: %w", err)
		}
	}
	var all []string
	seen := map[string]bool{}
	for _, as := range addrsOf {
		for _, a := range as {
			if !seen[a] {
				seen[a] = true
				all = append(all, a)
			}
		}
	}
	blocked := map[string]attribution.State{}
	if len(all) > 0 {
		var err error
		if blocked, err = g.BlockedTargets(ctx, tenantID, all); err != nil {
			return nil, err
		}
	}
	for t, h := range hostOf {
		addrs := addrsOf[h]
		cap := ""
		if len(addrs) == 0 {
			cap = scopedom.WebPorts
		}
		for _, a := range addrs {
			if _, ok := auth.Covers(a); ok {
				continue
			}
			if _, no := blocked[a]; no {
				cap = scopedom.WebPorts
				break
			}
			if mode == unclassifiedLowImpact {
				cap = scopedom.LowImpactPorts
			}
		}
		if cap != "" {
			out[t] = cap
		}
	}
	return out, nil
}

// StatementLimits are the scope limits a signed job carries for its
// targets (jobsign.Statement.Limits): for each target that only port- or
// path-limited entries cover at tier, one limit per covering entry, on the
// target's host. A host that an unlimited entry covers through any of the
// targets gets none (it is not limited). Targets nothing covers are left
// to the other checks.
func (g *ActiveGate) StatementLimits(ctx context.Context, tenantID shared.ID, targets []string, tier scopedom.Tier) ([]jobsign.Limit, error) {
	if err := g.ready(); err != nil {
		return nil, err
	}
	if len(targets) > maxGateItems {
		return nil, fmt.Errorf("%w: too many targets for one limit lookup", shared.ErrValidation)
	}
	var auth *scopeauth.Authority
	byHost := map[string][]scopedom.EntryLimit{}
	free := map[string]bool{}
	var hosts []string
	for _, t := range targets {
		h := jobsign.LimitHost(t)
		if h == "" || !needsAuthority(t) {
			continue
		}
		if auth == nil {
			var err error
			if auth, err = scopeauth.Load(ctx, tenantID, g.scope, g.roots); err != nil {
				return nil, err
			}
		}
		isFree, covered, ls := auth.EntryLimits(t, tier)
		switch {
		case !covered:
			continue
		case isFree:
			free[h] = true
			continue
		}
		if _, seen := byHost[h]; !seen {
			hosts = append(hosts, h)
		}
		for _, l := range ls {
			if !slices.Contains(byHost[h], l) {
				byHost[h] = append(byHost[h], l)
			}
		}
	}
	var out []jobsign.Limit
	for _, h := range hosts {
		if free[h] {
			continue
		}
		for _, l := range byHost[h] {
			out = append(out, jobsign.Limit{Host: h, Ports: l.Ports, Protocol: l.Protocol, PathPrefix: l.PathPrefix})
		}
	}
	return out, nil
}

// TierExceeded returns the targets the tenant's scope authority covers, but
// not at tier (RFC-054 §4.2 step 6, refusal tier_exceeds): every covering
// scope target has a lower max_tier, or only a seed or verified domain
// covers it and tier is above t1. Each is mapped to the covering entry with
// the highest ceiling (nil for a seed or verified domain). Targets nothing
// covers, and private or internal targets (scan zones gate them), are not
// listed: the ownership gate answers for them. Outside the Strict scan
// approval mode nothing exceeds (SetTierPolicy). Part of scan.AttributionGate.
func (g *ActiveGate) TierExceeded(ctx context.Context, tenantID shared.ID, targets []string, tier scopedom.Tier) (map[string]*scopedom.RuleRef, error) {
	if err := g.ready(); err != nil {
		return nil, err
	}
	out := map[string]*scopedom.RuleRef{}
	if tier <= scopedom.TierPassive || len(targets) == 0 {
		return out, nil
	}
	if len(targets) > maxGateItems {
		return nil, fmt.Errorf("%w: too many targets for one tier check", shared.ErrValidation)
	}
	if g.tiers != nil && !g.tiers.TierCeilingsEnforced(ctx, tenantID) {
		return out, nil
	}
	var auth *scopeauth.Authority
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
		if _, covered := auth.Covers(t); !covered {
			continue
		}
		if _, ok := auth.CoversAt(t, tier); ok {
			continue
		}
		var rule *scopedom.RuleRef
		if c := auth.Ceiling(t); c != nil {
			rule = &scopedom.RuleRef{Kind: scopedom.RuleScopeTarget, ID: c.ID().String(), Pattern: c.Pattern()}
		}
		out[t] = rule
	}
	return out, nil
}

// UncoveredTargets returns the targets naming an internet host or public
// address that no scope authority of the tenant covers: no active scope
// target, and no root-domain seed or verified domain at or above the name
// (RFC-071: a passive step takes only names in scope). Private and
// internal targets are not listed (scan zones gate them). Part of
// scan.AttributionGate.
func (g *ActiveGate) UncoveredTargets(ctx context.Context, tenantID shared.ID, targets []string) ([]string, error) {
	if err := g.ready(); err != nil {
		return nil, err
	}
	if len(targets) > maxGateItems {
		return nil, fmt.Errorf("%w: too many targets for one scope check", shared.ErrValidation)
	}
	var out []string
	var auth *scopeauth.Authority
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
		if _, ok := auth.Covers(t); !ok {
			out = append(out, t)
		}
	}
	if len(out) == 0 || g.unclassifiedMode(ctx, tenantID) == unclassifiedOff {
		return out, nil
	}
	// An unclassified inventory asset that active checks may reach
	// (RFC-054 §16) may be resolved too: only names the gate would refuse
	// stay out of a passive step.
	blocked, err := g.BlockedTargets(ctx, tenantID, out)
	if err != nil {
		return nil, err
	}
	kept := out[:0:0]
	for _, t := range out {
		if _, no := blocked[t]; no {
			kept = append(kept, t)
		}
	}
	return kept, nil
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
			if _, ok := auth.Covers(t); !ok {
				out[t] = attribution.StateUnattributed
			}
		}
	}
	return out, nil
}

// needsAuthority reports whether typed text names an internet host or a
// public address or range, which the scope authority must cover (a host with
// a path, such as a repository URL, counts as its host unless a scope target
// matches the whole text). Private and internal names are gated by scan
// zones; anything else (an identifier) is left to the act-scope check. The
// job signer's ledger uses the same rule (scopedom.NeedsAuthority).
func needsAuthority(t string) bool { return scopedom.NeedsAuthority(t) }

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
	hostRefusal, err := g.hostRefusals(ctx, tenantID, ids, assets)
	if err != nil {
		return nil, err
	}
	wildcard, err := g.wildcardOnly(ctx, tenantID, ids)
	if err != nil {
		return nil, err
	}

	var auth *scopeauth.Authority
	// unclassified: assets no scope entry covers that nobody excluded,
	// rejected or held, with the state they get while they stay passive.
	unclassified := map[string]attribution.State{}
	unclassifiedIDs := make([]string, 0, len(ids))
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
		// A child (a service, a URL) never gets more than its host: a
		// host a person did not leave to automation refuses its children.
		if st, ok := hostRefusal[id]; ok && !humanConfirmed {
			out[id] = st
			continue
		}
		// Resolves only through a wildcard record: passive only until a
		// person confirms this very asset.
		if wildcard[id] && !humanConfirmed {
			out[id] = attribution.StateWildcardOnly
			continue
		}
		if recorded && rec.State != attribution.StateConfirmed {
			if !automaticPending(rec) {
				out[id] = rec.State
				continue
			}
			// An automatic pending record: only an active scope entry that
			// covers the name lets probes reach it, whatever its type (a
			// private address too). The state stays as it is.
			if auth == nil {
				if auth, err = scopeauth.Load(ctx, tenantID, g.scope, g.roots); err != nil {
					return nil, err
				}
			}
			if _, ok := auth.Covers(a.Name()); !ok {
				unclassified[id] = rec.State
				unclassifiedIDs = append(unclassifiedIDs, id)
			}
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
			continue
		}
		if recorded {
			// Confirmed (by a person or a rule) but no scope entry, seed or
			// verified domain covers it any more, or never did.
			unclassified[id] = attribution.StateOutOfScope
		} else {
			unclassified[id] = attribution.StateUnattributed
		}
		unclassifiedIDs = append(unclassifiedIDs, id)
	}
	if len(unclassifiedIDs) == 0 {
		return out, nil
	}
	// Unclassified assets (RFC-054 §16): passive only while the mode is off;
	// otherwise active checks reach the ones no guardrail holds (the
	// low-impact cap is applied per job, ConstraintRefused).
	if g.unclassifiedMode(ctx, tenantID) == unclassifiedOff {
		for _, id := range unclassifiedIDs {
			out[id] = unclassified[id]
		}
		return out, nil
	}
	for id, reason := range g.guardrailReasons(ctx, tenantID, auth, unclassifiedIDs, assets) {
		if reason != "" {
			out[id] = attribution.StateGuardrailed
		}
	}
	return out, nil
}

// hostRefusals answers, for each asset whose name names a host other than
// itself (a service "host:port", a URL), the state of that host asset when
// it refuses probes on its own record: any state but confirmed, except an
// automatic pending one (which defers to the scope entries, as the child
// itself does). Hosts are the tenant's live assets only; a host with no
// asset or no record adds nothing.
func (g *ActiveGate) hostRefusals(ctx context.Context, tenantID shared.ID, ids []string, assets map[string]*asset.Asset) (map[string]attribution.State, error) {
	out := map[string]attribution.State{}
	hostName := map[string]string{} // asset id -> host name
	names := make([]string, 0, len(ids))
	for _, id := range ids {
		a := assets[id]
		if a == nil {
			continue
		}
		h := normalizeHost(asset.HostOf(a.Name()))
		if h == "" || h == normalizeHost(a.Name()) {
			continue
		}
		hostName[id] = h
		names = append(names, h)
	}
	if len(names) == 0 {
		return out, nil
	}
	hosts, err := g.assets.GetByNames(ctx, tenantID, names)
	if err != nil {
		return nil, fmt.Errorf("load hosts for the ownership check: %w", err)
	}
	hostIDs := make([]string, 0, len(hosts))
	idOfHost := map[string]string{} // host name -> host asset id
	for n, h := range hosts {
		if h == nil {
			continue
		}
		idOfHost[n] = h.ID().String()
		hostIDs = append(hostIDs, h.ID().String())
	}
	if len(hostIDs) == 0 {
		return out, nil
	}
	recs, err := g.records.Records(ctx, tenantID, hostIDs)
	if err != nil {
		return nil, fmt.Errorf("load host attribution for the ownership check: %w", err)
	}
	wildcardHost, err := g.wildcardOnly(ctx, tenantID, hostIDs)
	if err != nil {
		return nil, err
	}
	for id, h := range hostName {
		hid, ok := idOfHost[h]
		if !ok {
			continue
		}
		rec, ok := recs[hid]
		hostConfirmedByPerson := ok && rec.State == attribution.StateConfirmed && rec.HumanDecided
		if wildcardHost[hid] && !hostConfirmedByPerson {
			out[id] = attribution.StateWildcardOnly
			continue
		}
		if !ok || rec.State == attribution.StateConfirmed || automaticPending(rec) {
			continue
		}
		out[id] = rec.State
	}
	return out, nil
}

// automaticPending reports whether rec is a pending record written by
// automation (discovery, a scan, an unsolicited report): discovered,
// needs_review or candidate that no person set. Such a record is no
// decision, so a scope entry covering the asset decides. A person's
// needs_review (sent back to review) is a decision and keeps refusing.
func automaticPending(rec attribution.Record) bool {
	if rec.HumanDecided {
		return false
	}
	switch rec.State {
	case attribution.StateDiscovered, attribution.StateNeedsReview, attribution.StateCandidate:
		return true
	}
	return false
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
	// asset.HostOf reads every service name form ("host:443:tcp",
	// "host:443/tcp", "[v6]:443/tcp"), URLs and host:port, so a service
	// follows its host.
	h := normalizeHost(asset.HostOf(s))
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
func isInternalName(name string) bool { return scopedom.InternalName(name) }
