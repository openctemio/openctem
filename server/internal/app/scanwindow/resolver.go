// Package scanwindow applies scan window policies (RFC-067,
// docs/architecture/scan-windows.md): it finds the sources that govern a
// target (resolver.go) and manages policies and overrides (service.go). The
// decision itself is pkg/domain/scanwindow.Decide.
package scanwindow

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/internal/app/scopeauth"
	bp "github.com/openctemio/openctem/api/pkg/domain/bountyprogram"
	swdom "github.com/openctemio/openctem/api/pkg/domain/scanwindow"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// PolicyLister lists a tenant's policies (the policy repository).
type PolicyLister interface {
	List(ctx context.Context, tenantID shared.ID, f swdom.Filter) ([]*swdom.Policy, error)
}

// ActiveOverrides lists the overrides active at an instant (the override
// repository).
type ActiveOverrides interface {
	ListActive(ctx context.Context, tenantID shared.ID, t time.Time) ([]*swdom.Override, error)
}

// ProgramLookup reads a program of the tenant (the program repository).
type ProgramLookup interface {
	GetByID(ctx context.Context, tenantID, id shared.ID) (*bp.Program, error)
}

// Resolver finds the sources governing targets. Build it with NewResolver;
// the asset matcher, scope and programs are optional (a policy that needs a
// missing one fails closed: Load returns an error).
type Resolver struct {
	policies  PolicyLister
	overrides ActiveOverrides
	assets    swdom.AssetMatcher
	scope     scopeauth.Targets
	programs  ProgramLookup
}

// NewResolver creates a resolver over the policy and override stores.
func NewResolver(policies PolicyLister, overrides ActiveOverrides) *Resolver {
	return &Resolver{policies: policies, overrides: overrides}
}

// SetAssets wires the asset matcher (selectors on tags, groups, types,
// criticality and business units).
func (r *Resolver) SetAssets(m swdom.AssetMatcher) { r.assets = m }

// SetScope wires the scope entries and programs (selectors on scope entries
// and programs, and the programs' testing windows).
func (r *Resolver) SetScope(t scopeauth.Targets, p ProgramLookup) { r.scope, r.programs = t, p }

// noProof: matching needs coverage, not proof of ownership.
type noProof struct{}

func (noProof) VerifiedDomainNames(context.Context, shared.ID) ([]string, error) { return nil, nil }

// Snapshot is what governs a set of targets of one tenant at one instant.
// SourcesFor and the Decide helpers are pure.
type Snapshot struct {
	now       time.Time
	policies  []*swdom.Policy
	sources   map[shared.ID]swdom.Source
	overrides []*swdom.Override
	assets    map[string][]swdom.TargetAsset
	entries   map[string][]string
	programs  map[string][]string // target -> covering program ids
	progSrc   map[string]swdom.Source
}

// Load reads what governs targets of tenantID at now. Every read is
// tenant-scoped; any error is returned (callers fail closed).
func (r *Resolver) Load(ctx context.Context, tenantID shared.ID, targets []string, now time.Time) (*Snapshot, error) {
	if r == nil || r.policies == nil {
		return nil, fmt.Errorf("scan window policies are not configured")
	}
	s := &Snapshot{now: now, sources: map[shared.ID]swdom.Source{}}
	policies, err := r.policies.List(ctx, tenantID, swdom.Filter{EnabledOnly: true})
	if err != nil {
		return nil, fmt.Errorf("list scan window policies: %w", err)
	}
	needAssets, needScope := false, r.programs != nil && r.scope != nil
	for _, p := range policies {
		if !p.TenantID.Equals(tenantID) {
			continue // never another tenant's policy
		}
		s.policies = append(s.policies, p)
		s.sources[p.ID] = swdom.PolicySource(p)
		needAssets = needAssets || p.Selector.UsesAssets()
		needScope = needScope || p.Selector.UsesScope()
	}
	if len(s.policies) > 0 && r.overrides != nil {
		if s.overrides, err = r.overrides.ListActive(ctx, tenantID, now); err != nil {
			return nil, fmt.Errorf("list scan window overrides: %w", err)
		}
	}
	targets = uniqueTargets(targets)
	if needAssets && len(targets) > 0 {
		if r.assets == nil {
			return nil, fmt.Errorf("a scan window policy selects assets but assets cannot be matched")
		}
		if s.assets, err = r.assets.MatchTargetAssets(ctx, tenantID, targets); err != nil {
			return nil, fmt.Errorf("match target assets: %w", err)
		}
	}
	if needScope && len(targets) > 0 {
		if r.scope == nil {
			return nil, fmt.Errorf("a scan window policy selects scope entries or programs but the scope is not wired")
		}
		if err := s.loadScope(ctx, tenantID, targets, r.scope, r.programs); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func (s *Snapshot) loadScope(ctx context.Context, tenantID shared.ID, targets []string, scope scopeauth.Targets, programs ProgramLookup) error {
	auth, err := scopeauth.Load(ctx, tenantID, scope, noProof{})
	if err != nil {
		return fmt.Errorf("load scope: %w", err)
	}
	s.entries = map[string][]string{}
	s.programs = map[string][]string{}
	s.progSrc = map[string]swdom.Source{}
	loaded := map[shared.ID]bool{}
	for _, t := range targets {
		s.entries[t] = auth.EntriesCovering(t)
		for _, pid := range auth.ProgramsCovering(t) {
			s.programs[t] = append(s.programs[t], pid.String())
			if loaded[pid] || programs == nil {
				continue
			}
			loaded[pid] = true
			p, err := programs.GetByID(ctx, tenantID, pid)
			if err != nil {
				return fmt.Errorf("program %s: %w", pid, err)
			}
			if !p.TenantID.Equals(tenantID) {
				continue
			}
			if len(p.Rules.TestingWindows) > 0 {
				s.progSrc[pid.String()] = ProgramSource(p)
			}
		}
	}
	return nil
}

// ProgramSource is the allow source of a program's testing windows: every
// tool, grace 0, the program's rate, never overridable. A window whose time
// zone or times cannot be read makes the source fail closed.
func ProgramSource(p *bp.Program) swdom.Source {
	src := swdom.Source{
		ID: "program:" + p.ID.String(), Name: p.Name, Kind: swdom.KindAllow, Origin: swdom.OriginProgram,
		MinTier: swdom.TierAll, RateLimitRPS: p.Rules.RateLimitRPS,
	}
	for _, w := range p.Rules.TestingWindows {
		loc, err := time.LoadLocation(w.Timezone)
		start, err1 := swdom.ParseMinute(w.Start)
		end, err2 := swdom.ParseMinute(w.End)
		if err != nil || err1 != nil || err2 != nil {
			src.Broken = true
			return src
		}
		var days []int
		for _, d := range w.Days {
			iso, ok := programDays[strings.ToLower(d)]
			if !ok {
				src.Broken = true
				return src
			}
			days = append(days, iso)
		}
		src.Slots = append(src.Slots, swdom.LocalSlot{Days: days, Start: start, End: end, Loc: loc})
	}
	return src
}

var programDays = map[string]int{"mon": 1, "tue": 2, "wed": 3, "thu": 4, "fri": 5, "sat": 6, "sun": 7}

// Empty reports whether nothing governs any target of the snapshot.
func (s *Snapshot) Empty() bool {
	return s == nil || (len(s.policies) == 0 && len(s.progSrc) == 0)
}

// Now is the instant the snapshot was loaded for.
func (s *Snapshot) Now() time.Time { return s.now }

// SourcesFor returns the sources governing target when its work runs in
// zone (nil: no zone), minus those an active override suspends.
func (s *Snapshot) SourcesFor(target string, zone *shared.ID) []swdom.Source {
	target = strings.TrimSpace(target)
	if s.Empty() {
		return nil
	}
	var out []swdom.Source
	for _, p := range s.policies {
		if s.matches(p.Selector, target, zone) {
			out = append(out, s.sources[p.ID])
		}
	}
	for _, pid := range s.programs[target] {
		if src, ok := s.progSrc[pid]; ok {
			out = append(out, src)
		}
	}
	return swdom.WithoutSuspended(out, s.overrides, s.now)
}

// Decide is the decision for work of tier on all of targets together (every
// target must be open).
func (s *Snapshot) Decide(targets []string, zone *shared.ID, tier int) swdom.Decision {
	var all []swdom.Source
	for _, t := range targets {
		all = append(all, s.SourcesFor(t, zone)...)
	}
	return swdom.Decide(all, tier, s.now)
}

// DecideEach is the decision for each target alone.
func (s *Snapshot) DecideEach(targets []string, zone *shared.ID, tier int) map[string]swdom.Decision {
	out := make(map[string]swdom.Decision, len(targets))
	for _, t := range targets {
		if _, ok := out[t]; !ok {
			out[t] = swdom.Decide(s.SourcesFor(t, zone), tier, s.now)
		}
	}
	return out
}

// Assets returns the assets a target names (loaded only when a policy
// selects by asset).
func (s *Snapshot) Assets(target string) []swdom.TargetAsset { return s.assets[target] }

func (s *Snapshot) matches(sel swdom.Selector, target string, zone *shared.ID) bool {
	if len(sel.ScanZoneIDs) > 0 && (zone == nil || !slices.Contains(sel.ScanZoneIDs, zone.String())) {
		return false
	}
	if sel.UsesAssets() && !slices.ContainsFunc(s.assets[target], func(a swdom.TargetAsset) bool { return AssetMatches(sel, a) }) {
		return false
	}
	if len(sel.ScopeTargetIDs) > 0 && !intersects(s.entries[target], sel.ScopeTargetIDs) {
		return false
	}
	if len(sel.ProgramIDs) > 0 && !intersects(s.programs[target], sel.ProgramIDs) {
		return false
	}
	return true
}

// AssetMatches reports whether one asset meets every asset dimension of sel
// (tags case-insensitively).
func AssetMatches(sel swdom.Selector, a swdom.TargetAsset) bool {
	if len(sel.Tags) > 0 && !slices.ContainsFunc(a.Tags, func(t string) bool {
		return slices.ContainsFunc(sel.Tags, func(w string) bool { return strings.EqualFold(w, t) })
	}) {
		return false
	}
	if len(sel.AssetGroupIDs) > 0 && !intersects(a.GroupIDs, sel.AssetGroupIDs) {
		return false
	}
	if len(sel.AssetTypes) > 0 && !slices.Contains(sel.AssetTypes, a.Type) {
		return false
	}
	if len(sel.Criticalities) > 0 && !slices.Contains(sel.Criticalities, a.Criticality) {
		return false
	}
	if len(sel.BusinessUnitIDs) > 0 && !intersects(a.BusinessUnitIDs, sel.BusinessUnitIDs) {
		return false
	}
	return true
}

func intersects(a, b []string) bool {
	for _, x := range a {
		if slices.Contains(b, x) {
			return true
		}
	}
	return false
}

func uniqueTargets(in []string) []string {
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, t := range in {
		if t = strings.TrimSpace(t); t != "" && !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	return out
}
