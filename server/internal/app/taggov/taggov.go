// Package taggov finds the asset tags that decisions read, so that nobody
// can change one without the authority to change the rule that reads it.
//
// A tag is governing when an enabled team access rule (tag match), scan
// approval rule, scan window, or assignment rule names it. Changing such a
// tag changes who sees an asset, whether a scan needs approval, when it may
// run, or who receives its findings. A person with `assets:write` alone must
// not be able to do that, and an import (sensor, connector, CSV) must never
// set one. A governing `key:value` tag governs its whole key: setting
// `env:staging` is as much a change as removing `env:prod`.
package taggov

import (
	"context"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/openctemio/openctem/server/pkg/domain/accesscontrol"
	"github.com/openctemio/openctem/server/pkg/domain/permission"
	"github.com/openctemio/openctem/server/pkg/domain/scangov"
	"github.com/openctemio/openctem/server/pkg/domain/scanwindow"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/tag"
	"github.com/openctemio/openctem/server/pkg/domain/tenant"
)

// Requirement is what a caller needs to change a governing tag: the
// permission that edits the rule reading it (or the admin role, for rules
// only administrators edit).
type Requirement struct {
	// Rule names the kind of rule, for the message and the audit entry.
	Rule string `json:"rule"`
	// Permission is the permission that edits that kind of rule.
	Permission string `json:"permission,omitempty"`
	// AdminOnly: the rule is edited by an owner or administrator.
	AdminOnly bool `json:"admin_only,omitempty"`
}

// The rule kinds.
const (
	RuleAccessScope    = "team access rule"
	RuleScanApproval   = "scan approval rule"
	RuleScanWindow     = "scan window"
	RuleAssignmentRule = "assignment rule"
)

// Ref is one tag a rule reads.
type Ref struct {
	Tag string
	Req Requirement
}

// Source lists the tags one kind of rule reads in a tenant.
type Source interface {
	Refs(ctx context.Context, tenantID shared.ID) ([]Ref, error)
}

// Set is the governing tags of one tenant.
type Set struct {
	exact map[string][]Requirement
	keys  map[string][]Requirement
}

// NewSet builds a set from refs.
func NewSet(refs []Ref) Set {
	s := Set{exact: map[string][]Requirement{}, keys: map[string][]Requirement{}}
	for _, r := range refs {
		t := strings.ToLower(strings.TrimSpace(r.Tag))
		if t == "" {
			continue
		}
		s.exact[t] = appendReq(s.exact[t], r.Req)
		if k, _, ok := strings.Cut(t, ":"); ok && k != "" {
			s.keys[k] = appendReq(s.keys[k], r.Req)
		}
	}
	return s
}

func appendReq(l []Requirement, r Requirement) []Requirement {
	for _, x := range l {
		if x == r {
			return l
		}
	}
	return append(l, r)
}

// Requirements returns what changing t needs (empty: t is not governing).
func (s Set) Requirements(t string) []Requirement {
	t = strings.ToLower(strings.TrimSpace(t))
	out := append([]Requirement(nil), s.exact[t]...)
	if k, _, ok := strings.Cut(t, ":"); ok {
		for _, r := range s.keys[k] {
			out = appendReq(out, r)
		}
	}
	return out
}

// Protected reports whether t is governing.
func (s Set) Protected(t string) bool { return len(s.Requirements(t)) > 0 }

// Change is one governing tag that a request adds or removes.
type Change struct {
	Tag  string        `json:"tag"`
	Reqs []Requirement `json:"requirements"`
}

// Changes returns the governing tags among the added and removed ones.
func (s Set) Changes(added, removed []string) []Change {
	var out []Change
	seen := map[string]bool{}
	for _, t := range append(append([]string(nil), added...), removed...) {
		l := strings.ToLower(t)
		if seen[l] {
			continue
		}
		seen[l] = true
		if r := s.Requirements(t); len(r) > 0 {
			out = append(out, Change{Tag: t, Reqs: r})
		}
	}
	return out
}

// Diff returns the tags in next that are not in current (added) and the
// tags in current that are not in next (removed). The comparison is exact: a
// change of case is a remove plus an add, so renaming "env:prod" to
// "Env:Prod" cannot slip past the check as "no change" while a rule that
// matches the exact string stops matching.
func Diff(current, next []string) (added, removed []string) {
	has := slices.Contains[[]string]
	for _, t := range next {
		if !has(current, t) {
			added = append(added, t)
		}
	}
	for _, t := range current {
		if !has(next, t) {
			removed = append(removed, t)
		}
	}
	return added, removed
}

// Allowed reports whether the caller meets every requirement of the
// changes. has answers whether the caller holds a permission; admin whether
// the caller is an owner or administrator.
func Allowed(changes []Change, has func(permission string) bool, admin bool) bool {
	for _, c := range changes {
		for _, r := range c.Reqs {
			switch {
			case r.AdminOnly && !admin:
				return false
			case !r.AdminOnly && !has(r.Permission):
				return false
			}
		}
	}
	return true
}

// Governor builds the Set of a tenant from its sources and caches it for a
// short time (a rule change takes effect within ttl).
type Governor struct {
	sources []Source
	ttl     time.Duration
	now     func() time.Time

	mu    sync.Mutex
	cache map[shared.ID]cached
}

type cached struct {
	set Set
	at  time.Time
}

// NewGovernor returns a governor over the sources.
func NewGovernor(ttl time.Duration, sources ...Source) *Governor {
	return &Governor{sources: sources, ttl: ttl, now: time.Now, cache: map[shared.ID]cached{}}
}

// For returns the governing tags of tenantID. On an error from any source
// it returns the error: callers fail closed.
func (g *Governor) For(ctx context.Context, tenantID shared.ID) (Set, error) {
	g.mu.Lock()
	if c, ok := g.cache[tenantID]; ok && g.now().Sub(c.at) < g.ttl {
		g.mu.Unlock()
		return c.set, nil
	}
	g.mu.Unlock()
	var refs []Ref
	for _, s := range g.sources {
		r, err := s.Refs(ctx, tenantID)
		if err != nil {
			return Set{}, err
		}
		refs = append(refs, r...)
	}
	set := NewSet(refs)
	g.mu.Lock()
	g.cache[tenantID] = cached{set: set, at: g.now()}
	g.mu.Unlock()
	return set, nil
}

// Invalidate drops the cached set of a tenant (a rule just changed).
func (g *Governor) Invalidate(tenantID shared.ID) {
	g.mu.Lock()
	delete(g.cache, tenantID)
	g.mu.Unlock()
}

// ImportAllow returns the allow function for tag.FilterImport: it refuses
// the tags of set. On an error getting the set it refuses every tag that has
// a key or could be one (fail closed).
func ImportAllow(set Set, err error) func(string) (tag.Reason, bool) {
	return func(t string) (tag.Reason, bool) {
		if err != nil || set.Protected(t) {
			return tag.ReasonProtected, false
		}
		return "", true
	}
}

// --- sources ---

// FuncSource adapts a function.
type FuncSource func(ctx context.Context, tenantID shared.ID) ([]Ref, error)

// Refs implements Source.
func (f FuncSource) Refs(ctx context.Context, t shared.ID) ([]Ref, error) { return f(ctx, t) }

// ScopeRules reads the tag-match rules of the teams' data scope.
type ScopeRules interface {
	ListActiveScopeRulesByTenant(ctx context.Context, tenantID shared.ID) ([]*accesscontrol.ScopeRule, error)
}

// ScopeRuleSource lists the tags active team access rules match.
func ScopeRuleSource(r ScopeRules) Source {
	return FuncSource(func(ctx context.Context, tid shared.ID) ([]Ref, error) {
		rules, err := r.ListActiveScopeRulesByTenant(ctx, tid)
		if err != nil {
			return nil, err
		}
		var out []Ref
		for _, ru := range rules {
			if ru.RuleType() != accesscontrol.ScopeRuleTagMatch {
				continue
			}
			for _, t := range ru.MatchTags() {
				out = append(out, Ref{Tag: t, Req: Requirement{Rule: RuleAccessScope, Permission: permission.GroupsWrite.String()}})
			}
		}
		return out, nil
	})
}

// AssignmentRules reads the assignment rules.
type AssignmentRules interface {
	ListActiveRulesByPriority(ctx context.Context, tenantID shared.ID) ([]*accesscontrol.AssignmentRule, error)
}

// AssignmentRuleSource lists the asset tags active assignment rules read.
func AssignmentRuleSource(r AssignmentRules) Source {
	return FuncSource(func(ctx context.Context, tid shared.ID) ([]Ref, error) {
		rules, err := r.ListActiveRulesByPriority(ctx, tid)
		if err != nil {
			return nil, err
		}
		var out []Ref
		for _, ru := range rules {
			for _, t := range ru.Conditions().AssetTags {
				out = append(out, Ref{Tag: t, Req: Requirement{Rule: RuleAssignmentRule, Permission: permission.AssignmentRulesWrite.String()}})
			}
		}
		return out, nil
	})
}

// ScanWindows lists scan window policies.
type ScanWindows interface {
	List(ctx context.Context, tenantID shared.ID, f scanwindow.Filter) ([]*scanwindow.Policy, error)
}

// ScanWindowSource lists the tags enabled scan windows select.
func ScanWindowSource(r ScanWindows) Source {
	return FuncSource(func(ctx context.Context, tid shared.ID) ([]Ref, error) {
		ps, err := r.List(ctx, tid, scanwindow.Filter{EnabledOnly: true})
		if err != nil {
			return nil, err
		}
		var out []Ref
		for _, p := range ps {
			for _, t := range p.Selector.Tags {
				out = append(out, Ref{Tag: t, Req: Requirement{Rule: RuleScanWindow, Permission: permission.ScanWindowsManage.String()}})
			}
		}
		return out, nil
	})
}

// ApprovalSettings reads the scan approval rules of an organization.
type ApprovalSettings interface {
	GetScanGovernanceSettings(ctx context.Context, tenantID string) (*tenant.ScanGovernanceSettings, error)
}

// ApprovalRuleSource lists the tags enabled scan approval rules read. The
// rules are edited by owners and administrators.
func ApprovalRuleSource(r ApprovalSettings) Source {
	return FuncSource(func(ctx context.Context, tid shared.ID) ([]Ref, error) {
		st, err := r.GetScanGovernanceSettings(ctx, tid.String())
		if err != nil {
			return nil, err
		}
		var out []Ref
		if st == nil {
			return nil, nil
		}
		for _, ru := range st.Rules {
			if !ru.Enabled {
				continue
			}
			out = appendApproval(out, ru)
		}
		return out, nil
	})
}

func appendApproval(out []Ref, ru scangov.Rule) []Ref {
	for _, t := range ru.Conditions.AssetTags {
		out = append(out, Ref{Tag: t, Req: Requirement{Rule: RuleScanApproval, AdminOnly: true}})
	}
	return out
}
