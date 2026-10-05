// Package actscope decides which scan targets an actor may scan (research/15
// L-06, owner decision D9). Architecture: docs/architecture/active-probe-gate.md.
//
//   - A target that is an inventory asset may be scanned only by an actor who
//     can act on that asset (datascope.Enforcer.CanActOnAssets).
//   - A free-text target that is not an inventory asset may be scanned only by
//     an unrestricted actor, and only when it matches an active scope target
//     of the tenant (the scoping allowlist). Exclusions are applied by the
//     dispatch gate on top of this.
//   - A restricted actor may scan only inventory assets in their data scope.
//
// Every lookup error refuses (fail closed).
package actscope

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ActEnforcer is the one "may this actor act on these assets" check
// (*datascope.Enforcer).
type ActEnforcer interface {
	CanActOnAssets(ctx context.Context, tenantID shared.ID, fallbackUser *shared.ID, assetIDs []shared.ID) (func(shared.ID) bool, bool, error)
}

// AssetNames finds the tenant's assets by name (*postgres.AssetRepository).
type AssetNames interface {
	GetByNames(ctx context.Context, tenantID shared.ID, names []string) (map[string]*asset.Asset, error)
}

// ScopeTargets lists the tenant's active scope targets (*scope.Service).
type ScopeTargets interface {
	ListActiveTargets(ctx context.Context, tenantID string) ([]*scopedom.Target, error)
}

// Input is what an actor asks to scan.
type Input struct {
	TenantID shared.ID
	// FallbackUser acts when the context carries no user (a scheduled run:
	// the scan owner). Nil with no user in the context is the system.
	FallbackUser *shared.ID
	Targets      []string    // free-text targets, as typed
	AssetIDs     []shared.ID // inventory assets (asset-group members)
}

// Decision lists what the actor may not scan, with the reason.
type Decision struct {
	RefusedTargets map[string]string // target as given -> reason
	RefusedAssets  map[shared.ID]bool
}

// Refused reports whether anything was refused.
func (d *Decision) Refused() bool {
	return d != nil && (len(d.RefusedTargets) > 0 || len(d.RefusedAssets) > 0)
}

// Reasons shown to the caller.
const (
	ReasonOutOfDataScope = "the asset is outside your data scope"
	ReasonNotAnAsset     = "not an asset in your data scope; restricted members may scan only their assets"
	ReasonNoScopeTarget  = "matches no scope target; add it to Scoping > Targets before scanning it"
)

// Checker implements the act-scope rule.
type Checker struct {
	enforcer ActEnforcer
	assets   AssetNames
	targets  ScopeTargets
}

// New wires the checker. Every dependency is required: a nil one refuses
// every target (fail closed).
func New(enforcer ActEnforcer, assets AssetNames, targets ScopeTargets) *Checker {
	return &Checker{enforcer: enforcer, assets: assets, targets: targets}
}

// Check decides which targets and assets the actor may scan. It returns an
// error only when the decision cannot be made; nothing may be dispatched then.
func (c *Checker) Check(ctx context.Context, in Input) (*Decision, error) {
	if c == nil || c.enforcer == nil || c.assets == nil || c.targets == nil {
		return nil, fmt.Errorf("act-scope check is not configured; nothing dispatched")
	}
	if in.TenantID.IsZero() {
		return nil, fmt.Errorf("%w: tenant is required", shared.ErrValidation)
	}
	out := &Decision{RefusedTargets: map[string]string{}, RefusedAssets: map[shared.ID]bool{}}

	// Free-text targets that name an inventory asset are checked as that asset.
	byTarget, err := c.resolveAssets(ctx, in.TenantID, in.Targets)
	if err != nil {
		return nil, err
	}
	ids := make([]shared.ID, 0, len(in.AssetIDs)+len(byTarget))
	ids = append(ids, in.AssetIDs...)
	for _, id := range byTarget {
		ids = append(ids, id)
	}
	canAct, unrestricted, err := c.enforcer.CanActOnAssets(ctx, in.TenantID, in.FallbackUser, ids)
	if err != nil {
		return nil, err
	}

	for _, id := range in.AssetIDs {
		if !canAct(id) {
			out.RefusedAssets[id] = true
		}
	}

	var allowlist []*scopedom.Target
	allowlistLoaded := false
	for _, t := range in.Targets {
		if strings.TrimSpace(t) == "" {
			continue
		}
		if id, ok := byTarget[t]; ok {
			if !canAct(id) {
				out.RefusedTargets[t] = ReasonOutOfDataScope
			}
			continue
		}
		if !unrestricted {
			out.RefusedTargets[t] = ReasonNotAnAsset
			continue
		}
		if !allowlistLoaded {
			allowlist, err = c.targets.ListActiveTargets(ctx, in.TenantID.String())
			if err != nil {
				return nil, fmt.Errorf("list scope targets: %w", err)
			}
			allowlistLoaded = true
		}
		if !matchesAllowlist(allowlist, t) {
			out.RefusedTargets[t] = ReasonNoScopeTarget
		}
	}
	return out, nil
}

// resolveAssets maps each free-text target that names one of the tenant's
// assets (as typed, lower-cased, or by the host of a URL / host:port) to it.
func (c *Checker) resolveAssets(ctx context.Context, tenantID shared.ID, targets []string) (map[string]shared.ID, error) {
	out := map[string]shared.ID{}
	if len(targets) == 0 {
		return out, nil
	}
	forms := map[string][]string{}
	names := make([]string, 0, len(targets)*3)
	for _, t := range targets {
		f := MatchForms(t)
		forms[t] = f
		names = append(names, f...)
	}
	found, err := c.assets.GetByNames(ctx, tenantID, names)
	if err != nil {
		return nil, fmt.Errorf("resolve scan targets to assets: %w", err)
	}
	for t, fs := range forms {
		for _, f := range fs {
			if a, ok := found[f]; ok && a != nil {
				out[t] = a.ID()
				break
			}
		}
	}
	return out, nil
}

// matchesAllowlist reports whether the target (or the host it names) matches
// an active scope target.
func matchesAllowlist(allowlist []*scopedom.Target, target string) bool {
	for _, f := range MatchForms(target) {
		for _, st := range allowlist {
			if st != nil && st.Matches(f) {
				return true
			}
		}
	}
	return false
}

// MatchForms is the target as typed, lower-cased, and the host of a URL or
// host:port.
func MatchForms(target string) []string {
	v := strings.TrimSpace(target)
	out := []string{v}
	add := func(s string) {
		s = strings.Trim(strings.TrimSpace(s), "[]")
		if s == "" {
			return
		}
		for _, have := range out {
			if have == s {
				return
			}
		}
		out = append(out, s)
	}
	add(strings.ToLower(v))
	if strings.Contains(v, "://") {
		if u, err := url.Parse(v); err == nil {
			add(strings.ToLower(u.Hostname()))
		}
	} else if h, _, err := net.SplitHostPort(v); err == nil {
		add(strings.ToLower(h))
	}
	return out
}
