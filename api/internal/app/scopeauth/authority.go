// Package scopeauth is the one answer to "has this tenant authorized active
// probes of this name or address?" (RFC-054 §4.2 step 6). The act-scope check
// (typed text) and the ownership gate (inventory assets and typed text) both
// ask it, so a typed target and the same name as an inventory asset get the
// same decision. Architecture: docs/architecture/active-probe-gate.md.
//
// The authority of a tenant is its active scope entries (domain, IP, CIDR,
// URL, repository, ...), matched with pkg/domain/scope (a "*.x" entry covers
// x and everything below it). Nothing else authorizes (research/53 SC1,
// SC2): root-domain seeds were folded into entries (migration 001262), and a
// verified domain, of any purpose, is proof of control only (§8.1): it adds
// a requirement where proof is needed and never grants anything by itself.
//
// Every lookup is tenant-scoped; any lookup error refuses (the caller
// dispatches nothing). Another tenant's entries and verified domains never
// count here.
package scopeauth

import (
	"context"
	"fmt"
	"net/netip"
	"net/url"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/asset"

	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Targets lists the tenant's active scope targets (*scope.Service).
type Targets interface {
	ListActiveTargets(ctx context.Context, tenantID string) ([]*scopedom.Target, error)
}

// Roots lists the tenant's verified domains, the proof of control
// (*postgres.VerifiedDomainNameRepository).
type Roots interface {
	// VerifiedDomainNames: every verified domain, any purpose.
	VerifiedDomainNames(ctx context.Context, tenantID shared.ID) ([]string, error)
}

// KindScopeTarget is the one kind of authority: a scope entry.
const KindScopeTarget = "scope_target"

// Proof levels of the name (RFC-054 §8.1).
const (
	ProofVerified = "verified"
	ProofAsserted = "asserted"
)

// Via is what covers a name: the kind, the scope target id (for a scope
// target), the pattern or root, and whether the name sits at or under a
// verified domain.
type Via struct {
	Kind    string `json:"kind"`
	ID      string `json:"id,omitempty"`
	Pattern string `json:"pattern"`
	Proof   string `json:"proof"`
}

// Authority is one tenant's loaded authority. Build it with Load.
type Authority struct {
	targets []*scopedom.Target
	// verified: every verified domain, the proof of control.
	verified []string
}

// Load reads the tenant's authority. Both sources are required; a nil one
// fails (fail closed).
func Load(ctx context.Context, tenantID shared.ID, targets Targets, roots Roots) (*Authority, error) {
	if targets == nil || roots == nil {
		return nil, fmt.Errorf("scope authority is not configured; nothing dispatched")
	}
	if tenantID.IsZero() {
		return nil, fmt.Errorf("%w: tenant is required", shared.ErrValidation)
	}
	ts, err := targets.ListActiveTargets(ctx, tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("list scope targets: %w", err)
	}
	verified, err := roots.VerifiedDomainNames(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list verified domains: %w", err)
	}
	a := &Authority{targets: ts}
	for _, r := range verified {
		if r = normalizeRoot(r); r != "" {
			a.verified = append(a.verified, r)
		}
	}
	return a, nil
}

// Covers reports whether the tenant authorized active probes of name (an
// address, CIDR, host, host:port, URL or repository name) and which entry
// covers it. Proof is "verified" when the name sits at or under a verified
// domain, "asserted" otherwise.
func (a *Authority) Covers(name string) (Via, bool) {
	if a == nil {
		return Via{}, false
	}
	host := Host(name)
	proof := ProofAsserted
	if host != "" {
		if _, ok := underAny(host, a.verified); ok {
			proof = ProofVerified
		}
	}
	for _, f := range MatchForms(name) {
		for _, t := range a.targets {
			if t != nil && t.Matches(f) {
				return Via{Kind: KindScopeTarget, ID: t.ID().String(), Pattern: t.Pattern(), Proof: proof}, true
			}
		}
	}
	return Via{}, false
}

// CoversAt is Covers for a probe of the given tier (RFC-054 §4.2 step 6): an
// entry covers only when its max_tier is at or above tier. As in Covers, a
// verified domain never authorizes; it only proves.
func (a *Authority) CoversAt(name string, tier scopedom.Tier) (Via, bool) {
	if a == nil {
		return Via{}, false
	}
	host := Host(name)
	proof := ProofAsserted
	if host != "" {
		if _, ok := underAny(host, a.verified); ok {
			proof = ProofVerified
		}
	}
	for _, f := range MatchForms(name) {
		for _, t := range a.targets {
			if t != nil && t.MaxTier() >= tier && t.Matches(f) {
				return Via{Kind: KindScopeTarget, ID: t.ID().String(), Pattern: t.Pattern(), Proof: proof}, true
			}
		}
	}
	return Via{}, false
}

// Ceiling names the tenant's scope target with the highest max_tier that
// covers name (nil when none does).
func (a *Authority) Ceiling(name string) *scopedom.Target {
	if a == nil {
		return nil
	}
	var best *scopedom.Target
	for _, f := range MatchForms(name) {
		for _, t := range a.targets {
			if t != nil && t.Matches(f) && (best == nil || t.MaxTier() > best.MaxTier()) {
				best = t
			}
		}
	}
	return best
}

// Verified reports whether name is at or under one of the tenant's verified
// domains (the ownership proof RFC-054 §8.1 asks for).
func (a *Authority) Verified(name string) bool {
	if a == nil {
		return false
	}
	h := Host(name)
	if h == "" {
		return false
	}
	_, ok := underAny(h, a.verified)
	return ok
}

// underAny returns the first root that host equals or sits under.
func underAny(host string, roots []string) (string, bool) {
	for _, r := range roots {
		if host == r || strings.HasSuffix(host, "."+r) {
			return r, true
		}
	}
	return "", false
}

func normalizeRoot(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimPrefix(s, "*.")
	return strings.TrimSuffix(s, ".")
}

// Host is the lower-case DNS name a target or asset name points at ("" for
// an address, a CIDR or something that is not a host name).
func Host(s string) string {
	h := strings.TrimSpace(s)
	if strings.Contains(h, "://") {
		if _, err := url.Parse(h); err != nil {
			return ""
		}
	}
	h = normalizeRoot(asset.HostOf(h))
	if h == "" || !strings.Contains(h, ".") {
		return ""
	}
	if _, err := netip.ParseAddr(strings.Trim(h, "[]")); err == nil {
		return ""
	}
	return h
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
	if h := asset.HostOf(v); !strings.EqualFold(h, v) {
		add(h)
	}
	return out
}
