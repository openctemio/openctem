// Package scopeauth is the one answer to "has this tenant authorized active
// probes of this name or address?" (RFC-054 §4.2 step 6). The act-scope check
// (typed text) and the ownership gate (inventory assets and typed text) both
// ask it, so a typed target and the same name as an inventory asset get the
// same decision. Architecture: docs/architecture/active-probe-gate.md.
//
// The authority of a tenant is:
//
//   - its active scope targets (domain, IP, CIDR, URL, repository, …), matched
//     with pkg/domain/scope (a "*.x" target covers x and everything below it);
//   - its root-domain seeds and the domains it verified for attack-surface
//     work (purpose easm): a name at or under one. A domain verified for SSO
//     sign-in (purpose sso, set up by a platform administrator) never
//     authorizes; it still counts as proof of control (§8.1), which only
//     ever adds a requirement and never grants anything on its own.
//
// Every lookup is tenant-scoped; any lookup error refuses (the caller
// dispatches nothing). Another tenant's targets, seeds and verified domains
// never authorize anything here.
package scopeauth

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"

	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Targets lists the tenant's active scope targets (*scope.Service).
type Targets interface {
	ListActiveTargets(ctx context.Context, tenantID string) ([]*scopedom.Target, error)
}

// Roots lists the tenant's root-domain seeds and verified domains
// (*postgres.EASMSeedRepository).
type Roots interface {
	RootDomainSeedNames(ctx context.Context, tenantID shared.ID) ([]string, error)
	// VerifiedDomainNames: every verified domain, any purpose (proof).
	VerifiedDomainNames(ctx context.Context, tenantID shared.ID) ([]string, error)
	// EASMVerifiedDomainNames: verified domains of purpose easm only
	// (authority).
	EASMVerifiedDomainNames(ctx context.Context, tenantID shared.ID) ([]string, error)
}

// Kinds of authority that cover a name.
const (
	KindScopeTarget    = "scope_target"
	KindSeed           = "seed"
	KindVerifiedDomain = "verified_domain"
)

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
	seeds   []string
	// authorizing: verified domains that authorize (purpose easm).
	authorizing []string
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
	seeds, err := roots.RootDomainSeedNames(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list root-domain seeds: %w", err)
	}
	verified, err := roots.VerifiedDomainNames(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list verified domains: %w", err)
	}
	authorizing, err := roots.EASMVerifiedDomainNames(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list easm verified domains: %w", err)
	}
	a := &Authority{targets: ts}
	for _, r := range authorizing {
		if r = normalizeRoot(r); r != "" {
			a.authorizing = append(a.authorizing, r)
		}
	}
	for _, r := range seeds {
		if r = normalizeRoot(r); r != "" {
			a.seeds = append(a.seeds, r)
		}
	}
	for _, r := range verified {
		if r = normalizeRoot(r); r != "" {
			a.verified = append(a.verified, r)
		}
	}
	return a, nil
}

// Covers reports whether the tenant authorized active probes of name (an
// address, CIDR, host, host:port, URL or repository name) and what covers it.
// A verified domain is preferred over a seed, and a seed over a scope target,
// so Via names the strongest authority. Only a verified domain of purpose
// easm authorizes; a scope target or seed under an SSO-verified domain
// reports proof "verified".
func (a *Authority) Covers(name string) (Via, bool) {
	if a == nil {
		return Via{}, false
	}
	host := Host(name)
	proof := ProofAsserted
	if host != "" {
		if r, ok := underAny(host, a.authorizing); ok {
			return Via{Kind: KindVerifiedDomain, Pattern: r, Proof: ProofVerified}, true
		}
		if _, ok := underAny(host, a.verified); ok {
			proof = ProofVerified
		}
		if r, ok := underAny(host, a.seeds); ok {
			return Via{Kind: KindSeed, Pattern: r, Proof: proof}, true
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
	h = normalizeRoot(h)
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
	if strings.Contains(v, "://") {
		if u, err := url.Parse(v); err == nil {
			add(strings.ToLower(u.Hostname()))
		}
	} else if h, _, err := net.SplitHostPort(v); err == nil {
		add(strings.ToLower(h))
	}
	return out
}
