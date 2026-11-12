package scope

// Blocked target names (docs/rfcs/RFC-154-blocked-target-names.md): the
// government and military rule of the guardrails is a platform setting with
// per-organization exceptions, and the operator adds blocked names in the
// console. Every copy of Guardrails reads one shared NamePolicy, so a change
// applies to every check without rebuilding the guardrails.
//
// An exception lifts only the government and military rule, only for its
// organization and only for its name (and the names under it when
// Subdomains). It is judged against the clock at every check, so an expired
// one is refused when an entry is added and at dispatch alike. A check
// without an organization (Guardrails.For not called) applies no exception.

import (
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/publicsuffix"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// ErrGovernmentName refuses a government or military name the built-in rule
// blocks and no exception of the organization lifts.
var ErrGovernmentName = shared.NewDomainError("GOVERNMENT_NAME",
	"government and military domains are blocked on this installation; your platform administrator can grant an exception",
	shared.ErrValidation)

// Exception refusals.
var (
	// ErrExceptionName: the name is not a domain name, or is a public suffix.
	ErrExceptionName = shared.NewDomainError("EXCEPTION_NAME_INVALID",
		"an exception names one domain, such as portal.example.gov.xx", shared.ErrValidation)
	// ErrExceptionNotGovernment: the government rule does not block the name,
	// so an exception has nothing to lift.
	ErrExceptionNotGovernment = shared.NewDomainError("EXCEPTION_NOT_GOVERNMENT",
		"the government and military rule does not block this name", shared.ErrValidation)
	// ErrExceptionTooWide: the name is a government suffix itself.
	ErrExceptionTooWide = shared.NewDomainError("EXCEPTION_TOO_WIDE",
		"an exception must name a domain under the government suffix, never the suffix itself", shared.ErrValidation)
)

// governmentRoot returns the government or military suffix that blocks host
// ("gov", "gov.xx", "gc.ca"), or "".
func governmentRoot(host string) string {
	labels := strings.Split(host, ".")
	n := len(labels)
	last := labels[n-1]
	if last == "gov" || last == "mil" {
		return last
	}
	if n >= 2 && len(last) == 2 && governmentSLDs[labels[n-2]] {
		return labels[n-2] + "." + last
	}
	for _, s := range deniedNames {
		if host == s || strings.HasSuffix(host, "."+s) {
			return s
		}
	}
	return ""
}

// GovernmentName reports whether the built-in rule covers host.
func GovernmentName(host string) bool {
	_, host = splitDomainWildcard(host)
	return host != "" && governmentRoot(host) != ""
}

// NormalizeExceptionName checks and normalises the name of an exception:
// a domain name (no wildcard, no address) the government rule blocks, strictly
// under its government suffix, and not a public suffix.
func NormalizeExceptionName(name string) (string, error) {
	wild, host := splitDomainWildcard(name)
	if wild || host == "" || strings.ContainsAny(host, "*/:@ ") || !strings.Contains(host, ".") ||
		ValidatePattern(TargetTypeDomain, host) != nil {
		return "", ErrExceptionName
	}
	root := governmentRoot(host)
	if root == "" {
		return "", ErrExceptionNotGovernment
	}
	if host == root || !strings.HasSuffix(host, "."+root) {
		return "", ErrExceptionTooWide
	}
	if ps, _ := publicsuffix.PublicSuffix(host); ps == host {
		return "", ErrExceptionTooWide
	}
	return host, nil
}

// NameException is one organization's exception, as the guardrails see it.
type NameException struct {
	TenantID   shared.ID
	Name       string
	Subdomains bool
	ExpiresAt  time.Time
}

// covers reports whether e lifts the rule for host (a wildcard entry *.host
// needs Subdomains).
func (e NameException) covers(host string, wildcard bool) bool {
	if host == e.Name {
		return !wildcard || e.Subdomains
	}
	return e.Subdomains && strings.HasSuffix(host, "."+e.Name)
}

// NameSnapshot is the policy in force.
type NameSnapshot struct {
	// GovernmentRuleOff turns the built-in rule off. The zero value keeps it
	// on: an unread or empty policy fails closed.
	GovernmentRuleOff bool
	// Names are the operator's blocked names from the console (suffixes).
	Names []string
	// Exceptions are the active exceptions (revoked ones are left out;
	// expired ones are refused by the clock).
	Exceptions []NameException
}

type nameState struct {
	snap     NameSnapshot
	byTenant map[shared.ID][]NameException
	at       time.Time
}

// NamePolicy holds the policy every copy of the guardrails reads. Safe for
// concurrent use.
type NamePolicy struct {
	cur atomic.Pointer[nameState]
	now func() time.Time

	mu         sync.Mutex
	refresh    func()
	ttl        time.Duration
	refreshing atomic.Bool
}

// NewNamePolicy creates a policy with the built-in rule on, no operator names
// and no exceptions.
func NewNamePolicy() *NamePolicy {
	p := &NamePolicy{now: time.Now}
	p.Set(NameSnapshot{})
	return p
}

// SetClock replaces the clock (tests).
func (p *NamePolicy) SetClock(now func() time.Time) { p.now = now }

// OnStale makes the policy call refresh (in its own goroutine, one at a time)
// when the snapshot is older than ttl. refresh calls Set.
func (p *NamePolicy) OnStale(ttl time.Duration, refresh func()) {
	p.mu.Lock()
	p.refresh, p.ttl = refresh, ttl
	p.mu.Unlock()
}

// Set replaces the snapshot.
func (p *NamePolicy) Set(s NameSnapshot) {
	names := make([]string, 0, len(s.Names))
	for _, n := range s.Names {
		if _, n = splitDomainWildcard(n); n != "" {
			names = append(names, n)
		}
	}
	s.Names = names
	s.Exceptions = slices.Clone(s.Exceptions)
	st := &nameState{snap: s, byTenant: map[shared.ID][]NameException{}, at: p.now()}
	for _, e := range s.Exceptions {
		st.byTenant[e.TenantID] = append(st.byTenant[e.TenantID], e)
	}
	p.cur.Store(st)
}

// Snapshot returns the policy in force.
func (p *NamePolicy) Snapshot() NameSnapshot { return p.state().snap }

func (p *NamePolicy) state() *nameState {
	st := p.cur.Load()
	p.mu.Lock()
	refresh, ttl := p.refresh, p.ttl
	p.mu.Unlock()
	if refresh != nil && p.now().Sub(st.at) > ttl && p.refreshing.CompareAndSwap(false, true) {
		go func() {
			defer p.refreshing.Store(false)
			refresh()
		}()
	}
	return st
}

// governmentDenied reports whether the built-in rule refuses host for
// tenant (zero: no exception applies).
func (p *NamePolicy) governmentDenied(tenant shared.ID, host string, wildcard bool) bool {
	if governmentRoot(host) == "" {
		return false
	}
	if p == nil {
		return true
	}
	st := p.state()
	if st.snap.GovernmentRuleOff {
		return false
	}
	if tenant.IsZero() {
		return true
	}
	now := p.now()
	for _, e := range st.byTenant[tenant] {
		if now.Before(e.ExpiresAt) && e.covers(host, wildcard) {
			return false
		}
	}
	return true
}

// operatorNames are the operator's console names (nil policy: none).
func (p *NamePolicy) operatorNames() []string {
	if p == nil {
		return nil
	}
	return p.state().snap.Names
}

// platformNames is the platform's one policy, set once at start-up
// (SetPlatformNamePolicy). Guardrails built afterwards read it.
var platformNames atomic.Pointer[NamePolicy]

// SetPlatformNamePolicy sets the policy every guardrails built from now on
// reads (DefaultGuardrails and NewGuardrails). nil restores the built-in
// rule with no exceptions.
func SetPlatformNamePolicy(p *NamePolicy) { platformNames.Store(p) }
