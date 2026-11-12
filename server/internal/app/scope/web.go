package scope

// Path- and method-aware exclusions (docs/rfcs/RFC-056-web-attack-surface.md
// §5): building a `path` exclusion's web rule, its testing mode, the job web
// scope a web tool receives, and the endpoint check ingest runs.

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/openctemio/ctis/v2/weburl"

	scopedom "github.com/openctemio/openctem/server/pkg/domain/scope"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// webRuleFor validates the web part of a new exclusion: a `path` exclusion
// needs a host pattern and a path prefix; any other type takes neither.
func webRuleFor(t scopedom.ExclusionType, pattern string, pathPrefix *string, methods []string) (*scopedom.WebRule, error) {
	if t != scopedom.ExclusionTypePath {
		if pathPrefix != nil || len(methods) > 0 {
			return nil, fmt.Errorf("%w: path_prefix and methods apply only to path exclusions", shared.ErrValidation)
		}
		return nil, nil
	}
	if err := scopedom.ValidateHostPattern(pattern); err != nil {
		return nil, err
	}
	if pathPrefix == nil {
		return nil, fmt.Errorf("%w: a path exclusion needs path_prefix", shared.ErrValidation)
	}
	prefix, err := scopedom.NormalizePathPrefix(*pathPrefix)
	if err != nil {
		return nil, err
	}
	ms, err := scopedom.NormalizeMethods(methods)
	if err != nil {
		return nil, err
	}
	return &scopedom.WebRule{PathPrefix: prefix, Methods: ms, Testing: scopedom.TestingBlocked}, nil
}

func (s *Service) notifyTestingChange(ctx context.Context, tenantID shared.ID, e *scopedom.Exclusion) {
	if e == nil || e.Web() == nil {
		return
	}
	web := e.Web()
	body := fmt.Sprintf("Testing of the excluded path %s on %s is now %s", web.PathPrefix, e.HostPattern(), web.Testing)
	if web.TestingUntil != nil {
		body += " until " + web.TestingUntil.UTC().Format(time.RFC3339)
	}
	s.NotifyAdmins(ctx, tenantID, "Scope exclusion testing changed", body)
}

// ExclusionTestingRepository records a path exclusion's testing mode
// (*postgres.ScopeExclusionRepository).
type ExclusionTestingRepository interface {
	SetTesting(ctx context.Context, tenantID, id shared.ID, rule *scopedom.WebRule) error
}

// SetTestingInput is a scope approver's change of a path exclusion's
// testing mode.
type SetTestingInput struct {
	TenantID     string
	ExclusionID  string
	Testing      string
	TestingUntil *time.Time
	ChangedBy    string
}

// ChangeExclusionTesting sets how a path exclusion may be tested: blocked,
// read_only (GET and HEAD) or allowed, optionally until a deadline (at most
// MaxTestingWindow ahead), after which it is blocked again. The route gates
// it with the exclusion approval permission and step-up; the handler audits
// it and the caller notifies the administrators. It never widens scope:
// a target must still pass the one authority check.
func (s *Service) ChangeExclusionTesting(ctx context.Context, in SetTestingInput) (before, after *scopedom.Exclusion, err error) {
	repo, ok := s.exclusionRepo.(ExclusionTestingRepository)
	if !ok {
		return nil, nil, fmt.Errorf("exclusion testing is not configured")
	}
	tenantID, err := shared.IDFromString(in.TenantID)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	id, err := shared.IDFromString(in.ExclusionID)
	if err != nil {
		return nil, nil, scopedom.ErrExclusionNotFound
	}
	mode := scopedom.Testing(strings.TrimSpace(in.Testing))
	if !mode.Valid() {
		return nil, nil, fmt.Errorf("%w: testing must be blocked, read_only or allowed", shared.ErrValidation)
	}
	now := time.Now()
	until := in.TestingUntil
	switch {
	case mode == scopedom.TestingBlocked:
		until = nil
	case until != nil && !until.After(now):
		return nil, nil, fmt.Errorf("%w: testing_until must be in the future", shared.ErrValidation)
	case until != nil && until.Sub(now) > scopedom.MaxTestingWindow:
		return nil, nil, fmt.Errorf("%w: testing_until is at most %d days ahead", shared.ErrValidation, int(scopedom.MaxTestingWindow.Hours()/24))
	}
	before, err = s.exclusionRepo.GetByID(ctx, tenantID, id)
	if err != nil {
		return nil, nil, err
	}
	if before.ExclusionType() != scopedom.ExclusionTypePath || before.Web() == nil {
		return nil, nil, fmt.Errorf("%w: only a path exclusion has a testing mode", shared.ErrValidation)
	}
	rule := *before.Web()
	rule.Testing, rule.TestingUntil, rule.TestingChangedBy, rule.TestingChangedAt = mode, until, in.ChangedBy, &now
	if err := repo.SetTesting(ctx, tenantID, id, &rule); err != nil {
		return nil, nil, err
	}
	after, err = s.exclusionRepo.GetByID(ctx, tenantID, id)
	if err != nil {
		return nil, nil, err
	}
	s.notifyTestingChange(ctx, tenantID, after)
	return before, after, nil
}

// WebScope is the web scope a web tool's job carries (sdk-go webscope.Scope,
// RFC-055 §6.1): the paths it must never request and the methods the whole
// job may use (GET and HEAD when a rule blocks only some methods, every
// method otherwise; never empty, see allMethods).
type WebScope struct {
	DenyPaths []string `json:"deny_paths,omitempty"`
	// DenyPathsWildcard is the deny list with "*" segments kept as written
	// (nil when it equals DenyPaths). It is the platform's own: it never
	// leaves with the job. At claim, a sensor that reads "*" segments
	// (sensordom.ReadsWildcardDenyPaths) gets it as its deny_paths; any other
	// gets DenyPaths, where a "*" rule is cut to the path before it.
	DenyPathsWildcard []string `json:"deny_paths_wildcard,omitempty"`
	Methods           []string `json:"methods,omitempty"`
	// MaxRequestsPerHost caps the requests the job sends to one host; the
	// sensor's forwarder counts and refuses past it (0: no cap). Set only
	// on a path discovery job.
	MaxRequestsPerHost int `json:"max_requests_per_host,omitempty"`
}

// Bounds of a path discovery job's per-host request cap (the contract's
// max_requests_per_origin).
const (
	MinDiscoveryRequestsPerHost = 50
	MaxDiscoveryRequestsPerHost = 100000
)

// BuildDiscoveryWebScope returns the strict web scope of a path discovery
// job (enumerate.web_paths) on targets: GET and HEAD only, every path
// exclusion on a target host denied unless its testing mode is allowed (a
// read_only exclusion is denied too: an approver who allowed reads did not
// allow volume), and the per-host request cap. It is never nil: a discovery
// job always carries its limits, even with no exclusion. A failed lookup is
// an error (the caller does not dispatch).
func (s *Service) BuildDiscoveryWebScope(ctx context.Context, tenantID shared.ID, targets []string, maxRequestsPerHost int) (*WebScope, error) {
	ws, err := s.discoveryScope(ctx, tenantID, targets)
	if err != nil {
		return nil, err
	}
	ws.Methods = slices.Clone(readMethods)
	ws.MaxRequestsPerHost = min(max(maxRequestsPerHost, MinDiscoveryRequestsPerHost), MaxDiscoveryRequestsPerHost)
	return ws, nil
}

// DiscoveryDenyPaths are the path prefixes path discovery never requests on
// the targets' hosts: every path exclusion whose host pattern covers a
// target host and whose testing mode is not allowed at this moment. They are
// matched with contract/webpath semantics (decoded, dot segments resolved,
// case-insensitive prefix) by the candidate list, the tool and the sensor.
// Each is written as BuildWebScope writes it (scopedom.JobDenyPaths: the
// decoded form too, and cut before a "*" segment, which a sensor before
// webpath 1.3.1 compares literally).
func (s *Service) DiscoveryDenyPaths(ctx context.Context, tenantID shared.ID, targets []string) ([]string, error) {
	ws, err := s.discoveryScope(ctx, tenantID, targets)
	if err != nil {
		return nil, err
	}
	return ws.DenyPaths, nil
}

// discoveryScope is the deny lists of a path discovery job: DenyPaths in the
// job form and DenyPathsWildcard as written, like BuildWebScope. Both are
// non-nil-safe to read; DenyPaths is never nil.
func (s *Service) discoveryScope(ctx context.Context, tenantID shared.ID, targets []string) (*WebScope, error) {
	exclusions, err := s.effectiveExclusions(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list active scope exclusions: %w", err)
	}
	hosts := make([]string, 0, len(targets))
	for _, t := range targets {
		if h := hostOfTarget(t); h != "" {
			hosts = append(hosts, h)
		}
	}
	now := time.Now()
	ws := &WebScope{DenyPaths: []string{}}
	for _, e := range exclusions {
		web := e.Web()
		if e.ExclusionType() != scopedom.ExclusionTypePath || web == nil || web.EffectiveTesting(now) == scopedom.TestingAllowed {
			continue
		}
		if !slices.ContainsFunc(hosts, func(h string) bool { return scopedom.HostPatternMatches(e.HostPattern(), h) }) {
			continue
		}
		ws.addDeny(web.PathPrefix)
	}
	ws.finishDeny()
	return ws, nil
}

// readMethods are what a job keeps when a rule blocks other methods only.
var readMethods = []string{"GET", "HEAD"}

// allMethods are every method a web scope may allow (sdk-go webscope). A
// scope that only denies paths names them all: the SDK reads an empty
// method list as GET, HEAD and OPTIONS only, which would refuse every other
// method on every path of the job's hosts, not just under the denied paths.
var allMethods = []string{"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"}

// BuildWebScope returns the web scope for a web job on targets, from the
// path exclusions in effect whose host pattern covers a target host:
//
//   - a rule that blocks GET or HEAD denies its path prefix, as stored and
//     decoded, cut before a "*" segment (scopedom.JobDenyPaths);
//   - a rule that blocks only other methods (read_only, or a method-scoped
//     rule such as POST/PUT/DELETE on /admin) limits the whole job to GET
//     and HEAD, so read-only checks still run there;
//   - an allowed rule (in its window) adds nothing.
//
// nil when nothing applies (the job then carries no web scope, so a sensor
// without web-scope support still runs it). A failed lookup is an error: the
// caller does not dispatch (fail closed). Lifting a rule never widens scope:
// the targets passed the one authority check before this.
func (s *Service) BuildWebScope(ctx context.Context, tenantID shared.ID, targets []string) (*WebScope, error) {
	exclusions, err := s.effectiveExclusions(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list active scope exclusions: %w", err)
	}
	hosts := make([]string, 0, len(targets))
	for _, t := range targets {
		if h := hostOfTarget(t); h != "" {
			hosts = append(hosts, h)
		}
	}
	now := time.Now()
	ws := &WebScope{}
	for _, e := range exclusions {
		web := e.Web()
		if e.ExclusionType() != scopedom.ExclusionTypePath || web == nil {
			continue
		}
		blocked := web.BlockedMethods(now)
		if len(blocked) == 0 || !slices.ContainsFunc(hosts, func(h string) bool { return scopedom.HostPatternMatches(e.HostPattern(), h) }) {
			continue
		}
		if slices.ContainsFunc(readMethods, func(m string) bool { return slices.Contains(blocked, m) }) {
			ws.addDeny(web.PathPrefix)
			continue
		}
		ws.Methods = slices.Clone(readMethods)
	}
	if len(ws.DenyPaths) == 0 && len(ws.Methods) == 0 {
		return nil, nil
	}
	if len(ws.Methods) == 0 {
		ws.Methods = slices.Clone(allMethods)
	}
	ws.finishDeny()
	return ws, nil
}

// addDeny adds the deny paths of a path prefix: the job form (cut before a
// "*" segment) to DenyPaths and the form as written to DenyPathsWildcard.
func (w *WebScope) addDeny(prefix string) {
	for _, d := range scopedom.JobDenyPaths(prefix) {
		if !slices.Contains(w.DenyPaths, d) {
			w.DenyPaths = append(w.DenyPaths, d)
		}
	}
	for _, d := range scopedom.PrefixForms(prefix) {
		if !slices.Contains(w.DenyPathsWildcard, d) {
			w.DenyPathsWildcard = append(w.DenyPathsWildcard, d)
		}
	}
}

// finishDeny sorts the deny lists and drops the wildcard one when it is the
// same list.
func (w *WebScope) finishDeny() {
	slices.Sort(w.DenyPaths)
	slices.Sort(w.DenyPathsWildcard)
	if slices.Equal(w.DenyPaths, w.DenyPathsWildcard) {
		w.DenyPathsWildcard = nil
	}
}

// hostOfTarget is the host a scan target names: a URL's host, a host:port's
// host, or the target itself.
func hostOfTarget(t string) string {
	forms := exclusionMatchForms(t)
	return strings.ToLower(forms[len(forms)-1])
}

// WebRules are one tenant's path exclusions in effect, loaded once per
// ingest.
type WebRules struct {
	rules []*scopedom.Exclusion
	now   time.Time
}

// LoadWebRules loads the tenant's path exclusions in effect.
func (s *Service) LoadWebRules(ctx context.Context, tenantID shared.ID) (*WebRules, error) {
	exclusions, err := s.effectiveExclusions(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list active scope exclusions: %w", err)
	}
	out := &WebRules{now: time.Now()}
	for _, e := range exclusions {
		if e.ExclusionType() == scopedom.ExclusionTypePath && e.Web() != nil {
			out.rules = append(out.rules, e)
		}
	}
	return out, nil
}

// Blocking returns the first path exclusion that blocks method on origin +
// path, or nil. path is a normalised concrete path (an endpoint's example).
func (w *WebRules) Blocking(origin, method, path string) *scopedom.Exclusion {
	if w == nil || len(w.rules) == 0 {
		return nil
	}
	u, err := weburl.Parse(origin)
	if err != nil {
		return nil
	}
	for _, e := range w.rules {
		if e.BlocksWeb(u.Host, path, method, w.now) {
			return e
		}
	}
	return nil
}
