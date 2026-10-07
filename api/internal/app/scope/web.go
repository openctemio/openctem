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

	"github.com/openctemio/ctis/weburl"

	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
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
// RFC-055 §6.1): the paths it must never request and, when a rule blocks
// only some methods there, the methods the whole job may use.
type WebScope struct {
	DenyPaths []string `json:"deny_paths,omitempty"`
	Methods   []string `json:"methods,omitempty"`
}

// readMethods are what a job keeps when a rule blocks other methods only.
var readMethods = []string{"GET", "HEAD"}

// BuildWebScope returns the web scope for a web job on targets, from the
// path exclusions in effect whose host pattern covers a target host:
//
//   - a rule that blocks GET or HEAD denies its path prefix;
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
			if !slices.Contains(ws.DenyPaths, web.PathPrefix) {
				ws.DenyPaths = append(ws.DenyPaths, web.PathPrefix)
			}
			continue
		}
		ws.Methods = slices.Clone(readMethods)
	}
	if len(ws.DenyPaths) == 0 && len(ws.Methods) == 0 {
		return nil, nil
	}
	slices.Sort(ws.DenyPaths)
	return ws, nil
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
