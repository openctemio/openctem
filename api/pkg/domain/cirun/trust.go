// Package cirun is the domain of CI runs: pipelines that prove who they are
// with their CI provider's OIDC token, upload results for one repository and
// ask the platform for a pass/fail verdict.
//
// Design: docs/rfcs/RFC-051-ci-runner-identity-and-gate.md.
package cirun

import (
	"fmt"
	"net/url"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Provider is the CI system that issued the OIDC token.
type Provider string

const (
	ProviderGitHub Provider = "github"
	ProviderGitLab Provider = "gitlab"
)

// GitHubIssuer is the only issuer accepted for GitHub Actions.
const GitHubIssuer = "https://token.actions.githubusercontent.com"

// GitLabDefaultIssuer is the issuer of gitlab.com; a self-managed GitLab
// instance is its own issuer (its external URL).
const GitLabDefaultIssuer = "https://gitlab.com"

// Limits on a trust configuration.
const (
	maxNameLen       = 200
	maxAudienceLen   = 500
	maxRuleEntries   = 100
	maxRuleEntryLen  = 255
	maxBranchNameLen = 255
)

// IsValid reports whether p is a supported provider.
func (p Provider) IsValid() bool { return p == ProviderGitHub || p == ProviderGitLab }

// Rules decide which pipelines a trust configuration admits. A pipeline is
// admitted when every non-empty rule matches. Owners or Repositories must
// name something: there is no "any repository" configuration.
type Rules struct {
	// Owners are GitHub organizations or users (repository_owner) or GitLab
	// top-level groups (the first segment of project_path). Exact match,
	// case-insensitive.
	Owners []string `json:"owners,omitempty"`
	// Repositories are "owner/name" (GitLab: the full project path). A
	// trailing "/*" admits every repository directly under that path and
	// "/**" every repository below it.
	Repositories []string `json:"repositories,omitempty"`
	// Refs are the branches or tags a pipeline may run on: "main",
	// "release/*", or a full ref ("refs/tags/v*"). Shell-style patterns per
	// path segment. Empty admits every ref. For a pull request the branch is
	// the pull request's source branch.
	Refs []string `json:"refs,omitempty"`
	// Environments, when set, require the job to run in one of these
	// deployment environments (the token's environment claim).
	Environments []string `json:"environments,omitempty"`
	// Events, when set, are the only trigger events admitted (GitHub
	// event_name, GitLab pipeline_source).
	Events []string `json:"events,omitempty"`
	// AllowForkPullRequests admits events that run code from a fork with the
	// base repository's identity (pull_request_target, workflow_run,
	// external_pull_request_event). Off by default.
	AllowForkPullRequests bool `json:"allow_fork_pull_requests,omitempty"`
	// RequireProtectedRef admits only pipelines on a protected branch or tag
	// (GitLab ref_protected; GitHub tokens carry no such claim, so a GitHub
	// configuration with this set admits nothing).
	RequireProtectedRef bool `json:"require_protected_ref,omitempty"`
}

// TrustConfig is one tenant's trust in one CI issuer.
type TrustConfig struct {
	ID       shared.ID
	TenantID shared.ID
	Name     string
	Provider Provider
	Issuer   string
	Audience string
	Rules    Rules
	// DefaultBranch is the repositories' default branch when the platform
	// does not know it yet: the baseline the gate compares pull requests
	// with. A pipeline cannot set it.
	DefaultBranch string
	Enabled       bool
	CreatedBy     *shared.ID
	LastUsedAt    *time.Time
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// DefaultAudience is the audience a new trust configuration expects when the
// administrator does not choose one. It names the tenant, so a token minted
// for one organization is useless to another.
func DefaultAudience(tenantID shared.ID) string {
	return "openctem:tenant:" + tenantID.String()
}

// Normalize trims and canonicalizes the configuration in place.
func (c *TrustConfig) Normalize() {
	c.Name = strings.TrimSpace(c.Name)
	c.Issuer = strings.TrimRight(strings.TrimSpace(c.Issuer), "/")
	c.Audience = strings.TrimSpace(c.Audience)
	c.DefaultBranch = strings.TrimSpace(c.DefaultBranch)
	if c.DefaultBranch == "" {
		c.DefaultBranch = "main"
	}
	c.Rules = c.Rules.normalized()
	if c.Issuer == "" {
		switch c.Provider {
		case ProviderGitHub:
			c.Issuer = GitHubIssuer
		case ProviderGitLab:
			c.Issuer = GitLabDefaultIssuer
		}
	}
	if c.Audience == "" && !c.TenantID.IsZero() {
		c.Audience = DefaultAudience(c.TenantID)
	}
}

func (r Rules) normalized() Rules {
	clean := func(in []string, lower bool) []string {
		out := make([]string, 0, len(in))
		for _, v := range in {
			v = strings.Trim(strings.TrimSpace(v), "/")
			if lower {
				v = strings.ToLower(v)
			}
			if v != "" && !slices.Contains(out, v) {
				out = append(out, v)
			}
		}
		return out
	}
	r.Owners = clean(r.Owners, true)
	r.Repositories = clean(r.Repositories, true)
	r.Refs = clean(r.Refs, false)
	r.Environments = clean(r.Environments, false)
	r.Events = clean(r.Events, true)
	return r
}

// Validate checks a normalized configuration. Every error wraps
// shared.ErrValidation.
func (c *TrustConfig) Validate() error {
	invalid := func(format string, a ...any) error {
		return fmt.Errorf("%w: %s", shared.ErrValidation, fmt.Sprintf(format, a...))
	}
	if c.Name == "" || len(c.Name) > maxNameLen {
		return invalid("name is required (at most %d characters)", maxNameLen)
	}
	if !c.Provider.IsValid() {
		return invalid("provider must be github or gitlab")
	}
	switch c.Provider {
	case ProviderGitHub:
		if c.Issuer != GitHubIssuer {
			return invalid("the GitHub Actions issuer is %s", GitHubIssuer)
		}
	case ProviderGitLab:
		if err := validateIssuerURL(c.Issuer); err != nil {
			return invalid("issuer %v", err)
		}
	}
	if c.Audience == "" || len(c.Audience) > maxAudienceLen || strings.ContainsAny(c.Audience, " \t\r\n") {
		return invalid("audience is required, without spaces (at most %d characters)", maxAudienceLen)
	}
	if len(c.DefaultBranch) > maxBranchNameLen || strings.ContainsAny(c.DefaultBranch, " \t\r\n*?[") {
		return invalid("default_branch must be a branch name")
	}
	return c.Rules.validate()
}

func (r Rules) validate() error {
	invalid := func(format string, a ...any) error {
		return fmt.Errorf("%w: %s", shared.ErrValidation, fmt.Sprintf(format, a...))
	}
	if len(r.Owners) == 0 && len(r.Repositories) == 0 {
		return invalid("rules must name at least one owner or repository")
	}
	for name, list := range map[string][]string{
		"owners": r.Owners, "repositories": r.Repositories, "refs": r.Refs,
		"environments": r.Environments, "events": r.Events,
	} {
		if len(list) > maxRuleEntries {
			return invalid("%s: at most %d entries", name, maxRuleEntries)
		}
		for _, v := range list {
			if len(v) > maxRuleEntryLen || strings.ContainsAny(v, " \t\r\n") {
				return invalid("%s: %q is not a valid entry", name, v)
			}
		}
	}
	for _, o := range r.Owners {
		if strings.ContainsAny(o, "/*?[") {
			return invalid("owners: %q must be one organization or group name, without wildcards", o)
		}
	}
	for _, repo := range r.Repositories {
		segs := strings.Split(repo, "/")
		if len(segs) < 2 {
			return invalid("repositories: %q must be owner/name", repo)
		}
		// A wildcard may not stand for the owner: the owner is what ties
		// the rule to an organization the tenant controls.
		if strings.ContainsAny(segs[0], "*?[") {
			return invalid("repositories: %q may not use a wildcard for the owner", repo)
		}
		for _, s := range segs {
			if s == "" {
				return invalid("repositories: %q has an empty segment", repo)
			}
			if _, err := path.Match(s, ""); err != nil {
				return invalid("repositories: %q is not a valid pattern", repo)
			}
		}
	}
	for _, ref := range r.Refs {
		if _, err := path.Match(ref, ""); err != nil {
			return invalid("refs: %q is not a valid pattern", ref)
		}
	}
	return nil
}

// validateIssuerURL accepts https://host[:port][/path] without credentials,
// query or fragment.
func validateIssuerURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("must be an https URL without credentials, query or fragment")
	}
	return nil
}

// IssuerHost is the host part of the configuration's issuer, used to name
// GitLab repositories ("gitlab.example.com/group/project").
func IssuerHost(issuer string) string {
	u, err := url.Parse(issuer)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Host)
}
