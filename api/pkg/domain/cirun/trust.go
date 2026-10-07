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
func (p Provider) IsValid() bool { return slices.Contains(AllProviders(), p) }

// Rules decide which pipelines a trust configuration admits. A pipeline is
// admitted when every non-empty rule matches. Owners or Repositories must
// name something: there is no "any repository" configuration.
type Rules struct {
	// Owners are the first segment of the repository path: GitHub
	// organizations or users, GitLab top-level groups, the Bitbucket
	// workspace, the Azure Repos organization or the code host owner of a
	// repository built elsewhere. Exact match, case-insensitive.
	Owners []string `json:"owners,omitempty"`
	// Repositories are "owner/name" (GitLab: the full project path). A
	// trailing "/*" admits every repository directly under that path and
	// "/**" every repository below it. Bitbucket: repository UUIDs (the
	// token signs the id, never the name).
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
	// RequireProtectedRef admits only pipelines on a protected branch or tag.
	// GitLab: the token's ref_protected claim. GitHub tokens carry no such
	// claim: the job must run in one of Environments (required with this
	// switch), whose deployment branch rules admit only protected refs.
	RequireProtectedRef bool `json:"require_protected_ref,omitempty"`
	// WorkspaceUUID is the Bitbucket workspace's immutable id (required for
	// Bitbucket): the issuer names the workspace by its slug, which a
	// renamed workspace gives up to whoever takes it next.
	WorkspaceUUID string `json:"workspace_uuid,omitempty"`
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
	if c.Provider == ProviderBitbucket || c.Provider == ProviderAzureDevOps || c.Provider == ProviderCircleCI {
		// Their issuers are lower case; a pasted organization id or
		// workspace may not be.
		c.Issuer = strings.ToLower(c.Issuer)
	}
	if repositoriesByID(c.Provider) {
		for i, r := range c.Rules.Repositories {
			c.Rules.Repositories[i] = NormalizeUUID(r)
		}
	}
	if c.Provider == ProviderBitbucket {
		for i, e := range c.Rules.Environments {
			c.Rules.Environments[i] = NormalizeUUID(e)
		}
	}
	c.Rules.WorkspaceUUID = NormalizeUUID(c.Rules.WorkspaceUUID)
	if c.Issuer == "" {
		switch c.Provider {
		case ProviderGitHub:
			c.Issuer = GitHubIssuer
		case ProviderGitLab:
			c.Issuer = GitLabDefaultIssuer
		}
	}
	if c.Audience == "" {
		switch {
		case c.Provider == ProviderAzureDevOps:
			c.Audience = AzureDevOpsAudience
		case !c.TenantID.IsZero():
			c.Audience = DefaultAudience(c.TenantID)
		}
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
		return invalid("provider must be one of github, gitlab, azure_devops, bitbucket, circleci or jenkins")
	}
	if err := validateProviderIssuer(c.Provider, c.Issuer); err != nil {
		return invalid("issuer %v", err)
	}
	if c.Audience == "" || len(c.Audience) > maxAudienceLen || strings.ContainsAny(c.Audience, " \t\r\n") {
		return invalid("audience is required, without spaces (at most %d characters)", maxAudienceLen)
	}
	if err := c.validateProviderRules(); err != nil {
		return invalid("%v", err)
	}
	if len(c.DefaultBranch) > maxBranchNameLen || strings.ContainsAny(c.DefaultBranch, " \t\r\n*?[") {
		return invalid("default_branch must be a branch name")
	}
	return c.Rules.validate()
}

// validateProviderRules refuses what the provider's token cannot back: an
// audience shared with other services, a rule on a claim the token never
// carries (it would refuse every job), a protected-ref switch the token
// cannot prove.
func (c *TrustConfig) validateProviderRules() error {
	p := c.Provider
	switch {
	case p == ProviderAzureDevOps && c.Audience != AzureDevOpsAudience:
		return fmt.Errorf("an Azure Pipelines token always carries the audience %s", AzureDevOpsAudience)
	case TenantBoundAudience(p) && (c.TenantID.IsZero() || !strings.Contains(c.Audience, c.TenantID.String())):
		return fmt.Errorf("the audience must contain the organization id (default %s), so that a token "+
			"minted for this organization is refused by any other", DefaultAudience(c.TenantID))
	case p == ProviderBitbucket && !uuidRE.MatchString(c.Rules.WorkspaceUUID):
		return fmt.Errorf("workspace_uuid is required for Bitbucket: the workspace's UUID")
	case p != ProviderBitbucket && c.Rules.WorkspaceUUID != "":
		return fmt.Errorf("workspace_uuid applies to Bitbucket only")
	case len(c.Rules.Events) > 0 && !hasEventClaim(p):
		return fmt.Errorf("events: this provider's token does not name the trigger event")
	case len(c.Rules.Environments) > 0 && !hasEnvironmentClaim(p):
		return fmt.Errorf("environments: this provider's token does not name a deployment environment")
	}
	if repositoriesByID(p) {
		for _, r := range c.Rules.Repositories {
			if !uuidRE.MatchString(r) {
				return fmt.Errorf("repositories: %q must be a repository UUID (the token signs the id, never the name)", r)
			}
		}
		for _, e := range c.Rules.Environments {
			if !uuidRE.MatchString(e) {
				return fmt.Errorf("environments: %q must be a deployment environment UUID", e)
			}
		}
	}
	if c.Rules.RequireProtectedRef {
		switch protectedRefFrom(p) {
		case protectedRefNone:
			return fmt.Errorf("require_protected_ref: this provider's token does not say whether a ref is protected; " +
				"list the refs instead")
		case protectedRefEnvironment:
			if len(c.Rules.Environments) == 0 {
				return fmt.Errorf("require_protected_ref needs environments: list the deployment environments " +
					"whose rules admit only protected branches and tags")
			}
		}
	}
	return nil
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
		if uuidRE.MatchString(repo) {
			continue // a repository id (Bitbucket)
		}
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
