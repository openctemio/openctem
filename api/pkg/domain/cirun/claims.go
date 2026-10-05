package cirun

import (
	"fmt"
	"path"
	"regexp"
	"slices"
	"strings"
)

// Claims are the verified OIDC claims of a CI job, normalized across
// providers. Everything here comes from the signed token; nothing from the
// runner's request.
type Claims struct {
	Provider Provider
	Issuer   string
	Subject  string
	JTI      string
	// Repository is "owner/name" (GitLab: the full project path), lower case.
	Repository   string
	RepositoryID string
	// Ref is the full ref the job runs on ("refs/heads/main",
	// "refs/pull/7/merge", "refs/tags/v1"; GitLab bare names are expanded).
	Ref          string
	RefType      string // branch | tag
	RefProtected bool
	// Branch is the branch the results belong to: the pushed branch, or the
	// source branch of a pull request. Empty for a tag.
	Branch string
	// PullRequest is the pull or merge request number, when the token names
	// one.
	PullRequest string
	SHA         string
	Actor       string
	RunID       string // GitHub run_id, GitLab pipeline_id
	RunAttempt  string
	Workflow    string // GitHub workflow_ref, GitLab ci_config_ref_uri
	// WorkflowName is the workflow's display name (GitHub workflow; GitLab
	// has none). A label, never part of an identity.
	WorkflowName string
	// JobWorkflowRef is the reusable workflow the job runs (GitHub
	// job_workflow_ref, "org/security/.github/workflows/scan.yml@v2"), and
	// JobWorkflowSHA its commit (GitHub job_workflow_sha; GitLab
	// ci_config_sha). The pipeline's template, for drift.
	JobWorkflowRef string
	JobWorkflowSHA string
	Event          string // GitHub event_name, GitLab pipeline_source
	Environment    string
	// Audience is the audience the token was verified for.
	Audience string
}

// Owner is the first path segment of the repository: the GitHub
// organization or user, or the GitLab top-level group.
func (c Claims) Owner() string {
	owner, _, _ := strings.Cut(c.Repository, "/")
	return owner
}

// RefName is the short name of the ref: the branch for a branch or a pull
// request, the tag for a tag.
func (c Claims) RefName() string {
	switch {
	case c.Branch != "":
		return c.Branch
	case strings.HasPrefix(c.Ref, "refs/tags/"):
		return strings.TrimPrefix(c.Ref, "refs/tags/")
	case strings.HasPrefix(c.Ref, "refs/heads/"):
		return strings.TrimPrefix(c.Ref, "refs/heads/")
	}
	return c.Ref
}

// forkEvents run code from a fork with the base repository's identity.
var forkEvents = map[string]bool{
	"pull_request_target":         true, // GitHub
	"workflow_run":                true, // GitHub: triggered by another (possibly fork) workflow
	"external_pull_request_event": true, // GitLab: a pull request on an external repository
}

// IsForkEvent reports whether the job's trigger can run code from a fork.
func (c Claims) IsForkEvent() bool { return forkEvents[c.Event] }

// Refusal is why a trust configuration did not admit a job. Code is stable
// (audit metadata, tests); the caller never sees it.
type Refusal struct {
	Code   string
	Detail string
}

func (r *Refusal) Error() string { return r.Code + ": " + r.Detail }

// Refusal codes.
const (
	RefuseMissingClaims   = "missing_claims"
	RefuseOwner           = "owner_not_allowed"
	RefuseRepository      = "repository_not_allowed"
	RefuseRef             = "ref_not_allowed"
	RefuseEnvironment     = "environment_not_allowed"
	RefuseEvent           = "event_not_allowed"
	RefuseForkPullRequest = "fork_pull_request"
	RefuseRefNotProtected = "ref_not_protected"
)

func refuse(code, format string, a ...any) *Refusal {
	return &Refusal{Code: code, Detail: fmt.Sprintf(format, a...)}
}

// Admit checks the claims against the rules. A nil result admits the job.
func (r Rules) Admit(c Claims) *Refusal {
	if c.Repository == "" || c.SHA == "" || c.Ref == "" || c.JTI == "" {
		return refuse(RefuseMissingClaims, "the token lacks repository, sha, ref or jti")
	}
	if c.IsForkEvent() && !r.AllowForkPullRequests {
		return refuse(RefuseForkPullRequest, "event %q can run fork code; this configuration does not admit fork pull requests", c.Event)
	}
	if len(r.Owners) > 0 && !slices.Contains(r.Owners, c.Owner()) {
		return refuse(RefuseOwner, "owner %q is not listed", c.Owner())
	}
	if len(r.Repositories) > 0 && !slices.ContainsFunc(r.Repositories, func(p string) bool { return repoMatch(p, c.Repository) }) {
		return refuse(RefuseRepository, "repository %q is not listed", c.Repository)
	}
	if len(r.Refs) > 0 && !slices.ContainsFunc(r.Refs, func(p string) bool { return refMatch(p, c.Ref) || refMatch(p, c.RefName()) }) {
		return refuse(RefuseRef, "ref %q is not listed", c.Ref)
	}
	if len(r.Environments) > 0 && !slices.Contains(r.Environments, c.Environment) {
		return refuse(RefuseEnvironment, "environment %q is not listed", c.Environment)
	}
	if len(r.Events) > 0 && !slices.Contains(r.Events, c.Event) {
		return refuse(RefuseEvent, "event %q is not listed", c.Event)
	}
	if r.RequireProtectedRef && !r.protectedRef(c) {
		return refuse(RefuseRefNotProtected, "ref %q is not protected", c.Ref)
	}
	return nil
}

// protectedRef reports whether the job runs on a protected ref. GitLab says
// so in the token (ref_protected). A GitHub token carries no such claim: the
// proof is a deployment environment the configuration lists, whose
// deployment branch rules admit only protected branches and tags (Validate
// requires the list when the switch is on).
func (r Rules) protectedRef(c Claims) bool {
	if c.Provider == ProviderGitHub {
		return c.Environment != "" && slices.Contains(r.Environments, c.Environment)
	}
	return c.RefProtected
}

// repoMatch matches "owner/name", "owner/*" (one level) and "owner/**"
// (any depth) against a lower-case repository path.
func repoMatch(pattern, repo string) bool {
	if prefix, ok := strings.CutSuffix(pattern, "/**"); ok {
		return strings.HasPrefix(repo, prefix+"/")
	}
	if strings.Count(pattern, "/") != strings.Count(repo, "/") {
		return false
	}
	ok, err := path.Match(pattern, repo)
	return err == nil && ok
}

// refMatch matches a ref or ref name against a shell pattern; "**" matches
// anything and a trailing "/**" anything below a prefix.
func refMatch(pattern, ref string) bool {
	if pattern == "**" {
		return true
	}
	if prefix, ok := strings.CutSuffix(pattern, "/**"); ok {
		return strings.HasPrefix(ref, prefix+"/")
	}
	ok, err := path.Match(pattern, ref)
	return err == nil && ok
}

var pullRefRE = regexp.MustCompile(`^refs/pull/([0-9]{1,10})/(merge|head)$`)
var mergeRequestRefRE = regexp.MustCompile(`^refs/merge-requests/([0-9]{1,10})/(head|merge|train)$`)

// ParseGitHubClaims normalizes the claims of a GitHub Actions token.
func ParseGitHubClaims(m map[string]any) Claims {
	c := Claims{
		Provider:       ProviderGitHub,
		Issuer:         str(m, "iss"),
		Subject:        str(m, "sub"),
		JTI:            str(m, "jti"),
		Repository:     strings.ToLower(str(m, "repository")),
		RepositoryID:   str(m, "repository_id"),
		Ref:            str(m, "ref"),
		RefType:        str(m, "ref_type"),
		SHA:            strings.ToLower(str(m, "sha")),
		Actor:          str(m, "actor"),
		RunID:          str(m, "run_id"),
		RunAttempt:     str(m, "run_attempt"),
		Workflow:       str(m, "workflow_ref"),
		Event:          str(m, "event_name"),
		Environment:    str(m, "environment"),
		WorkflowName:   str(m, "workflow"),
		JobWorkflowRef: str(m, "job_workflow_ref"),
		JobWorkflowSHA: strings.ToLower(str(m, "job_workflow_sha")),
	}
	switch {
	case pullRefRE.MatchString(c.Ref):
		c.PullRequest = pullRefRE.FindStringSubmatch(c.Ref)[1]
		c.Branch = str(m, "head_ref")
	case strings.HasPrefix(c.Ref, "refs/heads/"):
		c.Branch = strings.TrimPrefix(c.Ref, "refs/heads/")
	}
	return c
}

// ParseGitLabClaims normalizes the claims of a GitLab CI ID token. GitLab
// sends bare ref names; they are expanded to full refs.
func ParseGitLabClaims(m map[string]any) Claims {
	c := Claims{
		Provider:       ProviderGitLab,
		Issuer:         str(m, "iss"),
		Subject:        str(m, "sub"),
		JTI:            str(m, "jti"),
		Repository:     strings.ToLower(str(m, "project_path")),
		RepositoryID:   str(m, "project_id"),
		RefType:        str(m, "ref_type"),
		RefProtected:   str(m, "ref_protected") == "true",
		SHA:            strings.ToLower(str(m, "sha")),
		Actor:          str(m, "user_login"),
		RunID:          str(m, "pipeline_id"),
		Workflow:       str(m, "ci_config_ref_uri"),
		Event:          str(m, "pipeline_source"),
		Environment:    str(m, "environment"),
		JobWorkflowSHA: strings.ToLower(str(m, "ci_config_sha")),
		// user_email is never read: a person's address is not needed to
		// identify a pipeline or a run (the login is).
	}
	ref := str(m, "ref")
	switch {
	case mergeRequestRefRE.MatchString(ref):
		// A detached merge request pipeline: the token names the merge
		// request, not its source branch. Its results belong to the merge
		// request, never to a real branch.
		c.Ref = ref
		c.PullRequest = mergeRequestRefRE.FindStringSubmatch(ref)[1]
		c.Branch = "merge-requests/" + c.PullRequest
	case strings.HasPrefix(ref, "refs/"):
		c.Ref = ref
		if b, ok := strings.CutPrefix(ref, "refs/heads/"); ok {
			c.Branch = b
		}
	case c.RefType == "tag":
		c.Ref = "refs/tags/" + ref
	case ref != "":
		c.Ref = "refs/heads/" + ref
		c.Branch = ref
	}
	return c
}

// str reads a claim as a string; numbers and booleans are formatted.
func str(m map[string]any, k string) string {
	switch v := m[k].(type) {
	case string:
		return strings.TrimSpace(v)
	case float64:
		return fmt.Sprintf("%.0f", v)
	case bool:
		if v {
			return "true"
		}
		return "false"
	case fmt.Stringer:
		return v.String()
	}
	return ""
}

// CanonicalRepository is the repository asset name for a job: the code
// host and the repository path, lower case ("github.com/acme/api",
// "gitlab.example.com/group/project").
func CanonicalRepository(provider Provider, issuer, repository string) string {
	host := "github.com"
	if provider == ProviderGitLab {
		host = IssuerHost(issuer)
	}
	return strings.ToLower(host + "/" + strings.Trim(repository, "/"))
}

// PipelineURL is the web address of the job's pipeline, built from the
// verified claims only.
func PipelineURL(provider Provider, issuer string, c Claims) string {
	if c.RunID == "" || c.Repository == "" {
		return ""
	}
	switch provider {
	case ProviderGitHub:
		return "https://github.com/" + c.Repository + "/actions/runs/" + c.RunID
	case ProviderGitLab:
		return strings.TrimRight(issuer, "/") + "/" + c.Repository + "/-/pipelines/" + c.RunID
	}
	return ""
}
