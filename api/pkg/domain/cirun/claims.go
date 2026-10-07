package cirun

import (
	"fmt"
	"net/url"
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
	// Repository is "owner/name" (GitLab: the full project path; Azure
	// Repos: "org/project/repo"), lower case, without the code host.
	Repository string
	// RepositoryHost is the code host of Repository when the token names it
	// (Azure Pipelines, CircleCI, Jenkins: from the repository URL;
	// Bitbucket: bitbucket.org). Empty for GitHub (github.com) and GitLab
	// (the issuer's host).
	RepositoryHost string
	// RepositoryID is the provider's immutable repository id (GitHub
	// repository_id, GitLab project_id, Bitbucket repositoryUuid, Azure
	// rpo_id; Jenkins: derived from the repository claim).
	RepositoryID string
	// OrgID is the CI organization the token says it comes from (Azure
	// org_id, CircleCI org-id, Bitbucket workspaceUuid); it must match the
	// organization the trust configuration names.
	OrgID string
	// ProjectID and DefinitionID identify the pipeline where the provider
	// keys it by project and definition (Azure prj_id and def_id, CircleCI
	// project-id and pipeline-definition-id).
	ProjectID    string
	DefinitionID string
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
	// CommitVerified: SHA comes from the signed token. False when the
	// provider signs no commit and SHA is the job's own report (Hints); such
	// a commit never matches a break-glass override.
	CommitVerified bool
	// SSHRerun: a CircleCI job re-run with SSH access, where a person can
	// run anything with the job's identity. Never admitted.
	SSHRerun   bool
	Actor      string
	RunID      string // GitHub run_id, GitLab pipeline_id
	RunAttempt string
	// JobID is the job within the pipeline run: GitHub check_run_id, GitLab
	// job_id. A run token is renewed only for the job it was issued to.
	JobID    string
	Workflow string // GitHub workflow_ref, GitLab ci_config_ref_uri
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

	// Azure organization and project names from the subject, for the run's
	// web address only.
	azureOrg, azureProject string
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

// IsForkEvent reports whether the job's trigger can run code from a fork
// with the repository's identity. GitHub and GitLab name such events. Azure
// Pipelines, CircleCI and Jenkins tokens cannot tell a fork's pull request
// from the repository's own, so every pull request build counts as one.
// Bitbucket runs a fork's pipelines in the fork's own repository, under its
// own repository id.
func (c Claims) IsForkEvent() bool {
	switch c.Provider {
	case ProviderAzureDevOps, ProviderCircleCI, ProviderJenkins:
		return c.PullRequest != ""
	case ProviderBitbucket:
		return false
	}
	return forkEvents[c.Event]
}

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
	// RefuseOrganization: the token's organization claim is not the one the
	// trust configuration names (Azure org_id, CircleCI org-id, Bitbucket
	// workspaceUuid).
	RefuseOrganization = "organization_mismatch"
	// RefuseSSHRerun: a CircleCI job re-run with SSH access.
	RefuseSSHRerun = "ssh_rerun"
)

func refuse(code, format string, a ...any) *Refusal {
	return &Refusal{Code: code, Detail: fmt.Sprintf(format, a...)}
}

// Admit checks the claims against the rules. A nil result admits the job.
func (r Rules) Admit(c Claims) *Refusal {
	if c.Repository == "" || c.SHA == "" || c.Ref == "" || c.JTI == "" {
		return refuse(RefuseMissingClaims, "the token lacks repository, sha, ref or jti")
	}
	if c.SSHRerun {
		return refuse(RefuseSSHRerun, "the job is a re-run with SSH access")
	}
	if r := r.admitOrganization(c); r != nil {
		return r
	}
	if c.IsForkEvent() && !r.AllowForkPullRequests {
		return refuse(RefuseForkPullRequest, "event %q can run fork code; this configuration does not admit fork pull requests", c.Event)
	}
	if len(r.Owners) > 0 && !slices.Contains(r.Owners, c.Owner()) {
		return refuse(RefuseOwner, "owner %q is not listed", c.Owner())
	}
	if len(r.Repositories) > 0 && repositoriesByID(c.Provider) {
		if !slices.Contains(r.Repositories, NormalizeUUID(c.RepositoryID)) {
			return refuse(RefuseRepository, "repository id %q is not listed", c.RepositoryID)
		}
	} else if len(r.Repositories) > 0 && !slices.ContainsFunc(r.Repositories, func(p string) bool { return repoMatch(p, c.Repository) }) {
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
	switch protectedRefFrom(c.Provider) {
	case protectedRefEnvironment:
		return c.Environment != "" && slices.Contains(r.Environments, c.Environment)
	case protectedRefClaim:
		return c.RefProtected
	}
	return false
}

// admitOrganization checks the token's organization claim against the
// organization the configuration trusts. Azure Pipelines signs every
// organization's tokens with one key set, so its org_id must be the one in
// the issuer; CircleCI's org-id likewise (when the token carries it).
// Bitbucket's issuer names a workspace by its slug, which a renamed
// workspace gives up: the immutable workspace UUID is pinned in the rules.
func (r Rules) admitOrganization(c Claims) *Refusal {
	switch c.Provider {
	case ProviderAzureDevOps:
		if want := IssuerOrganization(c.Provider, c.Issuer); want == "" || c.OrgID != want {
			return refuse(RefuseOrganization, "organization %q is not the issuer's", c.OrgID)
		}
	case ProviderCircleCI:
		if want := IssuerOrganization(c.Provider, c.Issuer); want == "" || (c.OrgID != "" && c.OrgID != want) {
			return refuse(RefuseOrganization, "organization %q is not the issuer's", c.OrgID)
		}
	case ProviderBitbucket:
		if r.WorkspaceUUID == "" || c.OrgID != r.WorkspaceUUID {
			return refuse(RefuseOrganization, "workspace %q is not the configured workspace", c.OrgID)
		}
	}
	return nil
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
		JobID:          str(m, "check_run_id"),
		Workflow:       str(m, "workflow_ref"),
		Event:          str(m, "event_name"),
		Environment:    str(m, "environment"),
		WorkflowName:   str(m, "workflow"),
		JobWorkflowRef: str(m, "job_workflow_ref"),
		JobWorkflowSHA: strings.ToLower(str(m, "job_workflow_sha")),
	}
	c.CommitVerified = c.SHA != ""
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
		JobID:          str(m, "job_id"),
		Workflow:       str(m, "ci_config_ref_uri"),
		Event:          str(m, "pipeline_source"),
		Environment:    str(m, "environment"),
		JobWorkflowSHA: strings.ToLower(str(m, "ci_config_sha")),
		// user_email is never read: a person's address is not needed to
		// identify a pipeline or a run (the login is).
	}
	c.CommitVerified = c.SHA != ""
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

// CanonicalRepository is the repository asset name for the job: its code
// host (from the token when it names one) and the repository path.
func (c Claims) CanonicalRepository() string {
	if c.RepositoryHost != "" {
		return strings.ToLower(c.RepositoryHost + "/" + strings.Trim(c.Repository, "/"))
	}
	return CanonicalRepository(c.Provider, c.Issuer, c.Repository)
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
	case ProviderAzureDevOps:
		if c.azureOrg == "" || !isDigits(c.RunID) {
			return ""
		}
		return "https://dev.azure.com/" + url.PathEscape(c.azureOrg) + "/" + url.PathEscape(c.azureProject) +
			"/_build/results?buildId=" + c.RunID
	case ProviderCircleCI:
		if !uuidRE.MatchString(c.RunID) {
			return ""
		}
		return "https://app.circleci.com/pipelines/workflows/" + c.RunID
	case ProviderBitbucket:
		if !uuidRE.MatchString(c.RunID) {
			return ""
		}
		return "https://bitbucket.org/" + c.Repository + "/pipelines/results/%7B" + c.RunID + "%7D"
	case ProviderJenkins:
		u, err := url.Parse(c.Subject)
		if err != nil || u.Scheme != schemeHTTPS || u.Host == "" || u.RawQuery != "" || u.Fragment != "" || !isDigits(c.RunID) {
			return ""
		}
		return strings.TrimRight(u.String(), "/") + "/" + c.RunID + "/"
	}
	return ""
}
