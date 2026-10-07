package cirun

// CI providers beyond GitHub Actions and GitLab CI: Azure Pipelines,
// Bitbucket Pipelines, CircleCI and Jenkins (OpenID Connect provider plugin).
// Each issues signed OIDC tokens; what a token proves differs per provider,
// and so does what a trust configuration may rely on. This file holds those
// differences: the issuer each provider uses, the audience it may carry, the
// claims it signs and how they map onto the neutral Claims.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

const (
	ProviderAzureDevOps Provider = "azure_devops"
	ProviderBitbucket   Provider = "bitbucket"
	ProviderCircleCI    Provider = "circleci"
	ProviderJenkins     Provider = "jenkins"
)

// AllProviders lists every supported provider.
func AllProviders() []Provider {
	return []Provider{ProviderGitHub, ProviderGitLab, ProviderAzureDevOps, ProviderBitbucket, ProviderCircleCI, ProviderJenkins}
}

// AzureDevOpsAudience is the only audience an Azure Pipelines token carries;
// a pipeline cannot choose another.
const AzureDevOpsAudience = "api://AzureADTokenExchange"

const (
	schemeHTTPS    = "https"
	azureReposHost = "dev.azure.com"
)

// Issuer formats. Each names exactly one organization, workspace or
// controller: there is no issuer that stands for every customer of a
// provider.
var (
	uuidRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	// https://vstoken.dev.azure.com/<organization id>
	azureIssuerRE = regexp.MustCompile(`^https://vstoken\.dev\.azure\.com/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$`)
	// https://oidc.circleci.com/org/<organization id>
	circleIssuerRE = regexp.MustCompile(`^https://oidc\.circleci\.com/org/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$`)
	// https://api.bitbucket.org/2.0/workspaces/<workspace>/pipelines-config/identity/oidc
	bitbucketIssuerRE = regexp.MustCompile(`^https://api\.bitbucket\.org/2\.0/workspaces/([a-z0-9][a-z0-9_.-]{0,99})/pipelines-config/identity/oidc$`)
	// A repository or project name segment a job may report (Bitbucket).
	repoSlugRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,127}$`)
	// A full commit id: SHA-1 or SHA-256.
	fullSHARE = regexp.MustCompile(`^([0-9a-f]{40}|[0-9a-f]{64})$`)
	// Jenkins multibranch names a pull request build "PR-<number>".
	jenkinsPRRE = regexp.MustCompile(`^PR-([0-9]{1,10})$`)
)

// IssuerOrganization is the organization id an issuer names: the Azure
// DevOps organization id or the CircleCI organization id ("" for other
// providers).
func IssuerOrganization(p Provider, issuer string) string {
	var m []string
	switch p {
	case ProviderAzureDevOps:
		m = azureIssuerRE.FindStringSubmatch(issuer)
	case ProviderCircleCI:
		m = circleIssuerRE.FindStringSubmatch(issuer)
	}
	if len(m) == 2 {
		return m[1]
	}
	return ""
}

// BitbucketWorkspace is the workspace slug a Bitbucket issuer names.
func BitbucketWorkspace(issuer string) string {
	if m := bitbucketIssuerRE.FindStringSubmatch(issuer); len(m) == 2 {
		return m[1]
	}
	return ""
}

// AzureDevOpsIssuer, CircleCIIssuer and BitbucketIssuer build an issuer
// from the organization or workspace an administrator names.
func AzureDevOpsIssuer(orgID string) string {
	return "https://vstoken.dev.azure.com/" + strings.ToLower(strings.TrimSpace(orgID))
}

func CircleCIIssuer(orgID string) string {
	return "https://oidc.circleci.com/org/" + strings.ToLower(strings.TrimSpace(orgID))
}

func BitbucketIssuer(workspace string) string {
	return "https://api.bitbucket.org/2.0/workspaces/" + strings.ToLower(strings.TrimSpace(workspace)) +
		"/pipelines-config/identity/oidc"
}

// validateProviderIssuer checks the issuer's shape for the provider.
func validateProviderIssuer(p Provider, issuer string) error {
	switch p {
	case ProviderGitHub:
		if issuer != GitHubIssuer {
			return fmt.Errorf("the GitHub Actions issuer is %s", GitHubIssuer)
		}
	case ProviderGitLab, ProviderJenkins:
		if err := validateIssuerURL(issuer); err != nil {
			return err
		}
		// A self-managed issuer is never one of the hosted providers'
		// issuers: each issuer is read with exactly one provider's claims.
		switch IssuerHost(issuer) {
		case "token.actions.githubusercontent.com", "vstoken.dev.azure.com", "oidc.circleci.com", "api.bitbucket.org":
			return fmt.Errorf("is a hosted provider's issuer; choose that provider")
		}
	case ProviderAzureDevOps:
		if !azureIssuerRE.MatchString(issuer) {
			return fmt.Errorf("must be https://vstoken.dev.azure.com/<organization id> (the organization's id, a UUID)")
		}
	case ProviderCircleCI:
		if !circleIssuerRE.MatchString(issuer) {
			return fmt.Errorf("must be https://oidc.circleci.com/org/<organization id> (the organization's id, a UUID)")
		}
	case ProviderBitbucket:
		if !bitbucketIssuerRE.MatchString(issuer) {
			return fmt.Errorf("must be https://api.bitbucket.org/2.0/workspaces/<workspace>/pipelines-config/identity/oidc")
		}
	}
	return nil
}

// TenantBoundAudience reports whether the provider lets the job choose its
// token's audience, so a trust configuration must expect one that names the
// tenant: a token minted for one organization is then useless to another,
// and to any other service that trusts the same CI organization.
func TenantBoundAudience(p Provider) bool {
	return p == ProviderBitbucket || p == ProviderCircleCI || p == ProviderJenkins
}

// JTIOptional reports whether the provider's tokens may come without a jti
// (CircleCI, Bitbucket and the Jenkins plugin never send one). Their replay
// key is derived from the token itself (pkg/oidc).
func JTIOptional(p Provider) bool {
	return p == ProviderBitbucket || p == ProviderCircleCI || p == ProviderJenkins
}

// protectedRefSource says how a provider's token proves a protected ref.
type protectedRefSource int

const (
	protectedRefNone        protectedRefSource = iota // the token cannot prove it
	protectedRefClaim                                 // a claim says so (GitLab ref_protected)
	protectedRefEnvironment                           // a listed deployment environment restricted to protected refs
)

func protectedRefFrom(p Provider) protectedRefSource {
	switch p {
	case ProviderGitLab:
		return protectedRefClaim
	case ProviderGitHub, ProviderBitbucket:
		return protectedRefEnvironment
	}
	return protectedRefNone
}

// hasEventClaim and hasEnvironmentClaim report whether a provider's token can
// carry the trigger event and the deployment environment; a rule on a claim
// the token never carries is refused when the configuration is saved instead
// of refusing every job later.
func hasEventClaim(p Provider) bool {
	return p == ProviderGitHub || p == ProviderGitLab || p == ProviderJenkins
}

func hasEnvironmentClaim(p Provider) bool {
	return p != ProviderAzureDevOps && p != ProviderCircleCI
}

// repositoriesByID reports whether the provider's repositories rule lists
// repository ids instead of names: a Bitbucket token signs the repository's
// UUID, never its name.
func repositoriesByID(p Provider) bool { return p == ProviderBitbucket }

// NormalizeUUID lower-cases a UUID and drops the braces Bitbucket writes
// around its ids.
func NormalizeUUID(s string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(s), "{"), "}"))
}

// Hints are what a job reports about itself, used only for what its
// provider's token does not sign: the commit (CircleCI, and Bitbucket and
// Jenkins tokens without one) and the repository name (Bitbucket). They
// never replace a signed claim.
type Hints struct {
	CommitSHA  string
	Repository string
}

// ApplyHints fills what the token lacks from the job's hints. A commit taken
// from a hint leaves CommitVerified false; a malformed hint is ignored (the
// claims then lack the value and the job is refused).
func (c *Claims) ApplyHints(h Hints) {
	if c.SHA == "" && (c.Provider == ProviderCircleCI || c.Provider == ProviderBitbucket || c.Provider == ProviderJenkins) {
		if sha := strings.ToLower(strings.TrimSpace(h.CommitSHA)); fullSHARE.MatchString(sha) {
			c.SHA, c.CommitVerified = sha, false
		}
	}
	if c.Provider == ProviderBitbucket && c.Repository == "" {
		// "workspace/name" or "name"; the workspace is always the issuer's.
		ws, name := BitbucketWorkspace(c.Issuer), strings.ToLower(strings.TrimSpace(h.Repository))
		if owner, rest, found := strings.Cut(name, "/"); found {
			name = rest
			if owner != ws {
				name = ""
			}
		}
		if ws != "" && repoSlugRE.MatchString(name) {
			c.Repository = ws + "/" + name
			c.RepositoryHost = "bitbucket.org"
		}
	}
}

// ParseClaims normalizes verified claims for the provider.
func ParseClaims(p Provider, m map[string]any) Claims {
	switch p {
	case ProviderGitHub:
		return ParseGitHubClaims(m)
	case ProviderGitLab:
		return ParseGitLabClaims(m)
	case ProviderAzureDevOps:
		return ParseAzureDevOpsClaims(m)
	case ProviderBitbucket:
		return ParseBitbucketClaims(m)
	case ProviderCircleCI:
		return ParseCircleCIClaims(m)
	case ProviderJenkins:
		return ParseJenkinsClaims(m)
	}
	return Claims{Provider: p}
}

// ParseAzureDevOpsClaims normalizes an Azure Pipelines pipeline token (one
// requested without a service connection, subject "p://org/project/pipeline").
// The repository comes from rpo_uri, the commit from rpo_ver and the ref from
// rpo_ref; the pipeline is the definition (def_id) in its project (prj_id).
// The token names no event, environment, actor or job.
func ParseAzureDevOpsClaims(m map[string]any) Claims {
	c := Claims{
		Provider:     ProviderAzureDevOps,
		Issuer:       str(m, "iss"),
		Subject:      str(m, "sub"),
		JTI:          str(m, "jti"),
		OrgID:        NormalizeUUID(str(m, "org_id")),
		ProjectID:    NormalizeUUID(str(m, "prj_id")),
		DefinitionID: str(m, "def_id"),
		RepositoryID: str(m, "rpo_id"),
		Ref:          str(m, "rpo_ref"),
		SHA:          strings.ToLower(str(m, "rpo_ver")),
		RunID:        str(m, "run_id"),
	}
	c.CommitVerified = c.SHA != ""
	c.RepositoryHost, c.Repository = RepositoryFromURL(str(m, "rpo_uri"))
	if org, project, pipeline, ok := azureSubject(c.Subject); ok {
		c.WorkflowName = pipeline
		c.azureOrg, c.azureProject = org, project
	}
	c.setBranchFromRef()
	return c
}

// azureSubject splits "p://org/project/pipeline".
func azureSubject(sub string) (org, project, pipeline string, ok bool) {
	rest, found := strings.CutPrefix(sub, "p://")
	if !found {
		return "", "", "", false
	}
	parts := strings.SplitN(rest, "/", 3)
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return "", "", "", false
	}
	return parts[0], parts[1], parts[2], true
}

// ParseBitbucketClaims normalizes a Bitbucket Pipelines step token. It signs
// the workspace and repository UUIDs, the pipeline and step, the branch and
// (when present) the commit, never the repository's name: the name is the
// job's hint, bound to the repository UUID by the platform.
func ParseBitbucketClaims(m map[string]any) Claims {
	c := Claims{
		Provider:     ProviderBitbucket,
		Issuer:       str(m, "iss"),
		Subject:      str(m, "sub"),
		JTI:          str(m, "jti"),
		OrgID:        NormalizeUUID(str(m, "workspaceUuid")),
		RepositoryID: NormalizeUUID(str(m, "repositoryUuid")),
		RunID:        NormalizeUUID(str(m, "pipelineUuid")),
		RunAttempt:   NormalizeUUID(str(m, "pipelineRunUuid")),
		JobID:        NormalizeUUID(str(m, "stepUuid")),
		SHA:          strings.ToLower(str(m, "commitSha")),
		Environment:  NormalizeUUID(str(m, "deploymentEnvironmentUuid")),
	}
	c.CommitVerified = c.SHA != ""
	if b := str(m, "branchName"); b != "" {
		c.Ref, c.Branch = "refs/heads/"+b, b
	}
	return c
}

// ParseCircleCIClaims normalizes a CircleCI job token. The repository and
// ref come from vcs-origin and vcs-ref; the project (project-id) and the
// pipeline definition identify the pipeline, the workflow the run and the
// job the job. It carries no commit (the job's hint, never verified) and no
// event or environment.
func ParseCircleCIClaims(m map[string]any) Claims {
	const ns = "oidc.circleci.com/"
	c := Claims{
		Provider:     ProviderCircleCI,
		Issuer:       str(m, "iss"),
		Subject:      str(m, "sub"),
		JTI:          str(m, "jti"),
		OrgID:        NormalizeUUID(str(m, ns+"org-id")),
		ProjectID:    NormalizeUUID(str(m, ns+"project-id")),
		DefinitionID: NormalizeUUID(str(m, ns+"pipeline-definition-id")),
		RunID:        NormalizeUUID(str(m, ns+"workflow-id")),
		JobID:        NormalizeUUID(str(m, ns+"job-id")),
		Ref:          str(m, ns+"vcs-ref"),
		SSHRerun:     str(m, ns+"ssh-rerun") == "true",
	}
	c.RepositoryHost, c.Repository = RepositoryFromURL(str(m, ns+"vcs-origin"))
	c.setBranchFromRef()
	return c
}

// Jenkins claim names. Only sub (the job's URL) and build_number are the
// plugin's own; the others are claim templates the controller's
// administrator adds (docs/how-to/connect-ci-pipelines.md), so they prove
// what the controller asserts and nothing more.
const (
	JenkinsClaimRepository  = "repository"  // ${GIT_URL}
	JenkinsClaimBranch      = "branch"      // ${BRANCH_NAME} (multibranch) or ${GIT_BRANCH}
	JenkinsClaimCommit      = "sha"         // ${GIT_COMMIT}
	JenkinsClaimEvent       = "event"       // optional
	JenkinsClaimEnvironment = "environment" // optional
)

// ParseJenkinsClaims normalizes a token of the Jenkins OpenID Connect
// provider plugin. The pipeline is the job (from sub, the job's URL, without
// its branch for a multibranch job), the run the build number.
func ParseJenkinsClaims(m map[string]any) Claims {
	c := Claims{
		Provider:    ProviderJenkins,
		Issuer:      str(m, "iss"),
		Subject:     str(m, "sub"),
		JTI:         str(m, "jti"),
		SHA:         strings.ToLower(str(m, JenkinsClaimCommit)),
		RunID:       str(m, "build_number"),
		Event:       strings.ToLower(str(m, JenkinsClaimEvent)),
		Environment: str(m, JenkinsClaimEnvironment),
	}
	if !fullSHARE.MatchString(c.SHA) {
		c.SHA = ""
	}
	c.CommitVerified = c.SHA != ""
	c.RepositoryHost, c.Repository = RepositoryFromURL(str(m, JenkinsClaimRepository))
	branch := strings.TrimPrefix(strings.TrimPrefix(str(m, JenkinsClaimBranch), "refs/heads/"), "origin/")
	switch {
	case jenkinsPRRE.MatchString(branch):
		c.PullRequest = jenkinsPRRE.FindStringSubmatch(branch)[1]
		c.Ref = "refs/pull/" + c.PullRequest + "/head"
		c.Branch = "pull/" + c.PullRequest
	case branch != "":
		c.Ref, c.Branch = "refs/heads/"+branch, branch
	}
	c.Workflow = jenkinsJobPath(c.Subject, branch)
	if c.Repository != "" {
		sum := sha256.Sum256([]byte(c.RepositoryHost + "/" + c.Repository))
		c.RepositoryID = hex.EncodeToString(sum[:16])
	}
	return c
}

// jenkinsJobPath turns a job URL ("https://ci.example/job/acme/job/api/job/main/")
// into the job's full name ("acme/api/main"), dropping the last segment when
// it is the branch (a multibranch job has one job per branch).
func jenkinsJobPath(jobURL, branch string) string {
	u, err := url.Parse(jobURL)
	if err != nil || u.Scheme != schemeHTTPS || u.Host == "" {
		return ""
	}
	// The escaped path: a branch name may contain an encoded "/".
	segs := strings.Split(strings.Trim(u.EscapedPath(), "/"), "/")
	var names []string
	for i := 0; i+1 < len(segs); i++ {
		if segs[i] == "job" {
			name, err := url.PathUnescape(segs[i+1])
			if err != nil {
				return ""
			}
			names = append(names, name)
			i++
		}
	}
	if len(names) > 1 && branch != "" && names[len(names)-1] == branch {
		names = names[:len(names)-1]
	}
	return strings.Join(names, "/")
}

// setBranchFromRef derives the branch and pull request from a full ref.
func (c *Claims) setBranchFromRef() {
	switch {
	case pullRefRE.MatchString(c.Ref):
		c.PullRequest = pullRefRE.FindStringSubmatch(c.Ref)[1]
		// The token names the pull request, not its source branch: its
		// results belong to the pull request, never to a real branch.
		c.Branch = "pull/" + c.PullRequest
	case strings.HasPrefix(c.Ref, "refs/heads/"):
		c.Branch = strings.TrimPrefix(c.Ref, "refs/heads/")
	}
}

// RepositoryFromURL splits a repository's clone or web URL into its host and
// path, lower case and without ".git": "https://github.com/acme/api.git" and
// "git@github.com:acme/api.git" give ("github.com", "acme/api"); an Azure
// Repos URL ("https://dev.azure.com/org/project/_git/repo",
// "https://org.visualstudio.com/project/_git/repo") gives ("dev.azure.com",
// "org/project/repo"); "github.com/acme/api" (no scheme) is read as a URL.
// ("", "") when the value is not a repository address.
func RepositoryFromURL(raw string) (host, path string) {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > 1000 || strings.ContainsAny(raw, " \t\r\n\\") {
		return "", ""
	}
	// scp-like: git@host:owner/name
	if !strings.Contains(raw, "://") {
		if at := strings.Index(raw, "@"); at >= 0 {
			if colon := strings.Index(raw[at:], ":"); colon > 0 {
				raw = "ssh://" + raw[:at+colon] + "/" + raw[at+colon+1:]
			}
		} else {
			raw = "https://" + raw
		}
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
		return "", ""
	}
	switch u.Scheme {
	case "https", "http", "ssh", "git":
	default:
		return "", ""
	}
	host = strings.ToLower(u.Hostname())
	p := strings.ToLower(strings.Trim(strings.TrimSuffix(strings.Trim(u.Path, "/"), ".git"), "/"))
	switch {
	case host == "ssh.dev.azure.com":
		// ssh.dev.azure.com:v3/org/project/repo
		host, p = azureReposHost, strings.TrimPrefix(p, "v3/")
	case host == azureReposHost:
		p = strings.Replace(p, "/_git/", "/", 1)
	case strings.HasSuffix(host, ".visualstudio.com"):
		org := strings.TrimSuffix(host, ".visualstudio.com")
		host, p = azureReposHost, org+"/"+strings.Replace(p, "/_git/", "/", 1)
	}
	segs := strings.Split(p, "/")
	if len(segs) < 2 {
		return "", ""
	}
	for _, s := range segs {
		if s == "" || s == "." || s == ".." || strings.HasPrefix(s, "_") {
			return "", ""
		}
	}
	return host, p
}
