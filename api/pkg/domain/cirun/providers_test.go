package cirun

import (
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Claim shapes mirror each provider's documented tokens (research note 66):
// Azure Pipelines pipeline token, Bitbucket step token, CircleCI job token,
// Jenkins OpenID Connect provider plugin token with the documented templates.

const (
	azOrg     = "0ca3ddd9-1111-4222-8333-444455556666"
	azProject = "7a1b2c3d-1111-4222-8333-444455556666"
	ccOrg     = "11111111-2222-4333-8444-555566667777"
	ccProject = "22222222-3333-4444-8555-666677778888"
	ccWF      = "33333333-4444-4555-8666-777788889999"
	bbWS      = "44444444-5555-4666-8777-888899990000"
	bbRepo    = "55555555-6666-4777-8888-999900001111"
	bbPipe    = "66666666-7777-4888-8999-000011112222"
	sha40     = "0123456789abcdef0123456789abcdef01234567"
)

func azureClaims() map[string]any {
	return map[string]any{
		"iss": AzureDevOpsIssuer(azOrg), "sub": "p://acme/Payments/payments-ci", "aud": AzureDevOpsAudience,
		"jti": "90b75b0a-61b6-4b6e-9f0e-1c2d3e4f5a6b", "org_id": azOrg, "prj_id": azProject, "def_id": "12",
		"run_id": "345", "rpo_id": "acme/api", "rpo_uri": "https://github.com/acme/api.git", "rpo_ver": sha40,
		"rpo_ref": "refs/heads/main",
	}
}

func bitbucketClaims() map[string]any {
	return map[string]any{
		"iss": BitbucketIssuer("acme"), "sub": "{" + bbRepo + "}:{step}", "aud": "openctem:tenant:t",
		"workspaceUuid": "{" + bbWS + "}", "repositoryUuid": "{" + bbRepo + "}", "pipelineUuid": "{" + bbPipe + "}",
		"stepUuid": "{77777777-8888-4999-8000-111122223333}", "branchName": "main", "commitSha": sha40,
	}
}

func circleClaims() map[string]any {
	const ns = "oidc.circleci.com/"
	return map[string]any{
		"iss": CircleCIIssuer(ccOrg), "sub": "org/" + ccOrg + "/project/" + ccProject + "/user/u", "aud": "openctem:tenant:t",
		ns + "org-id": ccOrg, ns + "project-id": ccProject, ns + "workflow-id": ccWF,
		ns + "job-id": "44444444-4444-4444-8444-444444444444", ns + "vcs-origin": "github.com/acme/api",
		ns + "vcs-ref": "refs/heads/main", ns + "ssh-rerun": false,
	}
}

func jenkinsClaims() map[string]any {
	return map[string]any{
		"iss": "https://jenkins.acme.example/oidc", "sub": "https://jenkins.acme.example/job/acme/job/api/job/main/",
		"aud": "openctem:tenant:t", "build_number": float64(42), "repository": "git@github.com:acme/api.git",
		"branch": "main", "sha": sha40,
	}
}

func TestParseProviderClaims(t *testing.T) {
	az := ParseClaims(ProviderAzureDevOps, azureClaims())
	if az.CanonicalRepository() != "github.com/acme/api" || az.Owner() != "acme" || az.SHA != sha40 || !az.CommitVerified ||
		az.Branch != "main" || az.RunID != "345" || az.OrgID != azOrg || az.WorkflowName != "payments-ci" {
		t.Fatalf("azure = %+v", az)
	}
	if u := PipelineURL(ProviderAzureDevOps, az.Issuer, az); u != "https://dev.azure.com/acme/Payments/_build/results?buildId=345" {
		t.Fatalf("azure url = %q", u)
	}

	bb := ParseClaims(ProviderBitbucket, bitbucketClaims())
	if bb.Repository != "" || bb.RepositoryID != bbRepo || bb.OrgID != bbWS || bb.RunID != bbPipe || bb.Branch != "main" || !bb.CommitVerified {
		t.Fatalf("bitbucket = %+v", bb)
	}
	bb.ApplyHints(Hints{Repository: "acme/API", CommitSHA: strings.Repeat("f", 40)})
	if bb.CanonicalRepository() != "bitbucket.org/acme/api" || bb.SHA != sha40 {
		t.Fatalf("bitbucket hints: repository %q sha %q (a signed commit must win)", bb.CanonicalRepository(), bb.SHA)
	}

	cc := ParseClaims(ProviderCircleCI, circleClaims())
	if cc.CanonicalRepository() != "github.com/acme/api" || cc.SHA != "" || cc.RunID != ccWF || cc.Branch != "main" {
		t.Fatalf("circleci = %+v", cc)
	}
	cc.ApplyHints(Hints{CommitSHA: strings.ToUpper(sha40)})
	if cc.SHA != sha40 || cc.CommitVerified {
		t.Fatalf("circleci commit hint: %q verified=%v", cc.SHA, cc.CommitVerified)
	}
	if PipelineURL(ProviderCircleCI, cc.Issuer, cc) != "https://app.circleci.com/pipelines/workflows/"+ccWF {
		t.Fatal("circleci url")
	}

	jk := ParseClaims(ProviderJenkins, jenkinsClaims())
	if jk.CanonicalRepository() != "github.com/acme/api" || jk.Workflow != "acme/api" || jk.RunID != "42" || !jk.CommitVerified {
		t.Fatalf("jenkins = %+v", jk)
	}
	if u := PipelineURL(ProviderJenkins, jk.Issuer, jk); u != "https://jenkins.acme.example/job/acme/job/api/job/main/42/" {
		t.Fatalf("jenkins url = %q", u)
	}
	pr := jenkinsClaims()
	pr["branch"] = "PR-7"
	pr["sub"] = "https://jenkins.acme.example/job/acme/job/api/job/PR-7/"
	jpr := ParseClaims(ProviderJenkins, pr)
	if jpr.PullRequest != "7" || !jpr.IsForkEvent() || jpr.Workflow != "acme/api" {
		t.Fatalf("jenkins pull request = %+v", jpr)
	}
}

// A malformed hint never fills a claim, and hints never apply to providers
// that sign the value.
func TestHintsAreBounded(t *testing.T) {
	cc := ParseClaims(ProviderCircleCI, circleClaims())
	cc.ApplyHints(Hints{CommitSHA: "abc123"})
	if cc.SHA != "" {
		t.Fatal("short commit hint accepted")
	}
	bb := ParseClaims(ProviderBitbucket, bitbucketClaims())
	bb.ApplyHints(Hints{Repository: "../etc"})
	if bb.Repository != "" {
		t.Fatalf("path hint accepted: %q", bb.Repository)
	}
	gh := ParseGitHubClaims(map[string]any{"repository": "acme/api", "ref": "refs/heads/main", "jti": "j"})
	gh.ApplyHints(Hints{CommitSHA: sha40, Repository: "other"})
	if gh.SHA != "" || gh.Repository != "acme/api" {
		t.Fatalf("hints applied to GitHub: %+v", gh)
	}
}

func admitted(t *testing.T, r Rules, c Claims) *Refusal {
	t.Helper()
	if c.JTI == "" {
		c.JTI = "sha256:x"
	}
	return r.Admit(c)
}

func TestAdmitProviderRefusals(t *testing.T) {
	az := ParseClaims(ProviderAzureDevOps, azureClaims())
	if r := admitted(t, Rules{Owners: []string{"acme"}}, az); r != nil {
		t.Fatalf("azure refused: %v", r)
	}
	// One key set signs every Azure organization: the org_id claim must be
	// the issuer's.
	other := azureClaims()
	other["org_id"] = "99999999-1111-4222-8333-444455556666"
	if r := admitted(t, Rules{Owners: []string{"acme"}}, ParseClaims(ProviderAzureDevOps, other)); r == nil || r.Code != RefuseOrganization {
		t.Fatalf("foreign organization admitted: %v", r)
	}
	// A pull request build may be a fork's: refused unless the
	// configuration admits fork pull requests.
	pr := azureClaims()
	pr["rpo_ref"] = "refs/pull/9/merge"
	if r := admitted(t, Rules{Owners: []string{"acme"}}, ParseClaims(ProviderAzureDevOps, pr)); r == nil || r.Code != RefuseForkPullRequest {
		t.Fatalf("azure pull request admitted by default: %v", r)
	}
	if r := admitted(t, Rules{Owners: []string{"acme"}, AllowForkPullRequests: true}, ParseClaims(ProviderAzureDevOps, pr)); r != nil {
		t.Fatalf("azure pull request refused when allowed: %v", r)
	}

	cc := ParseClaims(ProviderCircleCI, circleClaims())
	cc.ApplyHints(Hints{CommitSHA: sha40})
	if r := admitted(t, Rules{Repositories: []string{"acme/api"}}, cc); r != nil {
		t.Fatalf("circleci refused: %v", r)
	}
	ssh := circleClaims()
	ssh["oidc.circleci.com/ssh-rerun"] = true
	sc := ParseClaims(ProviderCircleCI, ssh)
	sc.ApplyHints(Hints{CommitSHA: sha40})
	if r := admitted(t, Rules{Repositories: []string{"acme/api"}, AllowForkPullRequests: true}, sc); r == nil || r.Code != RefuseSSHRerun {
		t.Fatalf("ssh re-run admitted: %v", r)
	}
	wrongOrg := circleClaims()
	wrongOrg["oidc.circleci.com/org-id"] = "99999999-2222-4333-8444-555566667777"
	wc := ParseClaims(ProviderCircleCI, wrongOrg)
	wc.ApplyHints(Hints{CommitSHA: sha40})
	if r := admitted(t, Rules{Repositories: []string{"acme/api"}}, wc); r == nil || r.Code != RefuseOrganization {
		t.Fatalf("circleci foreign org admitted: %v", r)
	}
	noSHA := ParseClaims(ProviderCircleCI, circleClaims())
	if r := admitted(t, Rules{Repositories: []string{"acme/api"}}, noSHA); r == nil || r.Code != RefuseMissingClaims {
		t.Fatalf("circleci without a commit admitted: %v", r)
	}

	bb := ParseClaims(ProviderBitbucket, bitbucketClaims())
	bb.ApplyHints(Hints{Repository: "api"})
	byID := Rules{Owners: []string{"acme"}, Repositories: []string{bbRepo}, WorkspaceUUID: bbWS}
	if r := admitted(t, byID, bb); r != nil {
		t.Fatalf("bitbucket refused: %v", r)
	}
	// The repository rule matches the signed UUID, never the reported name.
	if r := admitted(t, Rules{Owners: []string{"acme"}, Repositories: []string{"77777777-6666-4777-8888-999900001111"},
		WorkspaceUUID: bbWS}, bb); r == nil || r.Code != RefuseRepository {
		t.Fatalf("other bitbucket repository admitted: %v", r)
	}
	// A workspace that took over a renamed workspace's slug has another UUID.
	if r := admitted(t, Rules{Owners: []string{"acme"}, WorkspaceUUID: "88888888-5555-4666-8777-888899990000"}, bb); r == nil || r.Code != RefuseOrganization {
		t.Fatalf("other bitbucket workspace admitted: %v", r)
	}
	if r := admitted(t, Rules{Owners: []string{"acme"}}, bb); r == nil || r.Code != RefuseOrganization {
		t.Fatalf("bitbucket admitted without a pinned workspace: %v", r)
	}

	jk := ParseClaims(ProviderJenkins, jenkinsClaims())
	if r := admitted(t, Rules{Owners: []string{"acme"}, Refs: []string{"main"}}, jk); r != nil {
		t.Fatalf("jenkins refused: %v", r)
	}
	noRepo := jenkinsClaims()
	delete(noRepo, "repository")
	if r := admitted(t, Rules{Owners: []string{"acme"}}, ParseClaims(ProviderJenkins, noRepo)); r == nil || r.Code != RefuseMissingClaims {
		t.Fatalf("jenkins without a repository claim admitted: %v", r)
	}
}

func TestProviderTrustValidation(t *testing.T) {
	tenant := shared.NewID()
	ok := map[string]TrustConfig{
		"azure":     {Provider: ProviderAzureDevOps, Issuer: AzureDevOpsIssuer(strings.ToUpper(azOrg)), Rules: Rules{Owners: []string{"acme"}}},
		"circleci":  {Provider: ProviderCircleCI, Issuer: CircleCIIssuer(ccOrg), Rules: Rules{Repositories: []string{"acme/api"}}},
		"bitbucket": {Provider: ProviderBitbucket, Issuer: BitbucketIssuer("Acme"), Rules: Rules{Owners: []string{"acme"}, Repositories: []string{"{" + strings.ToUpper(bbRepo) + "}"}, WorkspaceUUID: "{" + bbWS + "}"}},
		"jenkins":   {Provider: ProviderJenkins, Issuer: "https://jenkins.acme.example/oidc/", Rules: Rules{Owners: []string{"acme"}}},
	}
	for name, c := range ok {
		c.Name, c.TenantID = name, tenant
		c.Normalize()
		if err := c.Validate(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if name == "azure" && c.Audience != AzureDevOpsAudience {
			t.Fatalf("azure audience = %q", c.Audience)
		}
		if name == "bitbucket" && (c.Rules.Repositories[0] != bbRepo || c.Rules.WorkspaceUUID != bbWS) {
			t.Fatalf("bitbucket ids not normalized: %+v", c.Rules)
		}
	}
	bad := map[string]TrustConfig{
		"azure wildcard issuer":          {Provider: ProviderAzureDevOps, Issuer: "https://vstoken.dev.azure.com", Rules: Rules{Owners: []string{"acme"}}},
		"azure other audience":           {Provider: ProviderAzureDevOps, Issuer: AzureDevOpsIssuer(azOrg), Audience: "openctem:tenant:x", Rules: Rules{Owners: []string{"acme"}}},
		"azure events":                   {Provider: ProviderAzureDevOps, Issuer: AzureDevOpsIssuer(azOrg), Rules: Rules{Owners: []string{"acme"}, Events: []string{"push"}}},
		"azure protected ref":            {Provider: ProviderAzureDevOps, Issuer: AzureDevOpsIssuer(azOrg), Rules: Rules{Owners: []string{"acme"}, RequireProtectedRef: true}},
		"circleci not an org id":         {Provider: ProviderCircleCI, Issuer: "https://oidc.circleci.com/org/acme", Rules: Rules{Owners: []string{"acme"}}},
		"circleci shared audience":       {Provider: ProviderCircleCI, Issuer: CircleCIIssuer(ccOrg), Audience: ccOrg, Rules: Rules{Owners: []string{"acme"}}},
		"circleci environments":          {Provider: ProviderCircleCI, Issuer: CircleCIIssuer(ccOrg), Rules: Rules{Owners: []string{"acme"}, Environments: []string{"prod"}}},
		"bitbucket no workspace uuid":    {Provider: ProviderBitbucket, Issuer: BitbucketIssuer("acme"), Rules: Rules{Owners: []string{"acme"}}},
		"bitbucket repository by name":   {Provider: ProviderBitbucket, Issuer: BitbucketIssuer("acme"), Rules: Rules{Repositories: []string{"acme/api"}, WorkspaceUUID: bbWS}},
		"bitbucket workspace audience":   {Provider: ProviderBitbucket, Issuer: BitbucketIssuer("acme"), Audience: "ari:cloud:bitbucket::workspace/" + bbWS, Rules: Rules{Owners: []string{"acme"}, WorkspaceUUID: bbWS}},
		"bitbucket other host":           {Provider: ProviderBitbucket, Issuer: "https://evil.example/2.0/workspaces/acme/pipelines-config/identity/oidc", Rules: Rules{Owners: []string{"acme"}, WorkspaceUUID: bbWS}},
		"jenkins http issuer":            {Provider: ProviderJenkins, Issuer: "http://jenkins.local/oidc", Rules: Rules{Owners: []string{"acme"}}},
		"jenkins hosted issuer":          {Provider: ProviderJenkins, Issuer: "https://oidc.circleci.com/org/" + ccOrg, Rules: Rules{Owners: []string{"acme"}}},
		"jenkins protected ref":          {Provider: ProviderJenkins, Issuer: "https://jenkins.acme.example/oidc", Rules: Rules{Owners: []string{"acme"}, RequireProtectedRef: true}},
		"workspace uuid outside bb":      {Provider: ProviderJenkins, Issuer: "https://jenkins.acme.example/oidc", Rules: Rules{Owners: []string{"acme"}, WorkspaceUUID: bbWS}},
		"gitlab with a hosted issuer":    {Provider: ProviderGitLab, Issuer: "https://api.bitbucket.org", Rules: Rules{Owners: []string{"acme"}}},
		"jenkins audience of the tenant": {Provider: ProviderJenkins, Issuer: "https://jenkins.acme.example/oidc", Audience: "openctem", Rules: Rules{Owners: []string{"acme"}}},
	}
	for name, c := range bad {
		c.Name, c.TenantID = name, tenant
		c.Normalize()
		if err := c.Validate(); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}

func TestProviderPipelineKeys(t *testing.T) {
	cases := map[Provider]struct {
		claims  map[string]any
		repoID  string
		wfPath  string
		hintRep string
	}{
		ProviderAzureDevOps: {azureClaims(), azProject, "pipelines/12", ""},
		ProviderCircleCI:    {circleClaims(), ccProject, CircleCIDefaultConfigPath, ""},
		ProviderBitbucket:   {bitbucketClaims(), bbRepo, BitbucketConfigPath, "api"},
		ProviderJenkins:     {jenkinsClaims(), "", "acme/api", ""},
	}
	for p, tc := range cases {
		c := ParseClaims(p, tc.claims)
		c.ApplyHints(Hints{Repository: tc.hintRep, CommitSHA: sha40})
		k, r := PipelineKeyFromClaims(p, c.Issuer, c)
		if r != nil {
			t.Fatalf("%s: %v", p, r)
		}
		if (tc.repoID != "" && k.ExternalRepoID != tc.repoID) || len(k.ExternalRepoID) > 64 || k.WorkflowPath != tc.wfPath {
			t.Fatalf("%s key = %+v", p, k)
		}
	}
	// A renamed Jenkins branch job keeps the key; another repository does not.
	a := ParseClaims(ProviderJenkins, jenkinsClaims())
	feat := jenkinsClaims()
	feat["branch"], feat["sub"] = "feature/x", "https://jenkins.acme.example/job/acme/job/api/job/feature%2Fx/"
	b := ParseClaims(ProviderJenkins, feat)
	ka, _ := PipelineKeyFromClaims(ProviderJenkins, a.Issuer, a)
	kb, _ := PipelineKeyFromClaims(ProviderJenkins, b.Issuer, b)
	if ka != kb {
		t.Fatalf("branches of one multibranch job are two pipelines: %+v %+v", ka, kb)
	}
	noProject := azureClaims()
	delete(noProject, "prj_id")
	c := ParseClaims(ProviderAzureDevOps, noProject)
	if _, r := PipelineKeyFromClaims(ProviderAzureDevOps, c.Issuer, c); r == nil {
		t.Fatal("azure token without a project id keyed a pipeline")
	}
}

func TestRepositoryFromURL(t *testing.T) {
	cases := map[string]string{
		"https://github.com/Acme/API.git":                  "github.com/acme/api",
		"git@github.com:acme/api.git":                      "github.com/acme/api",
		"ssh://git@gitlab.example.com:2222/grp/sub/x.git":  "gitlab.example.com/grp/sub/x",
		"https://acme@dev.azure.com/acme/Payments/_git/pp": "dev.azure.com/acme/payments/pp",
		"https://acme.visualstudio.com/Payments/_git/pp":   "dev.azure.com/acme/payments/pp",
		"git@ssh.dev.azure.com:v3/acme/Payments/pp":        "dev.azure.com/acme/payments/pp",
		"github.com/acme/api":                              "github.com/acme/api",
		"https://github.com/acme":                          "",
		"https://github.com/acme/../x":                     "",
		"file:///etc/passwd":                               "",
		"https://github.com/acme/api?x=1":                  "",
		"":                                                 "",
	}
	for in, want := range cases {
		host, p := RepositoryFromURL(in)
		got := ""
		if host != "" {
			got = host + "/" + p
		}
		if got != want {
			t.Errorf("%q = %q, want %q", in, got, want)
		}
	}
}
