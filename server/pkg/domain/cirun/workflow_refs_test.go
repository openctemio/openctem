package cirun

import (
	"errors"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// The workflow_refs rule admits only jobs that run a listed pipeline
// definition, so a pull request that edits or adds a workflow file (and
// would post its own verdict) is refused.
func TestRulesAdmitWorkflowRefs(t *testing.T) {
	central := "acme/security/.github/workflows/scan.yml@refs/heads/main"
	cases := []struct {
		name  string
		rules []string
		c     Claims
		want  string // "" admits
	}{
		{"github central workflow", []string{central},
			githubClaims(map[string]any{"job_workflow_ref": central}), ""},
		{"github path is case-insensitive", []string{"Acme/Security/.github/workflows/scan.yml@refs/heads/main"},
			githubClaims(map[string]any{"job_workflow_ref": central}), ""},
		{"github tag glob", []string{"acme/security/.github/workflows/scan.yml@refs/tags/v*"},
			githubClaims(map[string]any{"job_workflow_ref": "acme/security/.github/workflows/scan.yml@refs/tags/v2"}), ""},
		{"github tag glob does not match a branch", []string{"acme/security/.github/workflows/scan.yml@refs/tags/v*"},
			githubClaims(map[string]any{"job_workflow_ref": "acme/security/.github/workflows/scan.yml@refs/heads/v2"}), RefuseWorkflow},
		{"github repository's own workflow", []string{central},
			githubClaims(map[string]any{"job_workflow_ref": "Acme/API/.github/workflows/ci.yml@refs/heads/main"}), RefuseWorkflow},
		{"github central workflow at a feature branch", []string{central},
			githubClaims(map[string]any{"job_workflow_ref": "acme/security/.github/workflows/scan.yml@refs/heads/evil"}), RefuseWorkflow},
		{"github another file in the central repository", []string{central},
			githubClaims(map[string]any{"job_workflow_ref": "acme/security/.github/workflows/other.yml@refs/heads/main"}), RefuseWorkflow},
		{"github token without the claim", []string{central}, githubClaims(nil), RefuseWorkflow},
		{"gitlab central configuration", []string{"gitlab.example.com/grp/ci//scan.yml@refs/heads/main"},
			gitlabClaims(map[string]any{"ci_config_ref_uri": "gitlab.example.com/grp/ci//scan.yml@refs/heads/main"}), ""},
		{"gitlab project's own configuration", []string{"gitlab.example.com/grp/ci//scan.yml@refs/heads/main"},
			gitlabClaims(map[string]any{"ci_config_ref_uri": "gitlab.example.com/grp/proj//.gitlab-ci.yml@refs/heads/main"}), RefuseWorkflow},
		{"gitlab token without the claim", []string{"gitlab.example.com/grp/ci//scan.yml@refs/heads/main"}, gitlabClaims(nil), RefuseWorkflow},
		{"other provider fails closed", []string{central},
			Claims{Provider: ProviderJenkins, Repository: "acme/api", SHA: "abc", Ref: "refs/heads/main", JTI: "j"}, RefuseWorkflow},
		{"no rule admits any definition", nil,
			githubClaims(map[string]any{"job_workflow_ref": "Acme/API/.github/workflows/ci.yml@refs/heads/main"}), ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := Rules{Owners: []string{"acme", "grp"}, WorkflowRefs: tc.rules}
			got := r.Admit(tc.c)
			switch {
			case tc.want == "" && got != nil:
				t.Fatalf("refused: %v", got)
			case tc.want != "" && (got == nil || got.Code != tc.want):
				t.Fatalf("got %v, want %s", got, tc.want)
			}
		})
	}
}

func TestTrustConfigValidateWorkflowRefs(t *testing.T) {
	tid := shared.NewID()
	cfg := func(p Provider, refs ...string) *TrustConfig {
		c := &TrustConfig{TenantID: tid, Name: "x", Provider: p, Rules: Rules{Owners: []string{"acme"}, WorkflowRefs: refs}}
		if p == ProviderGitLab {
			c.Issuer = "https://gitlab.example.com"
		}
		c.Normalize()
		return c
	}
	good := []*TrustConfig{
		cfg(ProviderGitHub, " acme/security/.github/workflows/scan.yml@refs/heads/main ", "acme/security/.github/workflows/scan.yml@refs/tags/v*"),
		cfg(ProviderGitLab, "gitlab.example.com/grp/sub/ci//templates/scan.yml@refs/heads/main"),
	}
	for _, c := range good {
		if err := c.Validate(); err != nil {
			t.Errorf("%s %v: %v", c.Provider, c.Rules.WorkflowRefs, err)
		}
	}
	if got := good[0].Rules.WorkflowRefs[0]; got != "acme/security/.github/workflows/scan.yml@refs/heads/main" {
		t.Errorf("not trimmed: %q", got)
	}
	many := make([]string, maxWorkflowRefs+1)
	for i := range many {
		many[i] = "acme/security/.github/workflows/scan.yml@refs/tags/v" + strings.Repeat("1", i+1)
	}
	bad := map[string]*TrustConfig{
		"no ref":                cfg(ProviderGitHub, "acme/security/.github/workflows/scan.yml"),
		"empty ref":             cfg(ProviderGitHub, "acme/security/.github/workflows/scan.yml@"),
		"wildcard in the path":  cfg(ProviderGitHub, "acme/*/.github/workflows/scan.yml@refs/heads/main"),
		"not a workflow file":   cfg(ProviderGitHub, "acme/security/scan.yml@refs/heads/main"),
		"bad ref pattern":       cfg(ProviderGitHub, "acme/security/.github/workflows/scan.yml@refs/[x"),
		"too long":              cfg(ProviderGitHub, "acme/security/.github/workflows/"+strings.Repeat("a", maxWorkflowRefLen)+".yml@main"),
		"too many":              cfg(ProviderGitHub, many...),
		"gitlab without //":     cfg(ProviderGitLab, "gitlab.example.com/grp/ci/scan.yml@refs/heads/main"),
		"gitlab without a host": cfg(ProviderGitLab, "grp//scan.yml@refs/heads/main"),
	}
	for name, c := range bad {
		if err := c.Validate(); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("%s: err = %v, want validation", name, err)
		}
	}
	for _, p := range []Provider{ProviderJenkins, ProviderCircleCI, ProviderAzureDevOps, ProviderBitbucket} {
		c := &TrustConfig{TenantID: tid, Provider: p, Audience: DefaultAudience(tid), Rules: Rules{
			WorkflowRefs: []string{"acme/security/.github/workflows/scan.yml@main"}}}
		switch p {
		case ProviderAzureDevOps:
			c.Audience = AzureDevOpsAudience
		case ProviderBitbucket:
			c.Rules.WorkspaceUUID = "123e4567-e89b-12d3-a456-426614174000"
		}
		if err := c.validateProviderRules(); err == nil || !strings.Contains(err.Error(), "workflow_refs") {
			t.Errorf("%s: err = %v, want workflow_refs refused", p, err)
		}
	}
}
