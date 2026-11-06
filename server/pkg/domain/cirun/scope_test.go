package cirun

import (
	"slices"
	"testing"
)

func TestScopePatterns(t *testing.T) {
	cases := []struct {
		name string
		cfg  TrustConfig
		want []string
	}{
		{"github owners", TrustConfig{Provider: ProviderGitHub, Issuer: GitHubIssuer, Rules: Rules{Owners: []string{"acme", "beta"}}},
			[]string{"github.com/acme/*", "github.com/beta/*"}},
		{"github enterprise issuer names the orgs", TrustConfig{Provider: ProviderGitHub, Issuer: GitHubIssuer + "/acme-ent",
			Rules: Rules{Owners: []string{"acme"}}}, []string{"github.com/acme/*"}},
		{"github enterprise server", TrustConfig{Provider: ProviderGitHub, Issuer: "https://ghe.example.com/_services/token",
			Rules: Rules{Owners: []string{"acme"}}}, []string{"ghe.example.com/acme/*"}},
		{"gitlab.com user namespace", TrustConfig{Provider: ProviderGitLab, Issuer: GitLabDefaultIssuer,
			Rules: Rules{Owners: []string{"0xmanhnv"}}}, []string{"gitlab.com/0xmanhnv/*"}},
		{"self-managed gitlab", TrustConfig{Provider: ProviderGitLab, Issuer: "https://git.example.com",
			Rules: Rules{Owners: []string{"platform"}}}, []string{"git.example.com/platform/*"}},
		{"repositories win over owners", TrustConfig{Provider: ProviderGitLab, Issuer: GitLabDefaultIssuer,
			Rules: Rules{Owners: []string{"acme"}, Repositories: []string{"acme/app", "acme/team/*", "acme/svc-*", "acme/**"}}},
			[]string{"gitlab.com/acme/app", "gitlab.com/acme/team/*", "gitlab.com/acme/*"}},
		{"bitbucket names repositories by id", TrustConfig{Provider: ProviderBitbucket, Issuer: "https://api.bitbucket.org/2.0/workspaces/x/pipelines-config/identity/oidc",
			Rules: Rules{Repositories: []string{"{7f0b5f0e-0000-4000-8000-000000000000}"}}}, nil},
	}
	for _, c := range cases {
		c.cfg.Enabled, c.cfg.ManageScope = true, true
		if got := ScopePatterns(&c.cfg); !slices.Equal(got, c.want) {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
	off := TrustConfig{Provider: ProviderGitHub, Issuer: GitHubIssuer, Rules: Rules{Owners: []string{"acme"}}, Enabled: true}
	if got := ScopePatterns(&off); got != nil {
		t.Errorf("manage_scope off: %v", got)
	}
	off.ManageScope, off.Enabled = true, false
	if got := ScopePatterns(&off); got != nil {
		t.Errorf("disabled trust: %v", got)
	}
}
