package cirun

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

func allProjectsConfig(issuer string, p Provider) *TrustConfig {
	tid := shared.NewID()
	c := &TrustConfig{TenantID: tid, Name: "all", Provider: p, Issuer: issuer, Rules: Rules{AllRepositories: true}}
	c.Normalize()
	return c
}

// Every project is accepted only from a self-managed GitLab: on a shared
// issuer it would admit anyone in the world.
func TestAllRepositories_OnlySelfManagedGitLab(t *testing.T) {
	if err := allProjectsConfig("https://gitlab.example.com", ProviderGitLab).Validate(); err != nil {
		t.Fatalf("self-managed GitLab refused: %v", err)
	}
	for _, tc := range []struct {
		issuer string
		p      Provider
	}{
		{GitLabDefaultIssuer, ProviderGitLab},
		{"https://GitLab.com/", ProviderGitLab},
		{"https://eu.gitlab.com", ProviderGitLab},
		{"https://gitlab.com:443", ProviderGitLab},
		{GitHubIssuer, ProviderGitHub},
		{"https://ghe.example.com/_services/token", ProviderGitHub},
		{"https://jenkins.example.com/oidc", ProviderJenkins},
	} {
		err := allProjectsConfig(tc.issuer, tc.p).Validate()
		if err == nil || !errors.Is(err, shared.ErrValidation) || !strings.Contains(err.Error(), "all_repositories") {
			t.Errorf("%s %s: %v, want an all_repositories refusal", tc.p, tc.issuer, err)
		}
	}
}

func TestAllRepositories_RuleCombinations(t *testing.T) {
	c := allProjectsConfig("https://gitlab.example.com", ProviderGitLab)
	c.Rules.AllRepositories = false
	if err := c.Validate(); err == nil {
		t.Fatal("no owner, no repository and no all_repositories accepted")
	}
	c.Rules.Owners = []string{"grp"}
	c.Rules.AdmitNewRepositories = true
	if err := c.Validate(); err == nil {
		t.Fatal("admit_new_repositories without all_repositories accepted")
	}
}

// The rules check everything but the group and project; the approved lists
// decide those (ApprovedRepository).
func TestAllRepositories_AdmitLeavesRepositoryToApproval(t *testing.T) {
	r := Rules{AllRepositories: true, Owners: []string{"platform"}, Repositories: []string{"alice/tool"}, Refs: []string{"main"}}
	base := Claims{Provider: ProviderGitLab, SHA: "abc", JTI: "j", Ref: "refs/heads/main"}
	for repo, approved := range map[string]bool{"platform/api": true, "alice/tool": true, "alice/other": false, "newgrp/x": false} {
		c := base
		c.Repository = repo
		if ref := r.Admit(c); ref != nil {
			t.Errorf("%s refused by the rules: %v", repo, ref)
		}
		if r.ApprovedRepository(c) != approved {
			t.Errorf("ApprovedRepository(%s) = %v, want %v", repo, !approved, approved)
		}
	}
	c := base
	c.Repository, c.Ref = "platform/api", "refs/heads/feature"
	if ref := r.Admit(c); ref == nil || ref.Code != RefuseRef {
		t.Fatalf("other rules still apply: %v", ref)
	}
}

// Only approved groups and projects reach scope.
func TestAllRepositories_ScopeOnlyApproved(t *testing.T) {
	c := TrustConfig{Provider: ProviderGitLab, Issuer: "https://git.example.com", Enabled: true, ManageScope: true,
		Rules: Rules{AllRepositories: true, Owners: []string{"platform"}, Repositories: []string{"alice/tool"}}}
	if got := ScopePatterns(&c); !slices.Equal(got, []string{"git.example.com/platform/*", "git.example.com/alice/tool"}) {
		t.Fatalf("scope = %v", got)
	}
	c.Rules.Owners, c.Rules.Repositories = nil, nil
	if got := ScopePatterns(&c); len(got) != 0 {
		t.Fatalf("nothing approved, scope = %v", got)
	}
}
