package integration

import (
	"testing"

	"github.com/openctemio/openctem/api/internal/infra/scm"
	integrationdom "github.com/openctemio/openctem/api/pkg/domain/integration"
)

// A repository is tied to its code host identity only when the integration
// listing it is that host: a self-hosted server answering with github.com
// addresses cannot claim github.com repository ids.
func TestRepositoryIdentityBoundToIntegrationHost(t *testing.T) {
	for _, tc := range []struct {
		provider integrationdom.Provider
		base     string
		want     string
	}{
		{integrationdom.ProviderGitHub, "", "github.com"},
		{integrationdom.ProviderGitHub, "https://api.github.com", "github.com"},
		{integrationdom.ProviderGitHub, "https://GHE.example.com/api/v3", "ghe.example.com"},
		{integrationdom.ProviderGitLab, "", "gitlab.com"},
		{integrationdom.ProviderGitLab, "https://git.acme.test", "git.acme.test"},
		{integrationdom.ProviderBitbucket, "https://api.bitbucket.org/2.0", "bitbucket.org"},
		{integrationdom.Provider("other"), "", ""},
	} {
		if got := integrationWebHost(tc.provider, tc.base); got != tc.want {
			t.Fatalf("%s %q: %q, want %q", tc.provider, tc.base, got, tc.want)
		}
	}
	gh := scm.Repository{ID: "1", HTMLURL: "https://github.com/acme/api", CloneURL: "https://github.com/acme/api.git"}
	if !repositoryOnHost(gh, "github.com") {
		t.Fatal("a github.com repository listed by github.com was refused")
	}
	if repositoryOnHost(gh, "git.acme.test") {
		t.Fatal("a self-hosted server claimed a github.com repository")
	}
	if repositoryOnHost(gh, "") {
		t.Fatal("an unknown integration host trusted an address")
	}
	cloneOnly := scm.Repository{ID: "2", CloneURL: "https://git.acme.test/acme/api.git"}
	if !repositoryOnHost(cloneOnly, "git.acme.test") || repositoryOnHost(cloneOnly, "gitlab.com") {
		t.Fatal("clone address not checked")
	}
	stripped := withoutIdentity(gh)
	if stripped.ID != "" || stripped.HTMLURL != "" || stripped.CloneURL != "" {
		t.Fatalf("identity kept: %+v", stripped)
	}
	if name, _ := canonicalRepositoryName(stripped); name != "" {
		t.Fatalf("a repository without identity got a host name: %q", name)
	}
}
