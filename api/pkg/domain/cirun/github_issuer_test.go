package cirun

import "testing"

// GitHub Actions trust accepts github.com, an enterprise's customized
// issuer on github.com and a GitHub Enterprise Server; never a hosted
// provider's issuer under another name, nor a lookalike path.
func TestValidateGitHubIssuer(t *testing.T) {
	ok := []string{
		GitHubIssuer,
		GitHubIssuer + "/example-enterprise",
		"https://github.example.com/_services/token",
		"https://github.example.com:443/_services/token",
	}
	for _, iss := range ok {
		if err := validateProviderIssuer(ProviderGitHub, iss); err != nil {
			t.Errorf("%s refused: %v", iss, err)
		}
	}
	bad := []string{
		"",
		"http://github.example.com/_services/token",
		"https://github.example.com/_services/token/extra",
		"https://github.example.com",
		"https://github.example.com:8443/_services/token",
		"https://user:pw@github.example.com/_services/token",
		"https://github.example.com/_services/token?x=1",
		GitHubIssuer + "/Example_Enterprise",
		GitHubIssuer + "/a/b",
		"https://github.com/_services/token",
		"https://vstoken.dev.azure.com/_services/token",
		"https://token.actions.githubusercontent.com/_services/token",
	}
	for _, iss := range bad {
		if err := validateProviderIssuer(ProviderGitHub, iss); err == nil {
			t.Errorf("%s accepted", iss)
		}
	}
}

// A GitHub Enterprise Server job names its repository and pipeline on the
// server's host; github.com and enterprise issuers stay on github.com.
func TestGitHubHostNamesTheServer(t *testing.T) {
	ghes := "https://github.example.com/_services/token"
	if got := CanonicalRepository(ProviderGitHub, ghes, "Acme/API"); got != "github.example.com/acme/api" {
		t.Errorf("GHES repository = %s", got)
	}
	if got := CanonicalRepository(ProviderGitHub, GitHubIssuer+"/example-enterprise", "acme/api"); got != "github.com/acme/api" {
		t.Errorf("enterprise issuer repository = %s", got)
	}
	if got := PipelineURL(ProviderGitHub, ghes, Claims{Repository: "acme/api", RunID: "42"}); got != "https://github.example.com/acme/api/actions/runs/42" {
		t.Errorf("GHES pipeline url = %s", got)
	}
	if got := PipelineURL(ProviderGitHub, GitHubIssuer, Claims{Repository: "acme/api", RunID: "42"}); got != "https://github.com/acme/api/actions/runs/42" {
		t.Errorf("github.com pipeline url = %s", got)
	}
}
