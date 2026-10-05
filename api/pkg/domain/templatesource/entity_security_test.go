package templatesource

import (
	"errors"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestGitSourceConfig_RejectsPathsOutsideTheRepository(t *testing.T) {
	for _, p := range []string{"../", "../../", "templates/../../etc", "/etc", "/", `..\..\etc`, "a/\x00b", "templates/.."} {
		c := &GitSourceConfig{URL: "https://github.com/org/repo", Branch: "main", Path: p}
		if err := c.Validate(); err == nil || !errors.Is(err, shared.ErrValidation) {
			t.Errorf("path %q: want a validation error, got %v", p, err)
		}
	}
}

func TestGitSourceConfig_NormalizesLegitimatePaths(t *testing.T) {
	cases := map[string]string{"": "", ".": "", "templates/nuclei/": "templates/nuclei", "./templates": "templates", "a//b": "a/b"}
	for in, want := range cases {
		c := &GitSourceConfig{URL: "https://github.com/org/repo", Branch: "main", Path: in}
		if err := c.Validate(); err != nil {
			t.Errorf("path %q: unexpected error %v", in, err)
			continue
		}
		if c.Path != want {
			t.Errorf("path %q normalized to %q, want %q", in, c.Path, want)
		}
	}
}

func TestGitSourceConfig_URLSchemes(t *testing.T) {
	ok := []string{
		"https://github.com/org/repo.git",
		"ssh://git@github.com/org/repo.git",
		"git@github.com:org/repo.git",
	}
	for _, u := range ok {
		if err := (&GitSourceConfig{URL: u, Branch: "main"}).Validate(); err != nil {
			t.Errorf("%q: unexpected error %v", u, err)
		}
	}
	bad := []string{
		"http://git.corp.example/org/repo", // plain http: templates could be swapped in transit
		"file:///etc",
		"/srv/repos/other-tenant.git",
		"./repo",
		"git://internal.example/repo",
		"ext::sh -c touch% /tmp/pwned",
		"https:///no-host",
		"ssh://-oProxyCommand=x/repo",
	}
	for _, u := range bad {
		if err := (&GitSourceConfig{URL: u, Branch: "main"}).Validate(); err == nil {
			t.Errorf("%q: want a validation error", u)
		}
	}
}

func TestGitSourceConfig_RejectsOptionLikeBranch(t *testing.T) {
	for _, b := range []string{"--upload-pack=x", "a..b", "a b"} {
		if err := (&GitSourceConfig{URL: "https://github.com/org/repo", Branch: b}).Validate(); err == nil {
			t.Errorf("branch %q: want a validation error", b)
		}
	}
	if err := (&GitSourceConfig{URL: "https://github.com/org/repo", Branch: "release/v1.2"}).Validate(); err != nil {
		t.Errorf("ordinary branch rejected: %v", err)
	}
}

func TestS3SourceConfig_RequiresTenantCredentialsAndSafeEndpoint(t *testing.T) {
	base := S3SourceConfig{Bucket: "templates", Region: "us-east-1", AuthType: S3AuthKeys}

	// auth types that would fall back to the server's own AWS identity
	for _, at := range []string{"", "none", "default", "instance_profile"} {
		c := base
		c.AuthType = at
		if err := c.Validate(); err == nil {
			t.Errorf("auth_type %q must be refused (ambient credentials)", at)
		}
	}
	c := base
	c.AuthType = S3AuthSTSRole
	if err := c.Validate(); err == nil {
		t.Error("sts_role without role_arn must be refused")
	}

	for _, ep := range []string{"gopher://x", "http://user:pw@minio:9000", "http://minio:9000/?x=1", "minio:9000", "file:///tmp"} {
		c := base
		c.Endpoint = ep
		if err := c.Validate(); err == nil {
			t.Errorf("endpoint %q must be refused", ep)
		}
	}
	for _, r := range []string{"us-east-1.evil.com", "169.254.169.254", "US-EAST-1/x"} {
		c := base
		c.Region = r
		if err := c.Validate(); err == nil {
			t.Errorf("region %q must be refused", r)
		}
	}

	good := base
	good.Endpoint = "https://minio.corp.example:9000"
	if err := good.Validate(); err != nil {
		t.Errorf("legitimate config refused: %v", err)
	}
}

func TestTemplateSource_S3RequiresCredential(t *testing.T) {
	src, err := NewTemplateSource(shared.NewID(), "s3", SourceTypeS3, "nuclei", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := src.SetS3Config(&S3SourceConfig{Bucket: "templates", Region: "us-east-1", AuthType: S3AuthKeys}); err != nil {
		t.Fatal(err)
	}
	if err := src.Validate(); err == nil {
		t.Fatal("an s3 source without a credential must not validate")
	}
	src.SetCredential(shared.NewID())
	if err := src.Validate(); err != nil {
		t.Fatalf("s3 source with a credential refused: %v", err)
	}
}

// Template-source configuration is stored as plain JSON and shown to anyone
// who can read sources, and the fetched templates run on sensors: new or
// edited sources must use https and keep credentials out of the URL and the
// headers (settings audit SC-M7). Legacy rows are masked in responses.
func TestSourceConfig_HTTPSOnlyAndNoInlineCredentials(t *testing.T) {
	httpCases := []struct {
		name    string
		cfg     HTTPSourceConfig
		wantErr bool
	}{
		{"https ok", HTTPSourceConfig{URL: "https://templates.example.com/pack.zip", Headers: map[string]string{"Accept": "application/zip"}}, false},
		{"plain http", HTTPSourceConfig{URL: "http://templates.example.com/pack.zip"}, true},
		{"password in url", HTTPSourceConfig{URL: "https://bot:ghp_x@templates.example.com/pack.zip"}, true},
		{"authorization header", HTTPSourceConfig{URL: "https://t.example.com/a", Headers: map[string]string{"Authorization": "Bearer x"}}, true},
		{"api key header", HTTPSourceConfig{URL: "https://t.example.com/a", Headers: map[string]string{"X-Api-Key": "x"}}, true},
		{"header injection", HTTPSourceConfig{URL: "https://t.example.com/a", Headers: map[string]string{"Accept": "a\r\nX-Evil: 1"}}, true},
		{"timeout too long", HTTPSourceConfig{URL: "https://t.example.com/a", Timeout: 3600}, true},
	}
	for _, tc := range httpCases {
		c := tc.cfg
		if err := c.Validate(); (err != nil) != tc.wantErr {
			t.Errorf("http %s: err = %v, wantErr %v", tc.name, err, tc.wantErr)
		}
	}

	gitCases := []struct {
		url     string
		wantErr bool
	}{
		{"https://github.com/org/repo.git", false},
		{"git@github.com:org/repo.git", false},
		{"ssh://git@github.com/org/repo.git", false},
		{"http://github.com/org/repo.git", true},
		{"https://bot:ghp_token@github.com/org/repo.git", true},
	}
	for _, tc := range gitCases {
		c := GitSourceConfig{URL: tc.url, Branch: "main"}
		if err := c.Validate(); (err != nil) != tc.wantErr {
			t.Errorf("git %s: err = %v, wantErr %v", tc.url, err, tc.wantErr)
		}
	}

	if got := MaskedURL("https://bot:ghp_token@github.com/org/repo.git"); strings.Contains(got, "ghp_token") {
		t.Errorf("MaskedURL leaked the token: %s", got)
	}
}
