package templatesource

import (
	"errors"
	"testing"

	"github.com/openctemio/api/pkg/domain/shared"
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
		"http://git.corp.example/org/repo",
		"ssh://git@github.com/org/repo.git",
		"git@github.com:org/repo.git",
	}
	for _, u := range ok {
		if err := (&GitSourceConfig{URL: u, Branch: "main"}).Validate(); err != nil {
			t.Errorf("%q: unexpected error %v", u, err)
		}
	}
	bad := []string{
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
