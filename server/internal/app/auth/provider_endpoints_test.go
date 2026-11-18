package auth

import (
	"go/build"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// The provider endpoint override is test-only: a build without the tag
// "authtestseam" compiles the release file and not the override, and reads no
// environment variable.
func TestProviderTestSeam_TagSelectsTheFile(t *testing.T) {
	_, here, _, _ := runtime.Caller(0)
	dir := filepath.Dir(here)
	for _, c := range []struct {
		tags      []string
		want, not string
	}{
		{nil, "provider_endpoints_release.go", "provider_endpoints_testseam.go"},
		{[]string{"authtestseam"}, "provider_endpoints_testseam.go", "provider_endpoints_release.go"},
	} {
		ctx := build.Default
		ctx.BuildTags = c.tags
		pkg, err := ctx.ImportDir(dir, 0)
		if err != nil {
			t.Fatalf("tags %v: %v", c.tags, err)
		}
		if !slices.Contains(pkg.GoFiles, c.want) || slices.Contains(pkg.GoFiles, c.not) {
			t.Fatalf("tags %v compile %v; want %s and not %s", c.tags, pkg.GoFiles, c.want, c.not)
		}
	}
}

// The seam is opt-in twice: the tag AND an explicit test APP_ENV. The check
// is a plain function so a release-build test run proves it too.
func TestSeamEnvAllowed_OnlyExplicitTestValues(t *testing.T) {
	for _, ok := range []string{"test", "e2e", " TEST ", "E2E"} {
		if !SeamEnvAllowed(ok) {
			t.Errorf("APP_ENV=%q should allow the seam", ok)
		}
	}
	for _, no := range []string{"", "production", "prod", "staging", "development", "dev", "testing", "ci", "test-prod"} {
		if SeamEnvAllowed(no) {
			t.Errorf("APP_ENV=%q must not allow the seam", no)
		}
	}
}

// In a build without the tag (every release build) the environment cannot
// move a provider endpoint.
func TestProviderTestSeam_ReleaseBuildIgnoresTheEnvironment(t *testing.T) {
	if providerTestSeamCompiled {
		t.Skip("this test binary was built with the authtestseam tag")
	}
	t.Setenv(EnvTestSeamProviderURL, "https://idp.example.com")
	t.Setenv(EnvTestSeamProviderBrowserURL, "https://idp.example.com")
	if TestSeamActive() {
		t.Fatal("a release build reports the seam active")
	}
	s := &OAuthService{}
	for _, c := range []struct{ got, want string }{
		{TokenEndpoint(OAuthProviderGoogle), "https://oauth2.googleapis.com/token"},
		{TokenEndpoint(OAuthProviderGitHub), "https://github.com/login/oauth/access_token"},
		{TokenEndpoint(OAuthProviderMicrosoft), "https://login.microsoftonline.com/common/oauth2/v2.0/token"},
		{s.getAuthURL(OAuthProviderGoogle), "https://accounts.google.com/o/oauth2/v2/auth"},
		{providerEndpoint(googleJWKSURL), googleJWKSURL},
		{providerBrowserEndpoint("https://x.test/a"), "https://x.test/a"},
	} {
		got, want := c.got, c.want
		if got != want {
			t.Errorf("got %s, want %s", got, want)
		}
	}
}

// No build that ships passes the tag: it appears only in the test suites'
// own files (their scripts, compose files and workflow), never in a
// Dockerfile, bake file, Makefile, release script or another workflow.
func TestProviderTestSeam_NoReleaseBuildPassesTheTag(t *testing.T) {
	_, here, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(here), "..", "..", "..", "..") // repository root
	if _, err := os.Stat(filepath.Join(root, ".github")); err != nil {
		t.Skipf("repository root not found: %v", err)
	}
	allowed := []string{
		"server/tests/",
		"web/e2e/",
		".github/workflows/api-auth-scenarios.yml",
		// The release guards that refuse the tag: they name it to forbid it.
		".github/scripts/release/build-dist.sh",
		".github/scripts/release/check-no-test-seam.sh",
		".github/scripts/release/tests/test_build_dist_seam.sh",
	}
	buildFile := func(rel string) bool {
		base := filepath.Base(rel)
		switch {
		case strings.HasPrefix(base, "Dockerfile"), strings.HasSuffix(base, ".hcl"), base == "Makefile",
			strings.HasSuffix(base, ".mk"), strings.HasPrefix(base, ".goreleaser"), strings.HasSuffix(base, ".sh"),
			strings.HasSuffix(base, ".yml"), strings.HasSuffix(base, ".yaml"):
			return true
		}
		return false
	}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", ".next", "vendor":
				return filepath.SkipDir
			}
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if !buildFile(rel) {
			return nil
		}
		raw, rerr := os.ReadFile(path)
		if rerr != nil {
			t.Errorf("read %s: %v", rel, rerr)
			return nil
		}
		if !strings.Contains(string(raw), "authtestseam") {
			return nil
		}
		for _, a := range allowed {
			if strings.HasPrefix(rel, a) {
				return nil
			}
		}
		t.Errorf("%s passes the authtestseam build tag; only the sign-in test suites may", rel)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
