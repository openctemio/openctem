package scope

import (
	"errors"
	"testing"
)

func TestNormalizeRepositoryPattern(t *testing.T) {
	cases := map[string]string{
		"github.com/Acme/App":             "github.com/acme/app",
		"https://GitHub.com/acme/app.git": "github.com/acme/app",
		"gitlab.com/acme/**":              "gitlab.com/acme/*",
		"gitlab.com/acme/*":               "gitlab.com/acme/*",
		" git.example.com/* ":             "git.example.com/*",
		"gitlab.com/acme/app/":            "gitlab.com/acme/app",
	}
	for in, want := range cases {
		if got := NormalizeRepositoryPattern(in); got != want {
			t.Errorf("NormalizeRepositoryPattern(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestValidateRepositoryPattern(t *testing.T) {
	good := []string{
		"github.com/acme/app", "gitlab.com/acme/*", "gitlab.com/acme/sub/*", "git.example.com/*",
		"git.example.com:8443/team/app", "GitHub.com/Acme/App.git", "gitlab.com/0xmanhnv/*",
	}
	for _, p := range good {
		if err := ValidatePattern(TargetTypeRepository, p); err != nil {
			t.Errorf("ValidatePattern(%q) = %v, want nil", p, err)
		}
	}
	bad := []string{
		"github.com",          // a bare host
		"*/acme/app",          // a wildcard host
		"*.github.com/acme/*", // a wildcard host
		"github.com/a*/app",   // a wildcard inside a segment
		"github.com/*/app",    // a wildcard before the end
		"github.com/acme/../x",
		"github.com//app",
		"acme/app", // no code host
		"not a repo",
	}
	for _, p := range bad {
		if err := ValidatePattern(TargetTypeRepository, p); !errors.Is(err, ErrInvalidPattern) {
			t.Errorf("ValidatePattern(%q) = %v, want ErrInvalidPattern", p, err)
		}
	}
}

func TestMatchRepository(t *testing.T) {
	cases := []struct {
		pattern, value string
		want           bool
	}{
		{"gitlab.com/acme/*", "gitlab.com/acme/app", true},
		{"gitlab.com/acme/*", "gitlab.com/acme/sub/group/app", true}, // subgroups, any depth
		{"gitlab.com/acme/*", "gitlab.com/acme-evil/app", false},     // segment boundary
		{"gitlab.com/acme/*", "gitlab.com/acme", true},               // the namespace itself
		{"gitlab.com/acme/*", "gitlab.com/acme-evil", false},
		{"gitlab.com/acme/*", "gitlab.com/other/app", false},
		{"gitlab.com/acme/*", "GitLab.com/ACME/App.git", true}, // canonical form
		{"github.com/acme/app", "github.com/acme/app", true},
		{"github.com/acme/app", "github.com/acme/app-2", false},
		{"github.com/acme/app", "github.com/acme/app/sub", false},
		{"git.example.com/*", "git.example.com/any/thing", true},
		{"git.example.com/*", "git.example.com.evil.net/x", false},
		{"gitlab.com/acme/*", "gitlab.com/acme/sub/*", true}, // a narrower pattern is inside
		{"gitlab.com/acme/sub/*", "gitlab.com/acme/*", false},
	}
	for _, c := range cases {
		if got := MatchesPattern(TargetTypeRepository, c.pattern, c.value); got != c.want {
			t.Errorf("MatchesPattern(repository, %q, %q) = %v, want %v", c.pattern, c.value, got, c.want)
		}
		if got := MatchesExclusionPattern(ExclusionTypeRepository, c.pattern, c.value); got != c.want {
			t.Errorf("MatchesExclusionPattern(repository, %q, %q) = %v, want %v", c.pattern, c.value, got, c.want)
		}
	}
}

func TestRepositoryHostWide(t *testing.T) {
	if !RepositoryHostWide("git.example.com/*") || !RepositoryHostWide("git.example.com/**") {
		t.Error("host/* is host-wide")
	}
	if RepositoryHostWide("gitlab.com/acme/*") || RepositoryHostWide("gitlab.com/acme/app") {
		t.Error("a namespace or a repository is not host-wide")
	}
	if h := RepositoryPatternHost("Git.Example.com:8443/team/*"); h != "git.example.com" {
		t.Errorf("host = %q", h)
	}
}

// A whole-host entry is refused on a code host many organizations share (a
// namespace is the least there); any other host may be whole.
func TestGuardrails_RepositoryEntries(t *testing.T) {
	g := DefaultGuardrails()
	cases := []struct {
		pattern string
		want    error
	}{
		{"gitlab.com/*", ErrSharedCodeHost},
		{"github.com/**", ErrSharedCodeHost},
		{"https://GitHub.com/*", ErrSharedCodeHost},
		{"bitbucket.org/*", ErrSharedCodeHost},
		{"gitlab.com/0xmanhnv/*", nil},
		{"github.com/acme/app", nil},
		{"git.example.com/*", nil},
		{"git.example.com:8443/*", nil},
		{"git.agency.gov/*", ErrDenyList}, // the deny list applies to code hosts too
	}
	for _, c := range cases {
		if err := g.CheckPattern(TargetTypeRepository, c.pattern); !errors.Is(err, c.want) && err != c.want { //nolint:errorlint // nil case
			t.Errorf("CheckPattern(%q) = %v, want %v", c.pattern, err, c.want)
		}
	}
	// The operator's own shared hosts join the list.
	op := g.WithPublicCodeHosts([]string{" Git.Shared.Example "})
	if err := op.CheckPattern(TargetTypeRepository, "git.shared.example/*"); !errors.Is(err, ErrSharedCodeHost) {
		t.Errorf("operator host: %v", err)
	}
	if err := g.CheckPattern(TargetTypeRepository, "git.shared.example/*"); err != nil {
		t.Errorf("the operator's list leaked into the defaults: %v", err)
	}
	if !g.PublicCodeHost("GitHub.com:443") || g.PublicCodeHost("git.example.com") {
		t.Error("PublicCodeHost")
	}
}
