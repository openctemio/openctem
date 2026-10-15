package scope

// Repository scope entries name code repositories on a code host
// (docs/rfcs/RFC-054-scope-model.md, "Repository entries"):
//
//   - "github.com/acme/app" is that one repository;
//   - "gitlab.com/acme/*" is every repository under the namespace, at any
//     depth (GitLab subgroups included), like "*.x" for a domain;
//   - "git.example.com/*" is every repository on a host. It is refused on a
//     code host shared by many organizations (PublicCodeHost), where a
//     namespace is the least an entry may name.
//
// Patterns and values are compared in the repository asset's canonical form
// (asset.NormalizeName): lower case, without a scheme, credentials or a
// ".git" suffix, so "https://GitHub.com/Acme/App.git" is
// "github.com/acme/app".

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
)

var (
	// repositoryHostRE is a host name, optionally with a port (a
	// self-managed instance on a non-default port).
	repositoryHostRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*(:[0-9]{1,5})?$`)
	// repositorySegmentRE is one path segment of a repository path.
	repositorySegmentRE = regexp.MustCompile(`^[a-z0-9_.][a-z0-9_.+-]*$`)
)

// NormalizeRepositoryPattern is a repository pattern in canonical form:
// lower case, no scheme or ".git", no trailing slash, and "/**" written as
// "/*". Validation is separate (ValidatePattern).
func NormalizeRepositoryPattern(pattern string) string {
	p := strings.TrimSpace(pattern)
	wild := strings.HasSuffix(p, "/*") || strings.HasSuffix(p, "/**")
	if wild {
		p = strings.TrimRight(strings.TrimSuffix(strings.TrimSuffix(p, "*"), "*"), "/")
	}
	p = asset.NormalizeName(p, asset.AssetTypeRepository, "")
	p = strings.Trim(strings.ToLower(p), "/")
	if wild {
		return p + "/*"
	}
	return p
}

// repositoryParts splits a normalized pattern into its host, path segments
// and whether it ends in "/*".
func repositoryParts(pattern string) (host string, segs []string, wild bool) {
	p := pattern
	if strings.HasSuffix(p, "/*") {
		wild = true
		p = strings.TrimSuffix(p, "/*")
	}
	parts := strings.Split(p, "/")
	return parts[0], parts[1:], wild
}

func validateRepositoryPattern(pattern string) error {
	p := NormalizeRepositoryPattern(pattern)
	host, segs, wild := repositoryParts(p)
	if !repositoryHostRE.MatchString(host) || (!strings.Contains(host, ".") && !strings.Contains(host, ":") && host != "localhost") {
		return fmt.Errorf("%w: a repository entry starts with the code host, such as github.com/org/repo", ErrInvalidPattern)
	}
	if len(segs) == 0 && !wild {
		return fmt.Errorf("%w: name a repository (github.com/org/repo), a namespace (github.com/org/*) or a whole host (git.example.com/*)", ErrInvalidPattern)
	}
	for _, s := range segs {
		if s == "." || s == ".." || !repositorySegmentRE.MatchString(s) {
			return fmt.Errorf("%w: a repository path takes letters, digits, '.', '_', '-' and '+'; '*' only as the whole last segment", ErrInvalidPattern)
		}
	}
	return nil
}

// RepositoryHostWide reports whether a repository pattern covers every
// repository of its host ("host/*").
func RepositoryHostWide(pattern string) bool {
	_, segs, wild := repositoryParts(NormalizeRepositoryPattern(pattern))
	return wild && len(segs) == 0
}

// RepositoryPatternHost is the code host a repository pattern names
// (without the port).
func RepositoryPatternHost(pattern string) string {
	host, _, _ := repositoryParts(NormalizeRepositoryPattern(pattern))
	if i := strings.LastIndexByte(host, ':'); i > 0 {
		host = host[:i]
	}
	return host
}

// matchRepository reports whether a repository value (a repository name, or
// another pattern when patterns are compared) falls under pattern, segment
// by segment: "gitlab.com/acme/*" covers the namespace "gitlab.com/acme"
// itself, "gitlab.com/acme/sub/app" and "gitlab.com/acme/*", never
// "gitlab.com/acme-evil/app".
func matchRepository(pattern, value string) bool {
	p := NormalizeRepositoryPattern(pattern)
	v := NormalizeRepositoryPattern(value)
	if p == "" || v == "" {
		return false
	}
	if p == v {
		return true
	}
	if !strings.HasSuffix(p, "/*") {
		return false
	}
	prefix := strings.TrimSuffix(p, "/*")
	return v == prefix || strings.HasPrefix(v, prefix+"/")
}
