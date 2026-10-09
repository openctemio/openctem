// Package mcpoauth holds the OAuth 2.1 model of the MCP endpoint: the scopes
// an MCP client can be granted and the permissions each one stands for.
//
// Design: docs/rfcs/RFC-062-mcp-authorization.md.
package mcpoauth

import (
	"fmt"
	"sort"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Scope is an OAuth scope of the MCP resource.
type Scope string

// The read scopes. Each one stands for a fixed set of permissions; a token
// can use a permission only when one of its scopes covers it AND the user
// holds it at the time of the request.
const (
	ScopeFindingsRead   Scope = "mcp:findings.read"
	ScopeAssetsRead     Scope = "mcp:assets.read"
	ScopeComplianceRead Scope = "mcp:compliance.read"
	ScopePentestRead    Scope = "mcp:pentest.read"
	// ScopeFindingsWrite lets write tools change findings (today: add a
	// comment). Every such call still needs the person's confirmation in
	// the web UI (RFC-062 §10). Never offered up front: only through an
	// insufficient_scope challenge, and only when the organization allows it.
	ScopeFindingsWrite Scope = "mcp:findings.write"
)

// scopeInfo describes one scope.
type scopeInfo struct {
	perms []permission.Permission
	// title is the plain-words description shown on the consent page.
	title string
	write bool
}

// catalog is the closed list of scopes. A scope that is not here does not
// exist: it is refused at the authorization endpoint.
var catalog = map[Scope]scopeInfo{ //nolint:gochecknoglobals // fixed scope table
	ScopeFindingsRead: {
		perms: []permission.Permission{permission.FindingsRead},
		title: "Read findings, vulnerabilities, priorities and remediation groups",
	},
	ScopeAssetsRead: {
		perms: []permission.Permission{permission.AssetsRead},
		title: "Read assets and attack paths",
	},
	ScopeComplianceRead: {
		perms: []permission.Permission{permission.ComplianceFrameworksRead},
		title: "Read compliance posture",
	},
	ScopeFindingsWrite: {
		perms: []permission.Permission{permission.FindingsWrite},
		title: "Add comments to findings, each one confirmed by you in OpenCTEM",
		write: true,
	},
	ScopePentestRead: {
		perms: []permission.Permission{
			permission.PentestCampaignsRead,
			permission.PentestFindingsRead,
			permission.PentestRetestsRead,
			permission.PentestTemplatesRead,
		},
		title: "Read pentest campaigns, findings, retests and templates",
	},
}

// ReadScopes returns the read scopes in a fixed order. They are the scopes a
// client is offered up front (Protected Resource Metadata scopes_supported);
// write scopes are only ever obtained through an insufficient_scope challenge.
func ReadScopes() []Scope {
	out := make([]Scope, 0, len(catalog))
	for s, info := range catalog {
		if !info.write {
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// AllScopes returns every scope, read and write, in a fixed order.
func AllScopes() []Scope {
	out := make([]Scope, 0, len(catalog))
	for s := range catalog {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Known reports whether s is a scope of the MCP resource.
func Known(s Scope) bool {
	_, ok := catalog[s]
	return ok
}

// Title returns the plain-words description of s, or "" for an unknown scope.
func Title(s Scope) string {
	return catalog[s].title
}

// IsWrite reports whether s allows changes.
func IsWrite(s Scope) bool {
	return catalog[s].write
}

// ParseScopes parses a space-separated OAuth scope string. Duplicates are
// dropped and the result is sorted. An unknown scope is a validation error:
// a client must not be granted, or believe it was granted, a scope that does
// not exist.
func ParseScopes(raw string) ([]Scope, error) {
	seen := map[Scope]bool{}
	out := []Scope{}
	for _, f := range strings.Fields(raw) {
		s := Scope(f)
		if !Known(s) {
			return nil, fmt.Errorf("%w: unknown scope %q", shared.ErrValidation, f)
		}
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}

// Join renders scopes as a space-separated OAuth scope string.
func Join(scopes []Scope) string {
	parts := make([]string, len(scopes))
	for i, s := range scopes {
		parts[i] = string(s)
	}
	return strings.Join(parts, " ")
}

// Permissions returns the permissions the scopes stand for, sorted and
// without duplicates. Unknown scopes contribute nothing.
func Permissions(scopes []Scope) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, s := range scopes {
		for _, p := range catalog[s].perms {
			if !seen[string(p)] {
				seen[string(p)] = true
				out = append(out, string(p))
			}
		}
	}
	sort.Strings(out)
	return out
}

// ScopesFor returns the scopes that cover perm (none when no scope does).
// The MCP endpoint names them in an insufficient_scope challenge.
func ScopesFor(perm string) []Scope {
	out := []Scope{}
	for s, info := range catalog {
		for _, p := range info.perms {
			if string(p) == perm {
				out = append(out, s)
				break
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
