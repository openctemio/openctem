// Package include is the one implementation of include= on a read
// (GET /api/v1/tools?include=settings,stats), shared by every resource that
// embeds related data in a response.
//
// Security model (each rule has a test in this package or in the resource's
// conformance run, includetest.RunConformance):
//   - A whitelist per resource (Registry). An unknown value, a nested one
//     ("a.b"), more than MaxIncludes values or a parameter longer than
//     maxParamLen is refused with 400 INVALID_INCLUDE before any read.
//   - Each include names the permissions of its standalone read and is
//     checked with the same middleware.HasPermission as the route gates
//     (owner/admin bypass included). One the caller does not hold is
//     OMITTED and listed in meta.omitted_includes: the answer does not
//     depend on whether related data exists, so it is not an oracle.
//   - Names that would expose secrets, credentials, audit internals or other
//     users' personal data cannot be registered (deniedNames).
//   - Loading is the resource's job, once per include for the whole page
//     (never per row), through service calls that take the caller's tenant.
//     The projection of each include is an explicit response type.
//   - An expensive include lowers the page size (Set.PerPageCap) and costs
//     extra read-limiter tokens (Prepare); a response that took include= is
//     Cache-Control: private, no-store (Prepare).
package include

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
)

// MaxIncludes is the most include values one request may name.
const MaxIncludes = 3

// maxParamLen bounds the raw include parameter.
const maxParamLen = 64

// ExpensivePerPage is the page-size cap when an expensive include is loaded.
const ExpensivePerPage = 50

// Spec is one include a resource offers.
type Spec struct {
	Name string
	// Permissions are all required: the same as the include's standalone read.
	Permissions []permission.Permission
	// Cost is the extra read-limiter tokens the include takes (0: none).
	Cost int
	// Expensive lowers the page size to ExpensivePerPage.
	Expensive bool
}

// deniedWords can never appear in an include name: secrets, credentials,
// key material, audit internals and other users' personal data have their
// own audited or gated routes (docs/architecture/tool-availability.md). Matched per word of the
// name (words split on "_"), singular or plural.
var deniedWords = map[string]bool{
	"secret": true, "credential": true, "password": true, "token": true, "key": true, "apikey": true,
	"private": true, "audit": true, "session": true, "mfa": true, "email": true, "raw": true,
	"log": true, "evidence": true, "attachment": true, "hash": true, "signing": true,
}

var validName = regexp.MustCompile(`^[a-z][a-z_]{1,30}$`)

// Registry is the include whitelist of one resource.
type Registry struct {
	specs []Spec
	byKey map[string]Spec
	names []string
}

// NewRegistry builds a resource's whitelist. It panics on a malformed,
// duplicate or denied name, or an include without a permission: a
// programming error caught by the resource's first test.
func NewRegistry(specs ...Spec) *Registry {
	r := &Registry{byKey: make(map[string]Spec, len(specs))}
	for _, s := range specs {
		if !validName.MatchString(s.Name) {
			panic(fmt.Sprintf("include: malformed name %q", s.Name))
		}
		if Denied(s.Name) {
			panic(fmt.Sprintf("include: %q may never be includable", s.Name))
		}
		if len(s.Permissions) == 0 {
			panic(fmt.Sprintf("include: %q has no permission", s.Name))
		}
		if _, dup := r.byKey[s.Name]; dup {
			panic(fmt.Sprintf("include: %q registered twice", s.Name))
		}
		r.byKey[s.Name] = s
		r.specs = append(r.specs, s)
		r.names = append(r.names, s.Name)
	}
	return r
}

// Denied reports whether name falls under the deny-list.
func Denied(name string) bool {
	for _, w := range strings.Split(strings.ToLower(name), "_") {
		if deniedWords[w] || deniedWords[strings.TrimSuffix(w, "s")] {
			return true
		}
	}
	return false
}

// Specs returns the registered includes.
func (r *Registry) Specs() []Spec { return r.specs }

// Set is the outcome of an include parameter.
type Set struct {
	asked   bool
	granted map[string]Spec
	// Omitted are the includes asked for without the permission, in the
	// order asked.
	Omitted []string
}

// Granted returns a Set with the given includes loaded, for a response the
// server builds itself (no caller parameter).
func Granted(r *Registry, names ...string) Set {
	s := Set{granted: map[string]Spec{}, Omitted: []string{}}
	for _, n := range names {
		if spec, ok := r.byKey[n]; ok {
			s.granted[n] = spec
		}
	}
	return s
}

// Has reports whether name is asked for and allowed.
func (s Set) Has(name string) bool {
	_, ok := s.granted[name]
	return ok
}

// Cost is the extra read-limiter tokens of the loaded includes.
func (s Set) Cost() int {
	n := 0
	for _, spec := range s.granted {
		n += spec.Cost
	}
	return n
}

// PerPageCap is the page-size cap: ExpensivePerPage when an expensive
// include is loaded, otherwise normal.
func (s Set) PerPageCap(normal int) int {
	for _, spec := range s.granted {
		if spec.Expensive && normal > ExpensivePerPage {
			return ExpensivePerPage
		}
	}
	return normal
}

// Meta is the meta block of a response that took include=.
type Meta struct {
	// OmittedIncludes were asked for but left out: the caller lacks the
	// permission they need.
	OmittedIncludes []string `json:"omitted_includes"`
}

// Meta returns the response meta block.
func (s Set) Meta() Meta {
	if s.Omitted == nil {
		return Meta{OmittedIncludes: []string{}}
	}
	return Meta{OmittedIncludes: s.Omitted}
}

// Parse validates r's include parameter against the whitelist and keeps the
// includes the caller may read.
func (reg *Registry) Parse(r *http.Request) (Set, *apierror.Error) {
	set := Set{granted: map[string]Spec{}, Omitted: []string{}}
	raw := r.URL.Query().Get("include")
	if raw == "" {
		return set, nil
	}
	set.asked = true
	invalid := func(msg string) *apierror.Error {
		return apierror.New(http.StatusBadRequest, apierror.CodeInvalidInclude,
			fmt.Sprintf("%s; include takes at most %d of: %s", msg, MaxIncludes, strings.Join(reg.names, ", ")))
	}
	if len(raw) > maxParamLen {
		return set, invalid("include is too long")
	}
	values := make([]string, 0, MaxIncludes)
	for _, v := range strings.Split(raw, ",") {
		if v = strings.TrimSpace(v); v != "" {
			values = append(values, v)
		}
	}
	if len(values) > MaxIncludes {
		return set, invalid("too many includes")
	}
	seen := map[string]bool{}
	for _, v := range values {
		if strings.ContainsAny(v, ".()[]") {
			return set, invalid("nested includes are not supported")
		}
		spec, ok := reg.byKey[v]
		if !ok {
			return set, invalid("unknown include")
		}
		if seen[v] {
			continue
		}
		seen[v] = true
		if holdsAll(r, spec.Permissions) {
			set.granted[v] = spec
		} else {
			set.Omitted = append(set.Omitted, v)
		}
	}
	return set, nil
}

func holdsAll(r *http.Request, perms []permission.Permission) bool {
	for _, p := range perms {
		if !middleware.HasPermission(r.Context(), p.String()) {
			return false
		}
	}
	return true
}

// Prepare runs before the loaders: a response to a request that named
// include= is never stored by a shared cache, and the loaded includes take
// their extra cost from the caller's read budget. It answers 429 and returns
// false when the budget cannot cover them.
func Prepare(w http.ResponseWriter, r *http.Request, s Set) bool {
	if s.asked {
		w.Header().Set("Cache-Control", "private, no-store")
	}
	if !middleware.ChargeReadCost(r.Context(), s.Cost()) {
		w.Header().Set("Retry-After", "1")
		apierror.RateLimitExceeded().WriteJSON(w)
		return false
	}
	return true
}
