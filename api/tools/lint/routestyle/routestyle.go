// Package routestyle checks every registered HTTP route against the API
// conventions of RFC-041 (docs/rfcs/RFC-041-api-path-design.md,
// docs/architecture/api-conventions.md).
//
// It reads the route source the same way tools/lint/openapicontract and
// tests/unit/route_authz_coverage_test.go do: an AST walk of
// internal/infra/http/routes that follows Group nesting, so each route's path
// is its full path. It also records the middleware chain as source text, with
// the middleware-slice variables of the registering function expanded, so it
// can tell which authenticator a route runs.
//
// Today's violations are frozen in api/openapi/route-style-baseline.txt. The
// baseline only shrinks: a new violation fails, and so does a baseline line
// that no longer matches a violation.
package routestyle

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/openctemio/openctem/api/internal/infra/http/routes/plane"
	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
)

// Route is one registration.
type Route struct {
	Method string
	Path   string
	// Chain is the handler and middleware source (group and route level),
	// with middleware-slice variables expanded.
	Chain string
	Pos   string
}

// Violation is one rule a route breaks.
type Violation struct {
	Rule   string
	Method string
	Path   string
	Msg    string
}

// Key is the baseline form: "RULE METHOD /path".
func (v Violation) Key() string { return v.Rule + " " + v.Method + " " + v.Path }

// ---------------------------------------------------------------------------
// Route discovery
// ---------------------------------------------------------------------------

var routeMethods = map[string]bool{"GET": true, "POST": true, "PUT": true, "PATCH": true, "DELETE": true}

// Routes returns every route registered under routesDir (non-test files).
func Routes(routesDir string) ([]Route, error) {
	entries, err := os.ReadDir(routesDir)
	if err != nil {
		return nil, err
	}
	fset := token.NewFileSet()
	var out []Route
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(routesDir, name), nil, parser.SkipObjectResolution)
		if err != nil {
			return nil, err
		}
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			w := walker{fset: fset, vars: assignments(fset, fn.Body)}
			w.walk(fn.Body, "", nil, &out)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		return out[i].Method < out[j].Method
	})
	return out, nil
}

type walker struct {
	fset *token.FileSet
	vars map[string]string
}

func (w walker) src(n ast.Node) string {
	var b bytes.Buffer
	_ = printer.Fprint(&b, w.fset, n)
	return strings.Join(strings.Fields(b.String()), " ")
}

var identRe = regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]*`)

// expand appends the assigned source of every middleware-slice variable the
// text mentions, a few levels deep.
func (w walker) expand(s string) string {
	seen := map[string]bool{}
	out := s
	frontier := s
	for range 4 {
		var add []string
		for _, id := range identRe.FindAllString(frontier, -1) {
			if v, ok := w.vars[id]; ok && !seen[id] {
				seen[id] = true
				add = append(add, v)
			}
		}
		if len(add) == 0 {
			break
		}
		frontier = strings.Join(add, " ")
		out += " " + frontier
	}
	return out
}

func (w walker) walk(n ast.Node, prefix string, chain []string, out *[]Route) {
	ast.Inspect(n, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		p, ok := pathArg(call.Args[0])
		if !ok {
			return true
		}
		switch {
		case sel.Sel.Name == "Group" && len(call.Args) >= 2:
			body, ok := call.Args[1].(*ast.FuncLit)
			if !ok {
				return true
			}
			c := append([]string{}, chain...)
			for _, a := range call.Args[2:] {
				c = append(c, w.src(a))
			}
			w.walk(body.Body, join(prefix, p), c, out)
			return false
		case routeMethods[sel.Sel.Name]:
			c := append([]string{}, chain...)
			for _, a := range call.Args[1:] {
				c = append(c, w.src(a))
			}
			*out = append(*out, Route{
				Method: sel.Sel.Name,
				Path:   join(prefix, p),
				Chain:  w.expand(strings.Join(c, " | ")),
				Pos:    w.fset.Position(call.Pos()).String(),
			})
		}
		return true
	})
}

// assignments maps each variable assigned in body to the source of every
// right-hand side assigned to it.
func assignments(fset *token.FileSet, body *ast.BlockStmt) map[string]string {
	w := walker{fset: fset}
	vars := map[string]string{}
	ast.Inspect(body, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for i, lhs := range as.Lhs {
			id, ok := lhs.(*ast.Ident)
			if !ok || i >= len(as.Rhs) {
				continue
			}
			vars[id.Name] += " " + w.src(as.Rhs[i])
		}
		return true
	})
	return vars
}

func pathArg(e ast.Expr) (string, bool) {
	switch v := e.(type) {
	case *ast.BasicLit:
		if v.Kind != token.STRING {
			return "", false
		}
		s, err := strconv.Unquote(v.Value)
		return s, err == nil
	case *ast.SelectorExpr:
		if pkg, ok := v.X.(*ast.Ident); ok && pkg.Name == "protov2" {
			s, ok := protov2.Paths[v.Sel.Name]
			return s, ok
		}
	}
	return "", false
}

func join(prefix, path string) string {
	if path == "" || path == "/" {
		if prefix == "" {
			return "/"
		}
		return prefix
	}
	return strings.TrimSuffix(prefix, "/") + path
}

// ---------------------------------------------------------------------------
// Rules (RFC-041 §7)
// ---------------------------------------------------------------------------

var (
	segmentRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)
	paramRe   = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
	versionRe = regexp.MustCompile(`^v[0-9]+$`)
)

// Authenticator markers, matched against the expanded chain source.
var (
	sensorAuthMarkers = []string{"AuthenticateSource", "V2Observe("}
	adminAuthMarkers  = []string{"AdminAuthMiddleware"}
	tenantMarkers     = []string{"buildTokenTenantMiddlewares", "TenantContext("}
	scimAuthMarkers   = []string{"scimAuth", "SCIMAuth"}
	deprecatedMarkers = []string{"Deprecated("}
)

// Vocabulary is the closed set of action verbs (api-conventions.md §4.1).
var Vocabulary = map[string]bool{
	"enable": true, "disable": true, "approve": true, "reject": true,
	"cancel": true, "retry": true, "run": true, "test": true, "verify": true,
	"preview": true, "apply": true, "sync": true, "import": true, "export": true,
	"resolve": true, "reopen": true, "suspend": true, "reactivate": true,
	"revoke": true, "rotate": true, "claim": true, "release": true,
	"start": true, "complete": true, "fail": true, "commit": true,
}

// Synonyms are verbs that duplicate a vocabulary word.
var Synonyms = map[string]string{"activate": "enable", "deactivate": "disable", "acknowledge": "claim"}

// actionWords recognizes a segment as a verb (vocabulary, synonyms and other
// verbs seen in routes) so it can be held to the action rules.
var actionWords = map[string]bool{
	"assign": true, "unassign": true, "accept": true, "decline": true, "resend": true,
	"refresh": true, "regenerate": true, "renew": true, "reset": true, "recalculate": true,
	"validate": true, "check": true, "clone": true, "duplicate": true, "merge": true,
	"dismiss": true, "archive": true, "restore": true, "upload": true, "download": true,
	"generate": true, "evaluate": true, "enrich": true, "classify": true, "triage": true,
	"snooze": true, "toggle": true, "trigger": true, "rebaseline": true, "execute": true,
	"rerun": true, "mark": true, "read": true, "link": true, "unlink": true, "rescan": true,
	"stop": true, "pause": true, "resume": true, "login": true, "logout": true,
	"register": true, "confirm": true, "send": true, "compare": true, "reconcile": true,
	"promote": true, "submit": true, "close": true, "escalate": true, "ack": true,
}

func isAction(seg string) bool {
	if Vocabulary[seg] || Synonyms[seg] != "" || actionWords[seg] {
		return true
	}
	first, _, found := strings.Cut(seg, "-")
	return found && !strings.HasSuffix(seg, "s") && (Vocabulary[first] || Synonyms[first] != "" || actionWords[first])
}

// readActions are action-looking segments a GET may use, because they name a
// read: the export or download of a document, a preview, a comparison.
var readActions = map[string]bool{"export": true, "download": true, "preview": true, "compare": true}

// Singular segments that may precede a path parameter.
var singularOK = map[string]bool{"data": true, "metadata": true, "evidence": true, "settings": true, "status": true}

var tenantParams = map[string]bool{"tenant": true, "tenant_id": true, "tenantId": true, "org": true, "organization_id": true}

var secretParams = map[string]bool{"token": true, "secret": true, "password": true, "passphrase": true, "api_key": true}

func contains(s string, markers []string) bool {
	for _, m := range markers {
		if strings.Contains(s, m) {
			return true
		}
	}
	return false
}

func segments(path string) []string {
	var out []string
	for _, s := range strings.Split(path, "/") {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

func isParam(seg string) bool { return strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}") }

// Check applies the rules to every route.
func Check(routes []Route) []Violation {
	c := checker{preferred: preferredNames(routes)}
	for _, r := range routes {
		c.route(r)
	}
	// One line per (rule, route): a route can break a rule twice.
	seen := map[string]bool{}
	var uniq []Violation
	for _, v := range c.vs {
		if !seen[v.Key()] {
			seen[v.Key()] = true
			uniq = append(uniq, v)
		}
	}
	sort.Slice(uniq, func(i, j int) bool { return uniq[i].Key() < uniq[j].Key() })
	return uniq
}

// preferredNames maps each collection to the parameter name most routes use
// for it (R3: one collection, one parameter name).
func preferredNames(routes []Route) map[string]string {
	names := map[string]map[string]int{}
	for _, r := range routes {
		s := segments(r.Path)
		for i := 1; i < len(s); i++ {
			if isParam(s[i]) && !isParam(s[i-1]) {
				if names[s[i-1]] == nil {
					names[s[i-1]] = map[string]int{}
				}
				names[s[i-1]][s[i]]++
			}
		}
	}
	preferred := map[string]string{}
	for coll, m := range names {
		best := ""
		for n, c := range m {
			if best == "" || c > m[best] || (c == m[best] && n < best) {
				best = n
			}
		}
		preferred[coll] = best
	}
	return preferred
}

type checker struct {
	preferred map[string]string
	vs        []Violation
}

func (c *checker) add(r Route, rule, format string, args ...any) {
	c.vs = append(c.vs, Violation{Rule: rule, Method: r.Method, Path: r.Path, Msg: fmt.Sprintf(format, args...)})
}

func (c *checker) route(r Route) {
	rule, ok := plane.Of(r.Path)
	if !ok {
		c.add(r, "R1", "path matches no plane in routes/plane")
		return
	}
	c.authenticator(r, rule.Plane)

	s := segments(r.Path)
	body := s
	if len(s) >= 2 && s[0] == "api" && versionRe.MatchString(s[1]) {
		body = s[2:]
	}
	nParams := 0
	for i, seg := range s {
		if isParam(seg) {
			nParams++
			c.param(r, rule.Plane, s, i)
			continue
		}
		c.segment(r, rule.Plane, s, i)
	}
	if nParams > 3 || len(body) > 6 {
		c.add(r, "R8", "%d parameters, %d segments after the version (max 3 and 6)", nParams, len(body))
	}
	if rule.Closed && !contains(r.Chain, deprecatedMarkers) {
		c.add(r, "R9", "route under closed prefix %s without a deprecation marker (successor %s)", rule.Prefix, rule.Successor)
	}
}

// authenticator is R1: the route's authenticator matches its plane.
func (c *checker) authenticator(r Route, pl plane.Plane) {
	sensorAuth := contains(r.Chain, sensorAuthMarkers)
	switch {
	case pl == plane.Sensor && !sensorAuth:
		c.add(r, "R1", "sensor-plane route without the sensor authenticator")
	case pl != plane.Sensor && sensorAuth:
		c.add(r, "R1", "sensor authenticator on a %s-plane route", pl)
	}
	if contains(r.Chain, adminAuthMarkers) && pl != plane.Admin {
		c.add(r, "R1", "admin authenticator on a %s-plane route", pl)
	}
	if contains(r.Chain, scimAuthMarkers) && pl != plane.SCIM {
		c.add(r, "R1", "SCIM authenticator on a %s-plane route", pl)
	}
	if contains(r.Chain, tenantMarkers) && pl != plane.User && pl != plane.Self && pl != plane.Auth {
		c.add(r, "R1", "tenant chain on a %s-plane route", pl)
	}
}

// param is R3 (names), R6 (tenant selector) and R7 (secrets).
func (c *checker) param(r Route, pl plane.Plane, s []string, i int) {
	seg := s[i]
	name := strings.Trim(seg, "{}")
	if !paramRe.MatchString(name) {
		c.add(r, "R3", "path parameter {%s} is not snake_case", name)
	}
	if i > 0 && !isParam(s[i-1]) && c.preferred[s[i-1]] != seg {
		c.add(r, "R3", "%s is addressed as %s here and as %s elsewhere", s[i-1], seg, c.preferred[s[i-1]])
	}
	if tenantParams[name] && pl != plane.Admin && pl != plane.Auth && pl != plane.Inbound {
		c.add(r, "R6", "tenant selector {%s} in the path; the tenant comes from the credential", name)
	}
	if secretParams[name] {
		c.add(r, "R7", "secret {%s} in the URL path", name)
	}
}

// segment is R2 (case), R4 (plural collections) and R5 (actions).
func (c *checker) segment(r Route, pl plane.Plane, s []string, i int) {
	seg := s[i]
	if pl == plane.SCIM {
		return // RFC 7644 fixes these names
	}
	if !segmentRe.MatchString(seg) && seg != "openapi.yaml" {
		c.add(r, "R2", "segment %q is not lowercase kebab-case", seg)
	}
	// Auth-plane paths follow the protocols they implement (OAuth, SAML,
	// OIDC): their segments are not collections or actions.
	if pl == plane.Auth || i < 2 {
		return
	}
	if i+1 < len(s) && isParam(s[i+1]) && !strings.HasSuffix(seg, "s") && !singularOK[seg] {
		c.add(r, "R4", "collection %q before a parameter is not plural", seg)
	}
	if isAction(seg) {
		c.action(r, seg, i == len(s)-1)
	}
}

// action is R5: actions are POST, last, in the vocabulary, without synonyms.
func (c *checker) action(r Route, seg string, last bool) {
	switch {
	case r.Method == "GET" && readActions[seg]:
	case r.Method == "GET":
		c.add(r, "R5", "GET on action segment %q (reads use a noun resource)", seg)
	case r.Method != "POST":
		c.add(r, "R5", "%s on action segment %q (actions are POST)", r.Method, seg)
	case !last:
		c.add(r, "R5", "action segment %q is not the last segment", seg)
	}
	if syn := Synonyms[seg]; syn != "" {
		c.add(r, "R5", "action %q duplicates %q", seg, syn)
	} else if !Vocabulary[seg] && r.Method == "POST" && last {
		c.add(r, "R5", "action %q is not in the vocabulary", seg)
	}
}

// Baseline reads the frozen violation list (blank lines and # comments are
// ignored).
func Baseline(path string) (map[string]bool, error) {
	data, err := os.ReadFile(path) //nolint:gosec // repo-local path from the caller
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if len(strings.Fields(line)) != 3 {
			return nil, fmt.Errorf("malformed baseline line %q: want 'RULE METHOD /path'", line)
		}
		out[line] = true
	}
	return out, nil
}
