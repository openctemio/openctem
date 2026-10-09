package authzdoc

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
)

const authzCoverageFile = "tests/unit/route_authz_coverage_test.go"

// allowlist is why a route carries no permission gate, as the authz coverage
// gate records it (routeAuthzAllowlist and allowlistPrefixes).
type allowlist struct {
	exact    map[string]string // "METHOD /path" -> reason
	prefixes [][2]string       // prefix, reason
}

func (a allowlist) reason(method, path string) string {
	if r, ok := a.exact[method+" "+path]; ok {
		return r
	}
	best, reason := -1, ""
	for _, p := range a.prefixes {
		if strings.HasPrefix(path, p[0]) && len(p[0]) > best {
			best, reason = len(p[0]), p[1]
		}
	}
	return reason
}

func loadAllowlist(apiRoot string) (allowlist, error) {
	a := allowlist{exact: map[string]string{}}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filepath.Join(apiRoot, authzCoverageFile), nil, 0)
	if err != nil {
		return a, fmt.Errorf("parse %s: %w", authzCoverageFile, err)
	}
	str := func(e ast.Expr) string {
		if bl, ok := e.(*ast.BasicLit); ok && bl.Kind == token.STRING {
			s, _ := strconv.Unquote(bl.Value)
			return s
		}
		return ""
	}
	ast.Inspect(f, func(n ast.Node) bool {
		vs, ok := n.(*ast.ValueSpec)
		if !ok || len(vs.Names) != 1 || len(vs.Values) != 1 {
			return true
		}
		cl, ok := vs.Values[0].(*ast.CompositeLit)
		if !ok {
			return true
		}
		switch vs.Names[0].Name {
		case "routeAuthzAllowlist":
			for _, e := range cl.Elts {
				if kv, ok := e.(*ast.KeyValueExpr); ok {
					a.exact[str(kv.Key)] = str(kv.Value)
				}
			}
		case "allowlistPrefixes":
			for _, e := range cl.Elts {
				if c, ok := e.(*ast.CompositeLit); ok && len(c.Elts) == 2 {
					a.prefixes = append(a.prefixes, [2]string{str(c.Elts[0]), str(c.Elts[1])})
				}
			}
		}
		return false
	})
	if len(a.prefixes) < 5 {
		return a, fmt.Errorf("read only %d allowlist prefixes from %s", len(a.prefixes), authzCoverageFile)
	}
	return a, nil
}
