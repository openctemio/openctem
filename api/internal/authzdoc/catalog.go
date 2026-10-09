package authzdoc

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// DataSurface is how a route relates to the caller's data scope, as
// classified in the data-surface registry
// (tests/unit/route_scope_classification_test.go, dataSurfaceRegistry).
type DataSurface struct {
	Class string `json:"class"`
	Note  string `json:"note,omitempty"`
}

// DataScopeClasses explains each class in plain words.
var DataScopeClasses = map[string]string{
	"scoped":   "Rows come from assets and are limited to the caller's data scope; another asset by id answers 404.",
	"partial":  "Rows are limited to the data scope; some counts or summaries are organization-wide by design.",
	"gap":      "Asset-derived data not yet limited to the data scope (tracked).",
	"separate": "Another access model decides (for example pentest campaign membership).",
	"config":   "Organization configuration or administration, not asset data; the permission alone decides.",
	"system":   "Authentication, the caller's own data, machine protocols, catalogs or public endpoints.",
}

const dataSurfaceFile = "tests/unit/route_scope_classification_test.go"

// fileStringConsts maps the string constants declared in one file.
func fileStringConsts(f *ast.File) map[string]string {
	out := map[string]string{}
	ast.Inspect(f, func(n ast.Node) bool {
		vs, ok := n.(*ast.ValueSpec)
		if !ok {
			return true
		}
		for i, name := range vs.Names {
			if i >= len(vs.Values) {
				continue
			}
			if lit, ok := vs.Values[i].(*ast.BasicLit); ok && lit.Kind == token.STRING {
				if v, err := strconv.Unquote(lit.Value); err == nil {
					out[name.Name] = v
				}
			}
		}
		return true
	})
	return out
}

// dataSurfaceEntry reads one registry entry: "key": {classX, "note"}.
func dataSurfaceEntry(elt ast.Expr, classes map[string]string) (string, DataSurface, bool) {
	kv, ok := elt.(*ast.KeyValueExpr)
	if !ok {
		return "", DataSurface{}, false
	}
	kl, ok := kv.Key.(*ast.BasicLit)
	if !ok {
		return "", DataSurface{}, false
	}
	key, err := strconv.Unquote(kl.Value)
	vl, ok := kv.Value.(*ast.CompositeLit)
	if err != nil || !ok || len(vl.Elts) == 0 {
		return "", DataSurface{}, false
	}
	var ds DataSurface
	if id, ok := vl.Elts[0].(*ast.Ident); ok {
		ds.Class = classes[id.Name]
	}
	if len(vl.Elts) > 1 {
		if nl, ok := vl.Elts[1].(*ast.BasicLit); ok {
			ds.Note, _ = strconv.Unquote(nl.Value)
		}
	}
	return key, ds, true
}

// loadDataSurfaces reads dataSurfaceRegistry from its source file. The
// registry stays where route authors already maintain it; this reads it, so
// nothing is copied.
func loadDataSurfaces(apiRoot string) (map[string]DataSurface, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filepath.Join(apiRoot, dataSurfaceFile), nil, 0)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", dataSurfaceFile, err)
	}
	classes := fileStringConsts(f)
	out := map[string]DataSurface{}
	ast.Inspect(f, func(n ast.Node) bool {
		vs, ok := n.(*ast.ValueSpec)
		if !ok || len(vs.Names) != 1 || vs.Names[0].Name != "dataSurfaceRegistry" || len(vs.Values) != 1 {
			return true
		}
		if cl, ok := vs.Values[0].(*ast.CompositeLit); ok {
			for _, elt := range cl.Elts {
				if key, ds, ok := dataSurfaceEntry(elt, classes); ok {
					out[key] = ds
				}
			}
		}
		return false
	})
	if len(out) < 50 {
		return nil, fmt.Errorf("read only %d data-surface entries from %s", len(out), dataSurfaceFile)
	}
	return out, nil
}

// lookupDataSurface mirrors the registry's own lookup: the longest matching
// path prefix wins, a method-specific key beats a generic one, and a key
// ending in "$" matches its path exactly.
func lookupDataSurface(reg map[string]DataSurface, method, path string) (DataSurface, bool) {
	bestKey, bestLen, bestMethod := "", -1, false
	var found DataSurface
	for key, s := range reg {
		prefix, specific := key, false
		if m, rest, ok := strings.Cut(key, " "); ok {
			if m != method {
				continue
			}
			prefix, specific = rest, true
		}
		if exact, ok := strings.CutSuffix(prefix, "$"); ok {
			if path != exact {
				continue
			}
			prefix = exact
		} else if !strings.HasPrefix(path, prefix) {
			continue
		}
		if len(prefix) > bestLen || (len(prefix) == bestLen && specific && !bestMethod) {
			bestKey, bestLen, bestMethod, found = key, len(prefix), specific, s
		}
	}
	return found, bestKey != ""
}

// PermissionInfo describes one permission of the catalog.
type PermissionInfo struct {
	ID          string `json:"id"`
	Module      string `json:"module"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	AdminOnly   bool   `json:"admin_only,omitempty"`
}

// seedRow matches a permissions seed row: ('id', 'module', 'Name', 'Description'.
var seedRow = regexp.MustCompile(`\(\s*'([a-z][a-z0-9_]*(?::[a-z0-9_]+)+)'\s*,\s*'([a-z0-9_.]*)'\s*,\s*'((?:[^']|'')*)'\s*,\s*'((?:[^']|'')*)'`)

// loadPermissionText reads the names and descriptions the seed migrations
// give each permission (later migrations win).
func loadPermissionText(apiRoot string) (map[string]PermissionInfo, error) {
	dir := filepath.Join(apiRoot, "migrations")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".up.sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	out := map[string]PermissionInfo{}
	for _, n := range names {
		b, err := os.ReadFile(filepath.Join(dir, n)) //nolint:gosec // the repository's own migrations
		if err != nil {
			return nil, err
		}
		s := string(b)
		if !strings.Contains(s, "permissions") {
			continue
		}
		for _, m := range seedRow.FindAllStringSubmatch(s, -1) {
			out[m[1]] = PermissionInfo{
				ID: m[1], Module: m[2],
				Name:        strings.ReplaceAll(m[3], "''", "'"),
				Description: strings.ReplaceAll(m[4], "''", "'"),
			}
		}
	}
	return out, nil
}
