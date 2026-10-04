// Package tenantsql finds SQL statements in the Postgres repositories that
// select, update or delete a row of a tenant-scoped table by its primary key
// alone (`WHERE id = $1`, `WHERE id = ANY($1)`) with no `tenant_id`
// predicate.
//
// Such a statement is only safe while every caller checks the tenant after
// the fact. One forgetful handler turns it into a cross-tenant IDOR, so a new
// one must either carry the tenant predicate or be an explicitly named
// platform method (`...Unscoped`, `...ForPlatform`) that the allowlist
// records with a reason.
//
// The check works on the Go source, not on a database:
//
//   - The tenant-scoped tables are the base tables that have a tenant_id
//     column. They are listed in tenant_tables.txt, which a DB-backed test
//     regenerates and checks against the migrated schema.
//   - Each function in the repository package is evaluated statement by
//     statement: string literals, package constants and variables, local
//     variables built with := / = / +=, and fmt.Sprintf formats are folded
//     into the SQL text that reaches the driver.
//   - A statement is flagged when it names a tenant-scoped table as its
//     target, has an `id = $n` / `id = ANY($n)` predicate on that table,
//     and mentions tenant_id nowhere.
package tenantsql

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

// Finding is one tenantless statement, keyed by file and function.
type Finding struct {
	File  string // base name, e.g. "integration_repository.go"
	Func  string // "Type.Method" or "func"
	Table string
	Line  int
	SQL   string
}

// Key is the allowlist key: file:Func:table.
func (f Finding) Key() string { return f.File + ":" + f.Func + ":" + f.Table }

var (
	// The statement's target table: the first FROM / UPDATE / DELETE FROM.
	reTarget = regexp.MustCompile(`(?is)\b(?:delete\s+from|update|from)\s+(?:only\s+)?(?:public\.)?"?([a-z_][a-z0-9_]*)"?(?:\s+(?:as\s+)?([a-z_][a-z0-9_]*))?`)
	// An id predicate: optional alias, the bare column `id`, then = $n or = ANY($n).
	reIDPred = regexp.MustCompile(`(?is)(?:\bwhere|\band)\s+(?:([a-z_][a-z0-9_]*)\.)?id\s*=\s*(?:\$\d+|any\s*\(\s*\$\d+)`)
	// A tenant predicate, not a tenant_id in the column list.
	reTenantID = regexp.MustCompile(`(?is)\btenant_id\s*(?:=|<>|!=|\bin\b|\bis\s+(?:not\s+)?(?:distinct\b|null\b))|(?:=|\bin\s*\()\s*(?:[a-z_][a-z0-9_]*\.)?tenant_id\b`)
	reVerbs    = regexp.MustCompile(`(?i)^\s*(?:with\b|select\b|update\b|delete\b)`)
)

// sqlKeywords are words reTarget may capture as an alias that are not one.
var sqlKeywords = map[string]bool{
	"where": true, "set": true, "join": true, "left": true, "inner": true, "right": true,
	"on": true, "using": true, "returning": true, "order": true, "group": true, "limit": true,
	"for": true, "full": true, "cross": true, "natural": true, "lateral": true, "having": true,
	"union": true, "offset": true, "window": true,
}

// LoadTenantTables reads the generated tenant-table list (one table per
// line, # comments allowed).
func LoadTenantTables(path string) (map[string]bool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, l := range strings.Split(string(b), "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		out[l] = true
	}
	return out, nil
}

// Scan parses every non-test Go file in dir and returns the tenantless
// statements on tables in tenantTables.
func Scan(dir string, tenantTables map[string]bool) ([]Finding, error) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, func(fi os.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		return nil, err
	}
	var out []Finding
	for _, pkg := range pkgs {
		globals, funcs := packageStrings(pkg)
		for path, f := range pkg.Files {
			base := filepath.Base(path)
			for _, d := range f.Decls {
				if fd, ok := d.(*ast.FuncDecl); ok && fd.Body != nil {
					out = append(out, scanFunc(fset, base, fd, globals, funcs, tenantTables)...)
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key() < out[j].Key() })
	return out, nil
}

// packageStrings collects the package-level constants and variables, and the
// no-argument helpers that return one expression, keyed by name.
func packageStrings(pkg *ast.Package) (globals, funcs map[string]ast.Expr) { //nolint:staticcheck // ast.Package is what parser.ParseDir returns
	globals, funcs = map[string]ast.Expr{}, map[string]ast.Expr{}
	for _, f := range pkg.Files {
		for _, d := range f.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok {
				if r := singleReturn(fd); r != nil {
					funcs[funcName(fd)] = r
				}
				continue
			}
			gd, ok := d.(*ast.GenDecl)
			if !ok || (gd.Tok != token.CONST && gd.Tok != token.VAR) {
				continue
			}
			for _, s := range gd.Specs {
				vs, ok := s.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, n := range vs.Names {
					if i < len(vs.Values) {
						globals[n.Name] = vs.Values[i]
					}
				}
			}
		}
	}
	return globals, funcs
}

// scanFunc returns the tenantless statements of one function, one per table.
func scanFunc(fset *token.FileSet, file string, fd *ast.FuncDecl, globals, funcs map[string]ast.Expr, tenantTables map[string]bool) []Finding {
	name := funcName(fd)
	ev := &evaluator{globals: globals, funcs: funcs, locals: map[string]string{}}
	if fd.Recv != nil && len(fd.Recv.List) > 0 && len(fd.Recv.List[0].Names) > 0 {
		ev.recv = fd.Recv.List[0].Names[0].Name
		ev.recvType = strings.TrimSuffix(name, "."+fd.Name.Name)
	}
	var out []Finding
	seen := map[string]bool{}
	ev.walk(fd.Body, func(sql string, pos token.Pos) {
		for _, tbl := range tenantless(sql, tenantTables) {
			if seen[tbl] {
				continue
			}
			seen[tbl] = true
			out = append(out, Finding{
				File: file, Func: name, Table: tbl,
				Line: fset.Position(pos).Line, SQL: squash(sql),
			})
		}
	})
	return out
}

// tenantless returns the tenant-scoped tables that sql reads or writes by id
// alone.
func tenantless(sql string, tenantTables map[string]bool) []string {
	if !reVerbs.MatchString(sql) || reTenantID.MatchString(sql) {
		return nil
	}
	preds := reIDPred.FindAllStringSubmatch(sql, -1)
	if len(preds) == 0 {
		return nil
	}
	// Map alias -> table for every FROM/UPDATE/DELETE target.
	aliases := map[string]string{}
	var first string
	for _, m := range reTarget.FindAllStringSubmatch(sql, -1) {
		t := strings.ToLower(m[1])
		if first == "" {
			first = t
		}
		aliases[t] = t
		if a := strings.ToLower(m[2]); a != "" && !sqlKeywords[a] {
			aliases[a] = t
		}
	}
	var hits []string
	for _, p := range preds {
		tbl := first
		if a := strings.ToLower(p[1]); a != "" {
			tbl = aliases[a]
		}
		if tbl != "" && tenantTables[tbl] {
			hits = append(hits, tbl)
		}
	}
	return hits
}

func funcName(fd *ast.FuncDecl) string {
	if fd.Recv == nil || len(fd.Recv.List) == 0 {
		return fd.Name.Name
	}
	t := fd.Recv.List[0].Type
	if s, ok := t.(*ast.StarExpr); ok {
		t = s.X
	}
	if ix, ok := t.(*ast.IndexExpr); ok {
		t = ix.X
	}
	if id, ok := t.(*ast.Ident); ok {
		return id.Name + "." + fd.Name.Name
	}
	return fd.Name.Name
}

func squash(s string) string { return strings.Join(strings.Fields(s), " ") }

// evaluator folds string expressions into the SQL text they produce.
type evaluator struct {
	globals  map[string]ast.Expr
	funcs    map[string]ast.Expr // "Type.method" / "func" -> the one returned expression
	recv     string
	recvType string
	locals   map[string]string
	depth    int
}

// walk visits the statements of body in source order, tracking local string
// variables, and reports every string value that is complete SQL.
func (e *evaluator) walk(body ast.Node, report func(string, token.Pos)) {
	ast.Inspect(body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.AssignStmt:
			for i, lhs := range x.Lhs {
				id, ok := lhs.(*ast.Ident)
				if !ok || i >= len(x.Rhs) || len(x.Lhs) != len(x.Rhs) {
					continue
				}
				v, ok := e.eval(x.Rhs[i])
				if !ok {
					continue
				}
				if x.Tok == token.ADD_ASSIGN {
					v = e.locals[id.Name] + v
				}
				e.locals[id.Name] = v
				report(v, x.Pos())
			}
		case *ast.ValueSpec:
			for i, id := range x.Names {
				if i < len(x.Values) {
					if v, ok := e.eval(x.Values[i]); ok {
						e.locals[id.Name] = v
						report(v, x.Pos())
					}
				}
			}
		case *ast.CallExpr:
			for _, a := range x.Args {
				if v, ok := e.eval(a); ok {
					report(v, a.Pos())
				}
			}
		case *ast.ReturnStmt:
			for _, r := range x.Results {
				if v, ok := e.eval(r); ok {
					report(v, r.Pos())
				}
			}
		}
		return true
	})
}

// eval returns the string value of expr when it can be folded.
func (e *evaluator) eval(expr ast.Expr) (string, bool) {
	e.depth++
	defer func() { e.depth-- }()
	if e.depth > 20 {
		return "", false
	}
	switch x := expr.(type) {
	case *ast.BasicLit:
		if x.Kind != token.STRING {
			return "", false
		}
		s, err := strconv.Unquote(x.Value)
		if err != nil {
			return "", false
		}
		return s, true
	case *ast.ParenExpr:
		return e.eval(x.X)
	case *ast.BinaryExpr:
		if x.Op != token.ADD {
			return "", false
		}
		l, lok := e.eval(x.X)
		r, rok := e.eval(x.Y)
		if !lok && !rok {
			return "", false
		}
		return l + r, true
	case *ast.Ident:
		if v, ok := e.locals[x.Name]; ok {
			return v, true
		}
		if g, ok := e.globals[x.Name]; ok {
			return e.eval(g)
		}
		return "", false
	case *ast.CallExpr:
		if id, ok := x.Fun.(*ast.Ident); ok && len(x.Args) == 0 {
			if r, ok := e.funcs[id.Name]; ok {
				return e.eval(r)
			}
			return "", false
		}
		sel, ok := x.Fun.(*ast.SelectorExpr)
		if !ok {
			return "", false
		}
		pkg, _ := sel.X.(*ast.Ident)
		if pkg != nil && e.recv != "" && pkg.Name == e.recv && len(x.Args) == 0 {
			if r, ok := e.funcs[e.recvType+"."+sel.Sel.Name]; ok {
				return e.eval(r)
			}
			return "", false
		}
		if pkg == nil || pkg.Name != "fmt" || sel.Sel.Name != "Sprintf" || len(x.Args) == 0 {
			return "", false
		}
		format, ok := e.eval(x.Args[0])
		if !ok {
			return "", false
		}
		args := make([]any, 0, len(x.Args)-1)
		for _, a := range x.Args[1:] {
			v, _ := e.eval(a)
			args = append(args, v)
		}
		return fmt.Sprintf(strings.NewReplacer("%d", "%v", "%q", "%v").Replace(format), args...), true
	}
	return "", false
}

// singleReturn returns the expression of a function whose body is exactly
// `return <expr>` and that takes no parameters (a query-fragment helper).
func singleReturn(fd *ast.FuncDecl) ast.Expr {
	if fd.Body == nil || len(fd.Body.List) != 1 || fd.Type.Params.NumFields() != 0 {
		return nil
	}
	r, ok := fd.Body.List[0].(*ast.ReturnStmt)
	if !ok || len(r.Results) != 1 {
		return nil
	}
	return r.Results[0]
}
