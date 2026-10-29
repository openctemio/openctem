package postgres_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// The platform console's identity tables are written only by the console role
// (DB_ADMIN_USER); the API's app role reads admin_users and nothing else of
// them (deploy/postgres/least-privilege-roles.sql, section 8), so a SQL
// injection in the tenant plane cannot forge an administrator, a console
// session or an approval. A repository that touches those tables must run on
// the console pool, or the statement fails with 42501 in production while
// every single-role environment (dev, UAT, the default CI run) stays green.
//
// TestConsoleTables_OnlyConsolePoolRepositories reads the role grants from the
// script itself and fails when SQL in this package reads a table the app role
// cannot read, or writes or locks one it cannot write, outside the
// repositories listed in consolePoolRepos. TestConsoleTables_ConsolePoolWiring
// proves those repositories are built on the console pool in cmd/server.

// consolePoolRepos are the receiver types built on the console pool
// (cmd/server: Repositories.UseAdminDB and adminDBOf).
var consolePoolRepos = map[string]string{
	"AdminRepository":         "NewAdminRepository",
	"AdminConsoleRepository":  "NewAdminConsoleRepository",
	"PlatformIdPRepository":   "NewPlatformIdPRepository",
	"AdminSessionDirectory":   "NewAdminSessionDirectory",
	"AdminApprovalRepository": "NewAdminApprovalRepository",
	"PlatformRoleRepository":  "NewPlatformRoleRepository",
	"AdminFactorRepository":   "NewAdminFactorRepository",
}

// consoleFactorTables are the console's second factors. Write access to any of
// them is an administrator takeover (plant a passkey or a known recovery
// code), so the app role must neither read nor write them.
var consoleFactorTables = []string{"admin_webauthn_credentials", "admin_recovery_codes", "admin_webauthn_ceremonies"}

// consolePoolHelpers are package-level SQL constants and free functions used
// only by the repositories above.
var consolePoolHelpers = map[string]bool{
	"localSuperAdminsSQL": true, // withRosterGuard, AdminRepository only
}

const rolesScript = "../../../deploy/postgres/least-privilege-roles.sql"

// appRevoked returns the tables whose privilege the script revokes from the
// app role: "SELECT" (no read at all) and "WRITE" (no INSERT/UPDATE/DELETE).
func appRevoked(t *testing.T) (noRead, noWrite []string) {
	t.Helper()
	raw, err := os.ReadFile(rolesScript)
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	list := func(stmt string) []string {
		re := regexp.MustCompile(regexp.QuoteMeta(stmt) + `\s*FROM unnest\(ARRAY\[([^\]]*)\]\)`)
		m := re.FindStringSubmatch(src)
		if m == nil {
			t.Fatalf("%s: no %q statement; update this guard with the script", rolesScript, stmt)
		}
		var out []string
		for _, f := range strings.Split(m[1], ",") {
			out = append(out, strings.Trim(strings.TrimSpace(f), "'"))
		}
		return out
	}
	noRead = list(`SELECT format('REVOKE SELECT ON public.%I FROM %I', t, :'app_user')`)
	noWrite = list(`SELECT format('REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON public.%I FROM %I', t, :'app_user')`)
	if len(noRead) < 5 || len(noWrite) <= len(noRead) {
		t.Fatalf("unexpected revoke lists: read %v write %v", noRead, noWrite)
	}
	return noRead, noWrite
}

type sqlLiteral struct {
	owner string // receiver type, function or package-level name
	pos   token.Position
	text  string
}

// literals returns every string literal of the package's non-test files with
// the declaration it sits in.
func literals(t *testing.T) []sqlLiteral {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var out []sqlLiteral
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range f.Decls {
			owner := ""
			switch d := decl.(type) {
			case *ast.FuncDecl:
				owner = d.Name.Name
				if d.Recv != nil && len(d.Recv.List) == 1 {
					typ := d.Recv.List[0].Type
					if star, ok := typ.(*ast.StarExpr); ok {
						typ = star.X
					}
					if id, ok := typ.(*ast.Ident); ok {
						owner = id.Name
					}
				}
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					if vs, ok := spec.(*ast.ValueSpec); ok && len(vs.Names) > 0 {
						owner = vs.Names[0].Name
					}
				}
			}
			ast.Inspect(decl, func(n ast.Node) bool {
				lit, ok := n.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				s, err := strconv.Unquote(lit.Value)
				if err != nil {
					return true
				}
				out = append(out, sqlLiteral{owner: owner, pos: fset.Position(lit.Pos()), text: s})
				return true
			})
		}
	}
	return out
}

// TestConsoleTables_FactorTablesRevokedFromApp proves the script takes every
// privilege on the console's second factors from the app role, so the guard
// below covers them.
func TestConsoleTables_FactorTablesRevokedFromApp(t *testing.T) {
	noRead, noWrite := appRevoked(t)
	for _, tbl := range consoleFactorTables {
		r, w := slices.Contains(noRead, tbl), slices.Contains(noWrite, tbl)
		if !r || !w {
			t.Errorf("%s: %s must be in both app revoke lists (read %v, write %v)", rolesScript, tbl, r, w)
		}
	}
}

func TestConsoleTables_OnlyConsolePoolRepositories(t *testing.T) {
	noRead, noWrite := appRevoked(t)
	type rule struct {
		re   *regexp.Regexp
		what string
	}
	var rules []rule
	for _, tbl := range noRead {
		q := regexp.QuoteMeta(tbl)
		rules = append(rules, rule{regexp.MustCompile(`(?i)\b(FROM|JOIN|INTO|UPDATE|TABLE|USING)\s+(public\.)?` + q + `\b`),
			"reads or writes " + tbl + ", which the app role cannot read"})
	}
	for _, tbl := range noWrite {
		q := regexp.QuoteMeta(tbl)
		rules = append(rules,
			rule{regexp.MustCompile(`(?i)\b(INSERT\s+INTO|UPDATE|DELETE\s+FROM|TRUNCATE(\s+TABLE)?)\s+(public\.)?` + q + `\b`),
				"writes " + tbl + ", which the app role cannot write"},
			rule{regexp.MustCompile(`(?is)\bFROM\s+(public\.)?` + q + `\b[^;]*\bFOR\s+(UPDATE|NO\s+KEY\s+UPDATE|SHARE|KEY\s+SHARE)\s*(NOWAIT|SKIP|\)|;|$)`),
				// A lock clause without OF locks every table of the query.
				"row-locks " + tbl + " (needs UPDATE), which the app role cannot write"})
	}
	var bad []string
	for _, lit := range literals(t) {
		if _, ok := consolePoolRepos[lit.owner]; ok || consolePoolHelpers[lit.owner] {
			continue
		}
		for _, r := range rules {
			if r.re.MatchString(lit.text) {
				bad = append(bad, lit.pos.String()+" ("+lit.owner+"): "+r.what)
			}
		}
	}
	sort.Strings(bad)
	if len(bad) > 0 {
		t.Fatalf("SQL on the app pool touches the console's identity tables; it fails with 42501 under the "+
			"least-privilege roles. Move it to a console-pool repository, or read through a narrow SECURITY DEFINER "+
			"function (see admin_session_live):\n  %s", strings.Join(bad, "\n  "))
	}
}

// TestConsoleTables_ConsolePoolWiring proves every console-pool repository is
// built on the console pool: with adminDB or adminDBOf(...), or (in
// newRepositories) with the app pool and rebuilt on adminDB by UseAdminDB,
// which the server calls at start.
func TestConsoleTables_ConsolePoolWiring(t *testing.T) {
	ctors := map[string]bool{}
	for _, c := range consolePoolRepos {
		ctors[c] = true
	}
	files, err := filepath.Glob("../../../cmd/server/*.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("cmd/server sources: %v", err)
	}
	fset := token.NewFileSet()
	rebuilt := map[string]bool{} // constructors UseAdminDB calls with adminDB
	usesAdminDB := false
	type call struct {
		ctor, arg, fn string
		pos           token.Position
	}
	var calls []call
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range f.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				ce, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := ce.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if sel.Sel.Name == "UseAdminDB" && fd.Recv == nil {
					usesAdminDB = true
				}
				pkg, ok := sel.X.(*ast.Ident)
				if !ok || pkg.Name != "postgres" || !ctors[sel.Sel.Name] || len(ce.Args) == 0 {
					return true
				}
				arg := ""
				switch a := ce.Args[0].(type) {
				case *ast.Ident:
					arg = a.Name
				case *ast.CallExpr:
					if id, ok := a.Fun.(*ast.Ident); ok {
						arg = id.Name + "()"
					}
				}
				if fd.Name.Name == "UseAdminDB" && arg == "adminDB" {
					rebuilt[sel.Sel.Name] = true
				}
				calls = append(calls, call{sel.Sel.Name, arg, fd.Name.Name, fset.Position(ce.Pos())})
				return true
			})
		}
	}
	if !usesAdminDB {
		t.Fatal("the server no longer calls repos.UseAdminDB: the console repositories would stay on the app pool")
	}
	var bad []string
	for _, c := range calls {
		switch {
		case c.arg == "adminDB" || c.arg == "adminDBOf()":
		case c.fn == "newRepositories" && rebuilt[c.ctor]:
		default:
			bad = append(bad, c.pos.String()+": postgres."+c.ctor+"("+c.arg+") in "+c.fn)
		}
	}
	if len(calls) == 0 {
		t.Fatal("found no console-pool repository construction in cmd/server; update this guard")
	}
	if len(bad) > 0 {
		t.Fatalf("console-pool repositories built on the app pool (use adminDBOf(repos, db) or rebuild in UseAdminDB):\n  %s",
			strings.Join(bad, "\n  "))
	}
}
