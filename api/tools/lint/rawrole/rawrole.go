// Package rawrole finds SQL in the Go sources that decides something from the
// raw tenant_members.role label.
//
// A person's team role (owner, admin, member, viewer) is the highest system
// role they hold in user_roles, read through the v_user_effective_role view.
// tenant_members.role is only the label the membership routes and the
// ownership transfer write; the view derives the effective role from it when
// no system role row exists. A query that counts approvers, recipients or
// owners from the raw label can disagree with the gates, which read the view.
//
// The check parses the non-test Go files of one directory tree. It flags a
// string literal that mentions tenant_members and compares or selects a role
// through the table's own alias (no alias, tm, m, mem or tenant_members), for
// example `m.role IN ('owner','admin')` or `role = 'owner'`. Writes
// (`SET role = ...`) and reads through the view (`ver.role`) are fine.
//
// The check is syntactic: SQL assembled at run time from values it cannot see
// is not covered, and a literal is judged as a whole.
package rawrole

import (
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

// Finding is one literal with a raw label read, keyed by file and function.
type Finding struct {
	File string // base name
	Func string // "Type.Method", "func" or "<package>" for a package-level value
	Line int
	SQL  string
}

// Key is the allowlist key: file:Func.
func (f Finding) Key() string { return f.File + ":" + f.Func }

var (
	reTable = regexp.MustCompile(`(?i)\btenant_members\b`)
	// tenant_members tm / tenant_members AS tm: the aliases of the table.
	reAlias = regexp.MustCompile(`(?i)\btenant_members\s+(?:as\s+)?([a-z_][a-z0-9_]*)`)
	// Writes name the column but decide nothing.
	reWrite = regexp.MustCompile(`(?i)(?:\bset|,)\s*role\s*=|\bexcluded\.role\b`)
	// An unqualified role comparison.
	reBare = regexp.MustCompile(`(?i)(?:^|[^.\w])role\s*(?:=|<>|!=|\bnot\s+in\b|\bin\b|\bis\b)`)
)

// notAlias are SQL words reAlias can capture after the table name.
var notAlias = map[string]bool{
	"where": true, "set": true, "join": true, "left": true, "inner": true, "right": true, "on": true,
	"using": true, "for": true, "order": true, "group": true, "limit": true, "cross": true, "full": true,
	"natural": true, "values": true, "returning": true, "select": true, "and": true, "or": true,
}

// Violates reports whether one SQL string reads the raw label of
// tenant_members.
func Violates(sql string) bool {
	if !reTable.MatchString(sql) {
		return false
	}
	names := []string{"tenant_members"}
	for _, m := range reAlias.FindAllStringSubmatch(sql, -1) {
		if a := strings.ToLower(m[1]); !notAlias[a] {
			names = append(names, a)
		}
	}
	sql = reWrite.ReplaceAllString(sql, " ")
	for _, n := range names {
		if regexp.MustCompile(`(?i)\b` + regexp.QuoteMeta(n) + `\.role\b`).MatchString(sql) {
			return true
		}
	}
	return reBare.MatchString(sql)
}

// Scan parses every non-test Go file under dir (recursively) and returns the
// literals that read the raw label.
func Scan(dir string) ([]Finding, error) {
	var paths []string
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(p, ".go") && !strings.HasSuffix(p, "_test.go") {
			paths = append(paths, p)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	fset := token.NewFileSet()
	var out []Finding
	for _, p := range paths {
		f, err := parser.ParseFile(fset, p, nil, 0)
		if err != nil {
			return nil, err
		}
		base := filepath.Base(p)
		for _, d := range f.Decls {
			name := "<package>"
			if fd, ok := d.(*ast.FuncDecl); ok {
				name = funcName(fd)
			}
			ast.Inspect(d, func(n ast.Node) bool {
				lit, ok := n.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				s, err := strconv.Unquote(lit.Value)
				if err != nil || !Violates(s) {
					return true
				}
				out = append(out, Finding{File: base, Func: name, Line: fset.Position(lit.Pos()).Line, SQL: oneLine(s)})
				return true
			})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Key() != out[j].Key() {
			return out[i].Key() < out[j].Key()
		}
		return out[i].Line < out[j].Line
	})
	return out, nil
}

func funcName(fd *ast.FuncDecl) string {
	if fd.Recv == nil || len(fd.Recv.List) == 0 {
		return fd.Name.Name
	}
	t := fd.Recv.List[0].Type
	if s, ok := t.(*ast.StarExpr); ok {
		t = s.X
	}
	if id, ok := t.(*ast.Ident); ok {
		return id.Name + "." + fd.Name.Name
	}
	return fd.Name.Name
}

func oneLine(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 200 {
		s = s[:200] + "..."
	}
	return s
}
