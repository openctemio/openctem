package audit_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// auditWriteName matches the methods that write an audit row: LogEvent, the
// typed AuditService.Log* helpers and the suppression rule audit.
var auditWriteName = regexp.MustCompile(`^(LogEvent|Log[A-Z]\w*|RecordAudit|tenantEvent|adminEvent)$`)

// notAuditWrite lists Log* methods that return no error (they log a failure
// themselves), so a bare call is not a discard. Each entry needs its reason.
var notAuditWrite = map[string]string{
	"LogSessionRevoked": "returns nothing; logs a failed write itself (AuthService)",
	"LogAuditEvent":     "returns nothing; logs a failed write itself (TenantService)",
}

// logsItself are the support access helpers that log a failed audit write and
// return the error: `_ = s.tenantEvent(...)` is a deliberate decision there (an
// action that must proceed, or a refusal), but a bare call is a slip.
var logsItself = regexp.MustCompile(`^(tenantEvent|adminEvent)$`)

// TestNoDiscardedAuditWrite fails when production code throws away the error
// of an audit write (`_ = svc.LogEvent(...)`). Use audit.RecordOrWarn for an
// action that already took effect, or return the error when the action must not
// happen without its audit row.
func TestNoDiscardedAuditWrite(t *testing.T) {
	root := filepath.Join("..", "..", "..") // api/
	fset := token.NewFileSet()
	var offenders []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case "vendor", "node_modules", ".git":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return perr
		}
		offenders = append(offenders, discardedAuditWrites(fset, f)...)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(offenders) > 0 {
		t.Fatalf("audit write error discarded (use audit.RecordOrWarn or return it):\n%s", strings.Join(offenders, "\n"))
	}
}

func isAuditWrite(name string) bool {
	if _, skip := notAuditWrite[name]; skip {
		return false
	}
	return auditWriteName.MatchString(name)
}

// discardedAuditWrites returns the positions in f where the error of an audit
// write is dropped.
func discardedAuditWrites(fset *token.FileSet, f *ast.File) []string {
	var out []string
	ast.Inspect(f, func(n ast.Node) bool {
		// A bare call statement, `go x.LogEvent(...)` or `defer
		// x.LogEvent(...)` discards the error just the same.
		var bare *ast.CallExpr
		switch st := n.(type) {
		case *ast.ExprStmt:
			bare, _ = st.X.(*ast.CallExpr)
		case *ast.GoStmt:
			bare = st.Call
		case *ast.DeferStmt:
			bare = st.Call
		}
		if bare != nil {
			if sel, ok := bare.Fun.(*ast.SelectorExpr); ok && isAuditWrite(sel.Sel.Name) {
				out = append(out, fset.Position(n.Pos()).String())
			}
			return true
		}
		as, ok := n.(*ast.AssignStmt)
		if !ok || len(as.Rhs) != 1 {
			return true
		}
		for _, l := range as.Lhs {
			if id, ok := l.(*ast.Ident); !ok || id.Name != "_" {
				return true
			}
		}
		call, ok := as.Rhs[0].(*ast.CallExpr)
		if !ok {
			return true
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok && isAuditWrite(sel.Sel.Name) && !logsItself.MatchString(sel.Sel.Name) {
			out = append(out, fset.Position(as.Pos()).String())
		}
		return true
	})
	return out
}

func TestDiscardGuardFlagsEveryShape(t *testing.T) {
	src := `package p
func f() {
	_ = a.LogEvent()
	a.LogEvent()
	go a.LogEvent()
	defer a.RecordAudit()
	a.tenantEvent()
	_ = a.tenantEvent()
	a.LogSessionRevoked()
	if err := a.LogEvent(); err != nil {}
}`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "x.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	got := discardedAuditWrites(fset, f)
	// lines: 3 (_ =), 4 (bare), 5 (go), 6 (defer), 7 (bare helper)
	if len(got) != 5 {
		t.Fatalf("flagged %d, want 5: %v", len(got), got)
	}
}
