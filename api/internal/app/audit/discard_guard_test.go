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
var auditWriteName = regexp.MustCompile(`^(LogEvent|Log[A-Z]\w*|RecordAudit)$`)

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
		ast.Inspect(f, func(n ast.Node) bool {
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
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok && auditWriteName.MatchString(sel.Sel.Name) {
				offenders = append(offenders, fset.Position(as.Pos()).String())
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(offenders) > 0 {
		t.Fatalf("audit write error discarded (use audit.RecordOrWarn or return it):\n%s", strings.Join(offenders, "\n"))
	}
}
