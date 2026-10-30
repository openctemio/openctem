// Package errleak finds Go code that puts server-only text into what a
// person reads: error response messages, domain error messages handlers pass
// through, and the stored status text of integrations, scans and jobs.
//
// A message a person sees names the thing and says what to do. It never
// carries an entity id, the text of a lower error (SQL, network, an upstream
// body) or an internal name. pkg/apierror cleans every response message as a
// last net (safe.go); this check keeps new code from relying on that net.
// Design: research/258 (error message hygiene), described in
// docs/architecture/error-responses.md.
//
// Rules (syntactic, on non-test files):
//
//	echo       an apierror constructor's message contains err.Error() or
//	           formats an error value
//	id-message an apierror constructor's message formats an id
//	wrap-id    fmt.Errorf wraps an exported sentinel (shared.ErrValidation,
//	           finding.ErrNotFound, ...) and formats an id: handlers echo
//	           that text
//	wrap-err   fmt.Errorf wraps an exported sentinel and formats a lower
//	           error
//	domain-id  shared.NewDomainError's message formats an id
//	status     a stored status or failure text (SetError, Fail, ...) is
//	           built from an error's text
//	audit-id   an audit event's message (WithMessage) formats an id: the
//	           audit log shows it; the resource name and id are fields
//	raw-json   a JSON map in the HTTP layer carries err.Error() under
//	           "message", "error", "detail" or "reason"
//
// Today's findings are a shrink-only baseline (baseline.txt).
package errleak

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

// Finding is one call that leaks.
type Finding struct {
	Rule string
	File string // relative to the api module, slash-separated
	Func string
	Line int
}

// Key groups findings for the baseline: rule path:Func.
func (f Finding) Key() string { return f.Rule + " " + f.File + ":" + f.Func }

// messageArg is the index of the message argument of each apierror
// constructor that takes free text.
var messageArg = map[string]int{
	"BadRequest": 0, "Forbidden": 0, "Unauthorized": 0, "Conflict": 0, "NotFound": 0,
	"ModuleNotEnabled": 0, "QueryTimeout": 0, "ServiceUnavailable": 0, "BadGateway": 0,
	"TooManyRequests": 0, "InternalServerError": 0, "ValidationFailed": 0, "New": 2, "Wrap": 3,
}

// statusSetters store a failure text that a later read shows.
var statusSetters = map[string]bool{
	"SetError": true, "SetLastError": true, "SetStatusMessage": true, "SetErrorMessage": true,
	"SetSyncError": true, "SetFailure": true, "Fail": true, "MarkFailed": true, "SetFailed": true,
	"RecordFailure": true,
}

var (
	idName  = regexp.MustCompile(`^(id|ids|uuid|ID|IDs)$|[a-z0-9](ID|Id|IDs|Ids)$`)
	errName = regexp.MustCompile(`^(err|e|cause)$|^err[A-Z0-9]\w*$|[a-z]Err$`)
	jsonKey = map[string]bool{"message": true, "error": true, "detail": true, "reason": true}
)

// Scan parses every non-test Go file under dir and returns the findings,
// with paths relative to the parent of dir.
func Scan(dir string) ([]Finding, error) {
	root := filepath.Dir(filepath.Clean(dir))
	var out []Finding
	fset := token.NewFileSet()
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if n := d.Name(); n == "testdata" || n == "mocks" || n == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, p, nil, 0)
		if perr != nil {
			return perr
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		out = append(out, scanFile(fset, f, rel)...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Key() != out[j].Key() {
			return out[i].Key() < out[j].Key()
		}
		return out[i].Line < out[j].Line
	})
	return out, nil
}

const (
	fnErrorf  = "Errorf"
	fnSprintf = "Sprintf"
	pkgFmt    = "fmt"
)

func scanFile(fset *token.FileSet, f *ast.File, rel string) []Finding {
	var out []Finding
	inHTTP := strings.Contains(rel, "/infra/http/")
	for _, d := range f.Decls {
		fn := "<package>"
		if fd, ok := d.(*ast.FuncDecl); ok {
			fn = funcName(fd)
		}
		add := func(rule string, n ast.Node) {
			out = append(out, Finding{Rule: rule, File: rel, Func: fn, Line: fset.Position(n.Pos()).Line})
		}
		ast.Inspect(d, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.CallExpr:
				if rule := callRule(x, f.Name.Name == "shared"); rule != "" {
					add(rule, x)
				}
			case *ast.KeyValueExpr:
				if inHTTP && isRawJSONErr(x) {
					add("raw-json", x)
				}
			}
			return true
		})
	}
	return out
}

// callRule is the rule a call breaks, or "".
func callRule(x *ast.CallExpr, isShared bool) string {
	pkg, name := callee(x)
	switch {
	case pkg == "apierror":
		if i, ok := messageArg[name]; ok && i < len(x.Args) {
			if hasErrText(x.Args[i]) {
				return "echo"
			}
			if formatsID(x.Args[i]) {
				return "id-message"
			}
		}
	case pkg == pkgFmt && name == fnErrorf:
		if wrapsPublic(x, isShared) {
			args := x.Args[1:]
			if anyArg(args, isIDExpr) {
				return "wrap-id"
			}
			if countErrArgs(args) > 0 {
				return "wrap-err"
			}
		}
	case name == "NewDomainError" && (pkg == "shared" || isShared && pkg == ""):
		if len(x.Args) >= 2 && formatsID(x.Args[1]) {
			return "domain-id"
		}
	case name == "WithMessage" && len(x.Args) == 1:
		if _, isSel := x.Fun.(*ast.SelectorExpr); isSel && formatsID(x.Args[0]) {
			return "audit-id"
		}
	case statusSetters[name] && pkg != pkgFmt && pkg != "apierror":
		if _, isSel := x.Fun.(*ast.SelectorExpr); isSel && anyArg(x.Args, hasErrText) {
			return "status"
		}
	}
	return ""
}

// isRawJSONErr is a "message"/"error"/"detail"/"reason" key whose value is
// err.Error().
func isRawJSONErr(x *ast.KeyValueExpr) bool {
	k, ok := x.Key.(*ast.BasicLit)
	if !ok || k.Kind != token.STRING {
		return false
	}
	s, _ := strconv.Unquote(k.Value)
	return jsonKey[s] && isErrorCall(x.Value)
}

// callee returns the package (or receiver) name and function of a call.
func callee(c *ast.CallExpr) (string, string) {
	switch f := c.Fun.(type) {
	case *ast.SelectorExpr:
		if id, ok := f.X.(*ast.Ident); ok {
			return id.Name, f.Sel.Name
		}
		return "?", f.Sel.Name
	case *ast.Ident:
		return "", f.Name
	}
	return "?", ""
}

// isErrorCall is x.Error() with no arguments.
func isErrorCall(e ast.Expr) bool {
	c, ok := e.(*ast.CallExpr)
	if !ok || len(c.Args) != 0 {
		return false
	}
	s, ok := c.Fun.(*ast.SelectorExpr)
	return ok && s.Sel.Name == "Error"
}

// hasErrText reports whether an expression puts an error's text into a
// string: err.Error() anywhere in it, or an error value formatted by
// fmt.Sprintf / fmt.Errorf.
func hasErrText(e ast.Expr) bool {
	found := false
	ast.Inspect(e, func(n ast.Node) bool {
		if found {
			return false
		}
		c, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if isErrorCall(c) {
			found = true
			return false
		}
		if pkg, name := callee(c); pkg == pkgFmt && (name == fnSprintf || name == fnErrorf) && len(c.Args) > 1 {
			if countErrArgs(c.Args[1:]) > 0 {
				found = true
				return false
			}
		}
		// A helper that is passed the error decides the text itself
		// (a reviewed public-message mapper): not followed.
		return true
	})
	return found
}

// formatsID reports whether an expression formats an id into a string.
func formatsID(e ast.Expr) bool {
	found := false
	ast.Inspect(e, func(n ast.Node) bool {
		if found {
			return false
		}
		c, ok := n.(*ast.CallExpr)
		if !ok {
			if b, ok := n.(*ast.BinaryExpr); ok && b.Op == token.ADD && (isIDExpr(b.X) || isIDExpr(b.Y)) {
				found = true
			}
			return !found
		}
		if pkg, name := callee(c); pkg == pkgFmt && (name == fnSprintf || name == fnErrorf) && len(c.Args) > 1 {
			if anyArg(c.Args[1:], isIDExpr) {
				found = true
				return false
			}
		}
		return true
	})
	return found
}

// isIDExpr is an expression that is an entity id: x.ID(), x.ID().String(),
// an identifier or field named like an id (tenantID, req.FindingID, ids).
func isIDExpr(e ast.Expr) bool {
	switch x := e.(type) {
	case *ast.Ident:
		return idName.MatchString(x.Name)
	case *ast.SelectorExpr:
		return idName.MatchString(x.Sel.Name)
	case *ast.CallExpr:
		s, ok := x.Fun.(*ast.SelectorExpr)
		if !ok || len(x.Args) != 0 {
			return false
		}
		if s.Sel.Name == "ID" || idName.MatchString(s.Sel.Name) {
			return true
		}
		if s.Sel.Name == "String" {
			return isIDExpr(s.X)
		}
	case *ast.StarExpr:
		return isIDExpr(x.X)
	}
	return false
}

func isErrExpr(e ast.Expr) bool {
	switch x := e.(type) {
	case *ast.Ident:
		return errName.MatchString(x.Name)
	case *ast.SelectorExpr:
		return errName.MatchString(x.Sel.Name)
	case *ast.CallExpr:
		return isErrorCall(x)
	}
	return false
}

func countErrArgs(args []ast.Expr) int {
	n := 0
	for _, a := range args {
		if isErrExpr(a) {
			n++
		}
	}
	return n
}

func anyArg(args []ast.Expr, pred func(ast.Expr) bool) bool {
	for _, a := range args {
		if pred(a) {
			return true
		}
	}
	return false
}

// wrapsPublic reports whether fmt.Errorf wraps an exported sentinel
// (shared.ErrValidation, finding.ErrNotFound, ErrSomething in the same
// package). Domain sentinels wrap the shared ones, and the handlers' mappers
// send the whole wrapped text as the message.
func wrapsPublic(c *ast.CallExpr, _ bool) bool {
	lit, ok := c.Args[0].(*ast.BasicLit)
	if !ok || !strings.Contains(lit.Value, "%w") {
		return false
	}
	for _, a := range c.Args[1:] {
		switch x := a.(type) {
		case *ast.SelectorExpr:
			if _, ok := x.X.(*ast.Ident); ok && isSentinelName(x.Sel.Name) {
				return true
			}
		case *ast.Ident:
			if isSentinelName(x.Name) {
				return true
			}
		}
	}
	return false
}

func isSentinelName(n string) bool {
	return len(n) > 3 && strings.HasPrefix(n, "Err") && n[3] >= 'A' && n[3] <= 'Z'
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
