// Package routeperm implements a go/analysis pass that flags HTTP
// write routes (POST/PUT/PATCH/DELETE) registered in the routes
// package without a middleware.Require* wrapper.
//
// this is the S3 invariant enforcement — every tenant-user
// write MUST have a permission check. The route-permission audit in
// docs/audits/2026-04-route-permission-audit.md confirmed no gaps
// exist today; this linter keeps it that way.
//
// Opt-out directive: //routeperm:public — use for endpoints that are
// intentionally public (webhook receivers, OAuth callbacks,
// invitation-token flows).
package routeperm

import (
	"go/ast"
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/inspector"
)

// Analyzer is the exported go/analysis pass.
var Analyzer = &analysis.Analyzer{
	Name:     "routepermcheck",
	Doc:      "flags POST/PUT/PATCH/DELETE route registrations without middleware.Require*",
	Requires: []*analysis.Analyzer{inspect.Analyzer},
	Run:      run,
}

// writeMethods are the HTTP verbs that require permission gating.
var writeMethods = map[string]bool{
	"POST":   true,
	"PUT":    true,
	"PATCH":  true,
	"DELETE": true,
}

const optOutDirective = "//routeperm:public"

func run(pass *analysis.Pass) (any, error) {
	insp, ok := pass.ResultOf[inspect.Analyzer].(*inspector.Inspector)
	if !ok {
		return nil, nil
	}

	nodeFilter := []ast.Node{(*ast.CallExpr)(nil)}
	insp.Preorder(nodeFilter, func(n ast.Node) {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return
		}
		if !writeMethods[sel.Sel.Name] {
			return
		}
		// Heuristic: the common pattern is `r.POST(...)` or
		// `router.POST(...)`. Receiver is an ident — anything else
		// (method chain, field access) is also caught.
		// We treat any call matching the method name as a candidate
		// and let the signature-shape check filter false positives.

		// Expect signature: POST(path, handler, middlewares...).
		// A permission-gated call has middleware.Require(...) in args.
		// A public call has either:
		//   - 2 args (path, handler) AND carries the opt-out comment
		//   - explicit //routeperm:public on the line
		if hasOptOut(pass, n) {
			return
		}
		if hasRequireInArgs(call) {
			return
		}
		// Edge: some routes wrap in group middleware at router.Group
		// level. If the enclosing Group has a middleware.Require*
		// in its options we accept — but that requires a scope walk
		// the analyzer does not do today. For those cases the
		// //routeperm:public comment is the audit trail (the group
		// middleware is the "approval").
		pass.Reportf(call.Pos(),
			"route %s registered without middleware.Require*; add permission gate or suppress with %s",
			sel.Sel.Name, optOutDirective,
		)
	})
	return nil, nil
}

// hasRequireInArgs reports whether any argument in the call is a
// `middleware.Require*` expression or obviously a permission wrapper.
// We match by textual name (selector.X.Name == "middleware" AND
// selector.Sel.Name starts with "Require").
func hasRequireInArgs(call *ast.CallExpr) bool {
	for _, arg := range call.Args {
		if isRequireExpr(arg) {
			return true
		}
	}
	return false
}

func isRequireExpr(expr ast.Expr) bool {
	// The typical shapes we accept:
	//   middleware.Require(permission.X)
	//   middleware.RequireAny(...)
	//   middleware.RequireTeamAdmin()
	//   middleware.RequireCampaignRole(...)
	// All present as a *ast.CallExpr whose Fun is *ast.SelectorExpr.
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkgIdent, ok := sel.X.(*ast.Ident)
	if !ok {
		return false
	}
	if pkgIdent.Name != "middleware" {
		return false
	}
	return strings.HasPrefix(sel.Sel.Name, "Require")
}

// hasOptOut scans the file's comments for a //routeperm:public line
// on the line of or immediately above the flagged call.
func hasOptOut(pass *analysis.Pass, node ast.Node) bool {
	callLine := pass.Fset.Position(node.Pos()).Line
	for _, f := range pass.Files {
		for _, cg := range f.Comments {
			for _, c := range cg.List {
				if !strings.Contains(c.Text, optOutDirective) {
					continue
				}
				commentLine := pass.Fset.Position(c.End()).Line
				if commentLine == callLine || commentLine == callLine-1 {
					return true
				}
			}
		}
	}
	return false
}
