// Package getbyid implements a go/analysis pass that flags repository
// methods named GetByID / DeleteByID / UpdateByID that do NOT accept a
// tenantID parameter. It is meant to run over internal/infra/postgres/*
// in CI so the audit pattern from F-309 cannot regress.
//
// Accepted signatures (no diagnostic):
//
//	func (r *FooRepository) GetByID(ctx context.Context, tenantID shared.ID, id shared.ID) (...)
//	func (r *FooRepository) GetByTenantAndID(ctx context.Context, tenantID, id shared.ID) (...)
//
// Flagged signature (diagnostic):
//
//	func (r *FooRepository) GetByID(ctx context.Context, id shared.ID) (...)
//
// A method can opt out by adding the directive `//getbyid:unsafe` on the
// line immediately above its declaration — this makes the exception
// grep-able and reviewable.
package getbyid

import (
	"go/ast"
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/inspector"
)

// Analyzer is the exported go/analysis pass.
var Analyzer = &analysis.Analyzer{
	Name:     "getbyidtenant",
	Doc:      "flags repository GetByID/DeleteByID/UpdateByID methods missing a tenantID parameter",
	Requires: []*analysis.Analyzer{inspect.Analyzer},
	Run:      run,
}

// Analyzer result type uses `any` to align with newer go/analysis idioms.
var _ any = Analyzer

// flaggedNames is the set of method names that must take a tenant arg.
var flaggedNames = map[string]bool{
	"GetByID":    true,
	"UpdateByID": true,
	"DeleteByID": true,
}

const optOutDirective = "//getbyid:unsafe"

func run(pass *analysis.Pass) (any, error) {
	insp, ok := pass.ResultOf[inspect.Analyzer].(*inspector.Inspector)
	if !ok {
		return nil, nil
	}

	nodeFilter := []ast.Node{(*ast.FuncDecl)(nil)}
	insp.Preorder(nodeFilter, func(n ast.Node) {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Recv == nil || fn.Name == nil {
			return
		}
		if !flaggedNames[fn.Name.Name] {
			return
		}

		// Skip if caller opted out with a leading //getbyid:unsafe comment.
		if hasOptOut(pass, fn) {
			return
		}

		if hasTenantParam(fn) {
			return
		}

		pass.Reportf(fn.Pos(),
			"%s has no tenantID parameter — cross-tenant IDOR risk if wired to a user-facing handler. Add a GetByTenantAndID variant or suppress with %s",
			fn.Name.Name, optOutDirective,
		)
	})
	return nil, nil
}

// hasTenantParam returns true when the function's parameter list contains
// a parameter whose name contains "tenant" (case-insensitive). We match
// by name rather than type to tolerate typedef'd IDs (shared.ID,
// integration.ID, etc.) across the codebase.
func hasTenantParam(fn *ast.FuncDecl) bool {
	if fn.Type == nil || fn.Type.Params == nil {
		return false
	}
	for _, field := range fn.Type.Params.List {
		for _, name := range field.Names {
			if strings.Contains(strings.ToLower(name.Name), "tenant") {
				return true
			}
		}
	}
	return false
}

// hasOptOut looks for a //getbyid:unsafe directive in the doc comment or
// on the line immediately above the declaration.
func hasOptOut(pass *analysis.Pass, fn *ast.FuncDecl) bool {
	if fn.Doc != nil {
		for _, c := range fn.Doc.List {
			if strings.Contains(c.Text, optOutDirective) {
				return true
			}
		}
	}
	// Scan the file's comments for a standalone line above the function.
	for _, cg := range pass.Files[fileIndexFor(pass, fn)].Comments {
		for _, c := range cg.List {
			if strings.Contains(c.Text, optOutDirective) {
				// Accept if the comment ends on the same line as the
				// function's declaration or the line immediately above.
				commentEnd := pass.Fset.Position(c.End()).Line
				declStart := pass.Fset.Position(fn.Pos()).Line
				if commentEnd == declStart-1 || commentEnd == declStart {
					return true
				}
			}
		}
	}
	return false
}

func fileIndexFor(pass *analysis.Pass, node ast.Node) int {
	pos := pass.Fset.Position(node.Pos()).Filename
	for i, f := range pass.Files {
		if pass.Fset.Position(f.Pos()).Filename == pos {
			return i
		}
	}
	return 0
}
