package scope

// Guard: no write path to scope entries or exclusions bypasses the job
// signer's ledger hook (RFC-040 §5.6, docs/architecture/job-signing.md
// "Scope ledger"). A new path that changes what authorizes probes must go
// through commitEntry / commitExclusion / CommitEntries, or be listed below
// with the reason it cannot change the ledger.
//
// The check is syntactic and has three parts:
//  1. every SQL statement in the module that writes scope_targets or
//     scope_exclusions lives in a known repository method;
//  2. every call of those repository writes from the application services
//     (this package and bountyprogram) is inside the save function handed to
//     the hook, or is allowlisted with a reason;
//  3. the repositories are constructed and handed out only at known wiring
//     sites, so no other service gets a writer.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// moduleRoot is the api module directory.
func moduleRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("no caller")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", ".."))
}

type goFile struct {
	rel  string
	fset *token.FileSet
	file *ast.File
}

// parseTree parses every non-test Go file under the given module
// directories.
func parseTree(t *testing.T, root string, dirs ...string) []goFile {
	t.Helper()
	var out []goFile
	for _, d := range dirs {
		base := filepath.Join(root, d)
		if _, err := os.Stat(base); err != nil {
			continue
		}
		err := filepath.WalkDir(base, func(path string, de fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if de.IsDir() {
				if n := de.Name(); n == "testdata" || n == "vendor" || n == "node_modules" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			fset := token.NewFileSet()
			f, perr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
			if perr != nil {
				return perr
			}
			rel, _ := filepath.Rel(root, path)
			out = append(out, goFile{rel: filepath.ToSlash(rel), fset: fset, file: f})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return out
}

// funcName is "Recv.Name" or "Name" for a declaration.
func funcName(fd *ast.FuncDecl) string {
	if fd.Recv == nil || len(fd.Recv.List) == 0 {
		return fd.Name.Name
	}
	typ := fd.Recv.List[0].Type
	if st, ok := typ.(*ast.StarExpr); ok {
		typ = st.X
	}
	if id, ok := typ.(*ast.Ident); ok {
		return id.Name + "." + fd.Name.Name
	}
	return fd.Name.Name
}

var scopeWriteSQL = regexp.MustCompile(`(?is)\b(insert\s+into|update|delete\s+from)\s+scope_(targets|exclusions)\b`)

// TestLedgerGuard_SQLWritersAreKnown: part 1.
func TestLedgerGuard_SQLWritersAreKnown(t *testing.T) {
	known := map[string]bool{
		"internal/infra/postgres/scope_target_repository.go:ScopeTargetRepository.Create": true,
		// Shared INSERT of Create and the bounty Import / ReplaceScope (all three
		// known); TestLedgerGuard_InsertHelperCallers pins its callers.
		"internal/infra/postgres/scope_target_repository.go:insertScopeTarget":                  true,
		"internal/infra/postgres/scope_target_repository.go:ScopeTargetRepository.Update":       true,
		"internal/infra/postgres/scope_target_repository.go:ScopeTargetRepository.Delete":       true,
		"internal/infra/postgres/scope_target_repository.go:ScopeTargetRepository.ExpireOld":    true,
		"internal/infra/postgres/scope_exclusion_repository.go:ScopeExclusionRepository.Create": true,
		"internal/infra/postgres/scope_exclusion_repository.go:ScopeExclusionRepository.Update": true,
		"internal/infra/postgres/scope_exclusion_repository.go:ScopeExclusionRepository.Delete": true,
		// Time-based: the ledger holds the same expiry and drops it itself.
		"internal/infra/postgres/scope_exclusion_repository.go:ScopeExclusionRepository.ExpireOld": true,
		// Path exclusions only (web testing mode); not ledger exclusions.
		"internal/infra/postgres/scope_exclusion_repository.go:ScopeExclusionRepository.SetTesting": true,
		"internal/infra/postgres/bounty_program_repository.go:BountyProgramRepository.Import":       true,
		"internal/infra/postgres/bounty_program_repository.go:BountyProgramRepository.ReplaceScope": true,
		"internal/infra/postgres/bounty_program_repository.go:BountyProgramRepository.SetStatus":    true,
		// Only approval_reminded_at of a pending entry (RFC-054 §12.2): a
		// reminder never changes what authorizes probes.
		"internal/infra/postgres/scope_target_repository.go:ScopeTargetRepository.MarkReminded": true,
		// Only attestation_requested_at of an active t2 entry (RFC-054 §12.5):
		// asking for a confirmation changes nothing that authorizes probes.
		"internal/infra/postgres/scope_attestation_repository.go:ScopeTargetRepository.MarkAttestationRequested": true,
		// The t2 -> t1 downgrade (a narrowing); called only inside commitEntry
		// (scope.Service.downgradeUnattested).
		"internal/infra/postgres/scope_attestation_repository.go:ScopeTargetRepository.DowngradeUnattested": true,
	}
	root := moduleRoot(t)
	var unknown []string
	for _, gf := range parseTree(t, root, "internal", "pkg", "cmd") {
		for _, decl := range gf.file.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			key := gf.rel + ":" + funcName(fd)
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				lit, ok := n.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				s, err := strconv.Unquote(lit.Value)
				if err != nil {
					s = lit.Value
				}
				if scopeWriteSQL.MatchString(s) && !known[key] {
					unknown = append(unknown, key+" ("+gf.fset.Position(lit.Pos()).String()+")")
				}
				return true
			})
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		t.Fatalf("SQL writing scope_targets / scope_exclusions outside the known repository methods; route the write "+
			"through scope.Service (commitEntry / commitExclusion / CommitEntries) and add the method here with a reason:\n  %s",
			strings.Join(unknown, "\n  "))
	}
}

// hookFuncs are the ledger hook and its thin wrappers: a repository write
// inside a function literal passed to one of them goes through the hook.
var hookFuncs = map[string]bool{
	"commitEntry": true, "commitExclusion": true, "commitLedger": true, "CommitEntries": true,
	"commit": true, // bountyprogram.Service.commit → CommitEntries
}

// repoWrite reports whether call is a write on a scope repository field
// (receiver text ending in a known field name) and returns its label.
func repoWrite(call *ast.CallExpr) (string, bool) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return "", false
	}
	recv, ok := sel.X.(*ast.SelectorExpr)
	if !ok {
		return "", false
	}
	writes := map[string]map[string]bool{
		"targetRepo":    {"Create": true, "Update": true, "Delete": true, "ExpireOld": true},
		"exclusionRepo": {"Create": true, "Update": true, "Delete": true, "ExpireOld": true, "SetTesting": true},
		"repo":          {"Import": true, "ReplaceScope": true, "SetStatus": true}, // bountyprogram
	}
	if m, ok := writes[recv.Sel.Name]; ok && m[sel.Sel.Name] {
		return recv.Sel.Name + "." + sel.Sel.Name, true
	}
	return "", false
}

// TestLedgerGuard_ServiceWritesGoThroughTheHook: part 2.
func TestLedgerGuard_ServiceWritesGoThroughTheHook(t *testing.T) {
	// Writes that cannot change the ledger, with the reason.
	allowed := map[string]string{
		"internal/app/scope/entries.go:Service.RejectTarget targetRepo.Update":              "a pending entry is declined: it was never in effect",
		"internal/app/scope/service.go:Service.CreateExclusion exclusionRepo.Create":        "a new exclusion is pending until approved (ApproveExclusion goes through the hook)",
		"internal/app/scope/service.go:Service.RejectExclusion exclusionRepo.Update":        "a pending exclusion is declined: it never excluded anything",
		"internal/app/scope/service.go:Service.ExpireOldExclusions exclusionRepo.ExpireOld": "time-based: the ledger holds the same expiry",
	}
	root := moduleRoot(t)
	var bad []string
	hooked := 0
	for _, gf := range parseTree(t, root, "internal/app/scope", "internal/app/bountyprogram") {
		if gf.rel == "internal/app/scope/web.go" {
			// ChangeExclusionTesting: path exclusions (web testing mode) are not
			// ledger exclusions (ledgerExclusionType).
			continue
		}
		for _, decl := range gf.file.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			name := funcName(fd)
			var stack []ast.Node
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				if n == nil {
					stack = stack[:len(stack)-1]
					return true
				}
				stack = append(stack, n)
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				label, ok := repoWrite(call)
				if !ok {
					return true
				}
				if insideHook(stack) {
					hooked++
					return true
				}
				key := gf.rel + ":" + name + " " + label
				if _, ok := allowed[key]; ok {
					return true
				}
				bad = append(bad, key+" ("+gf.fset.Position(call.Pos()).String()+")")
				return true
			})
		}
	}
	// Not vacuous: a renamed repository field or hook would match nothing.
	if hooked < 10 {
		t.Fatalf("only %d scope repository writes found inside the ledger hook; the guard no longer recognizes them", hooked)
	}
	if len(bad) > 0 {
		sort.Strings(bad)
		t.Fatalf("scope repository writes outside the ledger hook; wrap the write in commitEntry / commitExclusion / "+
			"CommitEntries, or allowlist it here with the reason it cannot change what authorizes probes:\n  %s",
			strings.Join(bad, "\n  "))
	}
}

// insideHook reports whether the innermost node of stack sits in a function
// literal that is an argument of a hook call.
func insideHook(stack []ast.Node) bool {
	for i := len(stack) - 1; i > 0; i-- {
		lit, ok := stack[i].(*ast.FuncLit)
		if !ok {
			continue
		}
		call, ok := stack[i-1].(*ast.CallExpr)
		if !ok {
			continue
		}
		var name string
		switch f := call.Fun.(type) {
		case *ast.SelectorExpr:
			name = f.Sel.Name
		case *ast.Ident:
			name = f.Name
		}
		if !hookFuncs[name] {
			continue
		}
		for _, a := range call.Args {
			if a == lit {
				return true
			}
		}
	}
	return false
}

// TestLedgerGuard_RepositoriesHandedOutOnlyAtKnownSites: part 3.
func TestLedgerGuard_RepositoriesHandedOutOnlyAtKnownSites(t *testing.T) {
	ctors := map[string]bool{"NewScopeTargetRepository": true, "NewScopeExclusionRepository": true, "NewBountyProgramRepository": true}
	fields := map[string]bool{"ScopeTarget": true, "ScopeExcl": true}
	known := map[string]bool{
		"cmd/server/repositories.go NewScopeTargetRepository":    true,
		"cmd/server/repositories.go NewScopeExclusionRepository": true,
		// Read-only export of the scope in effect (ledger bootstrap).
		"cmd/server/signer_ledger_export.go NewScopeTargetRepository":                   true,
		"cmd/server/signer_ledger_export.go NewScopeExclusionRepository":                true,
		"cmd/server/services.go NewBountyProgramRepository":                             true,
		"internal/infra/postgres/bounty_program_repository.go NewScopeTargetRepository": true,
		// scope.NewService, CertMonitor.SetDomainSources (reads verified
		// domains' entries), the data-expiration controller (time-based
		// ExpireOld, see part 2).
		"cmd/server/services.go ScopeTarget": true,
		"cmd/server/services.go ScopeExcl":   true,
		"cmd/server/workers.go ScopeTarget":  true,
		"cmd/server/workers.go ScopeExcl":    true,
	}
	root := moduleRoot(t)
	seen := map[string]int{}
	var bad []string
	for _, gf := range parseTree(t, root, "internal", "pkg", "cmd") {
		ast.Inspect(gf.file, func(n ast.Node) bool {
			var name string
			switch x := n.(type) {
			case *ast.CallExpr:
				switch f := x.Fun.(type) {
				case *ast.SelectorExpr:
					name = f.Sel.Name
				case *ast.Ident:
					name = f.Name
				}
				if !ctors[name] {
					return true
				}
			case *ast.SelectorExpr:
				if !fields[x.Sel.Name] {
					return true
				}
				name = x.Sel.Name
			default:
				return true
			}
			key := gf.rel + " " + name
			if strings.HasPrefix(gf.rel, "cmd/server/repositories.go") && fields[name] {
				return true // the struct literal that defines them
			}
			seen[key]++
			if !known[key] {
				bad = append(bad, key+" ("+gf.fset.Position(n.Pos()).String()+")")
			}
			return true
		})
	}
	if len(bad) > 0 {
		sort.Strings(bad)
		t.Fatalf("a scope repository is constructed or handed out at a new site; a service holding it could write scope "+
			"around the ledger hook. Use scope.Service instead, or add the site here with a reason:\n  %s",
			strings.Join(bad, "\n  "))
	}
}

// TestLedgerGuard_InsertHelperCallers: the shared INSERT helper is called
// only from the known repository writers (part 1 lists it as one).
func TestLedgerGuard_InsertHelperCallers(t *testing.T) {
	known := map[string]bool{
		"internal/infra/postgres/scope_target_repository.go:ScopeTargetRepository.Create":           true,
		"internal/infra/postgres/bounty_program_repository.go:BountyProgramRepository.Import":       true,
		"internal/infra/postgres/bounty_program_repository.go:BountyProgramRepository.ReplaceScope": true,
	}
	root := moduleRoot(t)
	var bad []string
	for _, gf := range parseTree(t, root, "internal", "pkg", "cmd") {
		for _, decl := range gf.file.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			key := gf.rel + ":" + funcName(fd)
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "insertScopeTarget" && !known[key] {
					bad = append(bad, key+" ("+gf.fset.Position(call.Pos()).String()+")")
				}
				return true
			})
		}
	}
	if len(bad) > 0 {
		sort.Strings(bad)
		t.Fatalf("insertScopeTarget called outside the known repository writers:\n  %s", strings.Join(bad, "\n  "))
	}
}
