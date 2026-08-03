package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"

	_ "github.com/lib/pq"

	"github.com/openctemio/api/pkg/domain/module"
)

// Module catalog parity — the Go catalog vs the `modules` table.
//
// Everything a tenant can actually reach is enumerated from the DATABASE:
// ModuleService.getTenantDisabledModules iterates ModuleRepository
// .ListActiveModules() (`WHERE is_active = TRUE`) and decides enablement from
// those rows. Go's catalog — CoreModuleIDs / UserFacingModuleIDs /
// ModulePermissionMapping, the preset bundles in presets.go, the module IDs
// wired into ModuleGate.RequireModule — is only ever the *intent*.
//
// Nothing used to compare the two. TestPresetsReferenceKnownModules checks
// presets.go against the same three Go maps, i.e. code against code; the
// migration seed was never an input to any test. So adding a module in code
// and forgetting the migration row failed nowhere: the module simply never
// appears in ListActiveModules, cannot be enabled by the bundle a tenant
// subscribed to, and is invisible to the gate — silently, at runtime, in
// production.
//
// These tests close that loop. CI applies migrations/ to the test database
// before `go test` (see .github/workflows/ci.yml), so the seed is the oracle.
//
// Direction matters: the database legitimately holds MORE rows than the Go
// maps. UserFacingModuleIDs is deliberately sidebar-visible-only — its own
// comment excludes agents/tools/pipelines because toggling them has no sidebar
// effect. So DB ⊋ code is expected and never asserted; only code ⊆ DB is.

// catalogRow is one row of the `modules` table. Column names verified
// against migrations 000004 (create) and 000077 (is_core): the table has
// is_active, is_core, release_status and parent_module_id — there is no
// is_enabled_by_default.
type catalogRow struct {
	isActive      bool
	isCore        bool
	releaseStatus string
	parentID      string // "" when parent_module_id IS NULL
}

// openModuleCatalogDB connects to the migrated test database, following the
// same skip-unless-DATABASE_URL convention as the other *_db_test.go files.
func openModuleCatalogDB(t *testing.T) *sql.DB {
	t.Helper()

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping module catalog parity check")
	}

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Skipf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	if err := db.PingContext(context.Background()); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}
	return db
}

// loadModuleCatalog reads every row of `modules` keyed by ID.
func loadModuleCatalog(t *testing.T, db *sql.DB) map[string]catalogRow {
	t.Helper()

	rows, err := db.QueryContext(context.Background(),
		`SELECT id, is_active, is_core, release_status, COALESCE(parent_module_id, '') FROM modules`)
	if err != nil {
		t.Fatalf("query modules: %v", err)
	}
	defer func() { _ = rows.Close() }()

	out := make(map[string]catalogRow)
	for rows.Next() {
		var id string
		var r catalogRow
		if err := rows.Scan(&id, &r.isActive, &r.isCore, &r.releaseStatus, &r.parentID); err != nil {
			t.Fatalf("scan modules row: %v", err)
		}
		out[id] = r
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate modules: %v", err)
	}

	// A guard that reads an empty table passes everything. That is the failure
	// mode this whole file exists to prevent, so refuse to run.
	if len(out) == 0 {
		t.Fatal("`modules` table is empty — the migration seed was not applied to DATABASE_URL, " +
			"so this parity guard would pass vacuously. Apply migrations/ before running the tests.")
	}
	return out
}

// requireDerivedNonEmpty fails when a set derived from source comes back empty.
// Every check below is of the form "for each X, assert ...", which is trivially
// true for an empty X — so an export rename, a moved file or a parser that
// stops matching would turn the guard green instead of red.
func requireDerivedNonEmpty(t *testing.T, what string, n int) {
	t.Helper()
	if n == 0 {
		t.Fatalf("derived %s set is empty, so this parity check would pass vacuously.\n"+
			"Something changed shape (a renamed export, a moved file, a call form the parser "+
			"no longer recognizes). Fix the derivation — do not delete this guard.", what)
	}
}

// failMissing reports absent module IDs with the remedy attached. Whoever trips
// this is adding a feature, not studying the module system, so the message has
// to carry the fix.
func failMissing(t *testing.T, requirement string, missing map[string][]string) {
	t.Helper()
	if len(missing) == 0 {
		return
	}

	ids := make([]string, 0, len(missing))
	for id := range missing {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	var b strings.Builder
	fmt.Fprintf(&b, "%d module ID(s) %s:\n", len(ids), requirement)
	for _, id := range ids {
		refs := missing[id]
		sort.Strings(refs)
		fmt.Fprintf(&b, "  - %-32s referenced by: %s\n", id, strings.Join(refs, ", "))
	}
	b.WriteString("\nWhy this matters: tenant module resolution enumerates the DATABASE " +
		"(ModuleRepository.ListActiveModules, `WHERE is_active = TRUE`). A module that exists " +
		"only in Go can never be enabled, gated or shown — it is invisible at runtime, with no error.\n")
	b.WriteString("\nFIX: add a migration under migrations/ that seeds the row(s):\n\n" +
		"  INSERT INTO modules (id, slug, name, description, category, display_order,\n" +
		"                       is_active, is_core, release_status, parent_module_id)\n" +
		"  VALUES ('my_module', 'my-module', 'My Module', '...', 'settings', 0,\n" +
		"          TRUE, FALSE, 'released', NULL)\n" +
		"  ON CONFLICT (id) DO NOTHING;\n\n" +
		"For a sub-module ID containing a '.', use the parent ID as parent_module_id " +
		"(e.g. 'integrations.siem' -> parent_module_id 'integrations').\n" +
		"If instead the ID is a typo or the module was retired, fix/remove the Go reference.")

	t.Fatal(b.String())
}

// -----------------------------------------------------------------------------
// Derivations from source
// -----------------------------------------------------------------------------

// repoRoot walks up from this test file until it finds go.mod.
func repoRoot(t *testing.T) string {
	t.Helper()

	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed; cannot locate the repository root")
	}
	dir := filepath.Dir(thisFile)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("no go.mod found above %s", filepath.Dir(thisFile))
		}
		dir = parent
	}
}

// moduleIDConstants maps every string constant declared in pkg/domain/module to
// its value, e.g. "ModulePentest" -> "pentest". RequireModule is called with
// those constants rather than literals, so resolving them is what lets the gate
// list be derived instead of hardcoded.
func moduleIDConstants(t *testing.T, root string) map[string]string {
	t.Helper()

	dir := filepath.Join(root, "pkg", "domain", "module")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}

	fset := token.NewFileSet()
	out := make(map[string]string)
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, perr := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if perr != nil {
			t.Fatalf("parse %s: %v", filepath.Join(dir, name), perr)
		}
		for _, decl := range file.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				continue
			}
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, ident := range vs.Names {
					if i >= len(vs.Values) {
						continue
					}
					lit, ok := vs.Values[i].(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						continue
					}
					v, uerr := strconv.Unquote(lit.Value)
					if uerr != nil {
						continue
					}
					out[ident.Name] = v
				}
			}
		}
	}
	return out
}

// gatedModuleIDs finds every module ID passed to ModuleGate.RequireModule
// anywhere under internal/, mapping it to the call sites. Derived from the
// source on purpose: hardcoding today's seven would leave the eighth — the one
// added next month by someone who never read this file — unguarded.
func gatedModuleIDs(t *testing.T, root string) map[string][]string {
	t.Helper()

	consts := moduleIDConstants(t, root)
	if len(consts) == 0 {
		t.Fatal("no string constants found in pkg/domain/module; RequireModule arguments cannot be resolved")
	}

	out := make(map[string][]string)
	fset := token.NewFileSet()

	walkErr := filepath.WalkDir(filepath.Join(root, "internal"), func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		// Test files call RequireModule with literals against a stub gate; they
		// are not production wiring.
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}

		file, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return fmt.Errorf("parse %s: %w", path, perr)
		}

		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "RequireModule" || len(call.Args) == 0 {
				return true
			}

			pos := fset.Position(call.Pos())
			site := fmt.Sprintf("%s:%d", mustRel(root, path), pos.Line)

			id, ok := resolveModuleIDArg(call.Args[0], consts)
			if !ok {
				// Never skip quietly: an unrecognized call form is a hole in the
				// guard, not a pass.
				t.Errorf("%s: cannot resolve the RequireModule argument to a module ID.\n"+
					"Pass a string constant from pkg/domain/module (e.g. moduledom.ModulePentest) "+
					"or a string literal, or teach resolveModuleIDArg the new form — "+
					"otherwise this route's module is silently unguarded.", site)
				return true
			}
			out[id] = append(out[id], site)
			return true
		})
		return nil
	})
	if walkErr != nil {
		t.Fatalf("scan internal/ for RequireModule call sites: %v", walkErr)
	}
	return out
}

// resolveModuleIDArg turns a RequireModule argument into its module ID.
func resolveModuleIDArg(arg ast.Expr, consts map[string]string) (string, bool) {
	switch a := arg.(type) {
	case *ast.BasicLit: // RequireModule("pentest")
		if a.Kind != token.STRING {
			return "", false
		}
		v, err := strconv.Unquote(a.Value)
		return v, err == nil
	case *ast.Ident: // RequireModule(ModulePentest) — from inside the module package
		v, ok := consts[a.Name]
		return v, ok
	case *ast.SelectorExpr: // RequireModule(moduledom.ModulePentest)
		v, ok := consts[a.Sel.Name]
		return v, ok
	default:
		return "", false
	}
}

func mustRel(root, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return path
	}
	return rel
}

// presetModuleIDs unions what every bundle in presets.go actually turns on:
// the explicit allow-list plus core, plus the mandatory operational modules,
// plus hard transitive dependencies — exactly what ResolvePresetModules hands
// to bundle resolution at runtime.
func presetModuleIDs() map[string][]string {
	out := make(map[string][]string)
	for i := range module.ModulePresets {
		p := &module.ModulePresets[i]
		for id := range module.ResolvePresetModules(p) {
			out[id] = append(out[id], "preset "+p.ID)
		}
	}
	return out
}

// codeCatalogIDs unions the three static Go maps — the same union
// knownModuleIDs() builds in the module package, which until now was only ever
// compared against other Go code.
func codeCatalogIDs() map[string][]string {
	out := make(map[string][]string)
	for id := range module.CoreModuleIDs {
		out[id] = append(out[id], "CoreModuleIDs")
	}
	for id := range module.UserFacingModuleIDs {
		out[id] = append(out[id], "UserFacingModuleIDs")
	}
	for id := range module.ModulePermissionMapping {
		out[id] = append(out[id], "ModulePermissionMapping")
	}
	return out
}

// -----------------------------------------------------------------------------
// The checks
// -----------------------------------------------------------------------------

// TestModuleCatalog_PresetModulesHaveActiveRows — every module a bundle
// enables must exist and be active. A bundle that references a module the
// database does not serve is a promise the platform cannot keep: bundle
// resolution walks ListActiveModules, so the module is neither enabled nor
// reported as disabled — it just is not there.
func TestModuleCatalog_PresetModulesHaveActiveRows(t *testing.T) {
	db := openModuleCatalogDB(t)
	catalog := loadModuleCatalog(t, db)

	referenced := presetModuleIDs()
	requireDerivedNonEmpty(t, "preset bundle module", len(referenced))

	missing := make(map[string][]string)
	for id, refs := range referenced {
		row, ok := catalog[id]
		if !ok || !row.isActive {
			missing[id] = refs
		}
	}
	failMissing(t, "referenced by a preset bundle in pkg/domain/module/presets.go "+
		"have no ACTIVE row in the `modules` table", missing)
}

// TestModuleCatalog_GatedModulesHaveActiveRows — every module wired into
// ModuleGate.RequireModule must exist, be active, and not be retired. The gate
// resolves enablement through the same DB enumeration, so a gated module with
// no row is a route whose gate can never make a meaningful decision.
func TestModuleCatalog_GatedModulesHaveActiveRows(t *testing.T) {
	db := openModuleCatalogDB(t)
	catalog := loadModuleCatalog(t, db)

	gated := gatedModuleIDs(t, repoRoot(t))
	requireDerivedNonEmpty(t, "RequireModule-gated module", len(gated))

	missing := make(map[string][]string)
	var retired []string
	for id, sites := range gated {
		row, ok := catalog[id]
		switch {
		case !ok || !row.isActive:
			missing[id] = sites
		case row.releaseStatus == string(module.ReleaseStatusDeprecated) || row.releaseStatus == "disabled":
			sort.Strings(sites)
			retired = append(retired, fmt.Sprintf("%s (release_status=%q, gated at %s)",
				id, row.releaseStatus, strings.Join(sites, ", ")))
		}
	}
	failMissing(t, "gated by ModuleGate.RequireModule have no ACTIVE row in the `modules` table", missing)

	if len(retired) > 0 {
		sort.Strings(retired)
		t.Fatalf("%d route(s) are gated on a retired module:\n  - %s\n\n"+
			"Either revive the module (flip release_status back in a migration) or drop the gate "+
			"and the routes behind it. Gating live routes on a deprecated/disabled module leaves "+
			"the feature reachable while the catalog says it is gone.",
			len(retired), strings.Join(retired, "\n  - "))
	}
}

// TestModuleCatalog_CodeMapsHaveRows — every ID in CoreModuleIDs,
// UserFacingModuleIDs and ModulePermissionMapping must have a row.
//
// Existence only, not active: the maps legitimately retain retired IDs
// (sources, secrets, scope, pipelines and webhooks are all seeded
// is_active = FALSE / deprecated) so that historic permission lookups still
// resolve. What must never happen is an ID present in Go and absent from the
// table entirely.
func TestModuleCatalog_CodeMapsHaveRows(t *testing.T) {
	db := openModuleCatalogDB(t)
	catalog := loadModuleCatalog(t, db)

	referenced := codeCatalogIDs()
	requireDerivedNonEmpty(t, "Go catalog map module", len(referenced))

	missing := make(map[string][]string)
	for id, refs := range referenced {
		if _, ok := catalog[id]; !ok {
			missing[id] = refs
		}
	}
	failMissing(t, "listed in the Go catalog maps (module.go) have no row at all "+
		"in the `modules` table", missing)
}

// TestModuleCatalog_SubModuleParentsResolve — a sub-module ID is
// "<parent>.<child>" by construction (BuildSubModuleID), and the table models
// the relation with parent_module_id. Both halves must agree, or the UI groups
// a sub-module under nothing and applySubModuleInheritance cannot inherit the
// parent's bundle decision.
func TestModuleCatalog_SubModuleParentsResolve(t *testing.T) {
	db := openModuleCatalogDB(t)
	catalog := loadModuleCatalog(t, db)

	// (a) Sub-modules referenced from Go must have their parent seeded.
	referenced := make(map[string][]string)
	for id, refs := range presetModuleIDs() {
		referenced[id] = append(referenced[id], refs...)
	}
	for id, refs := range codeCatalogIDs() {
		referenced[id] = append(referenced[id], refs...)
	}

	subReferenced := 0
	missingParents := make(map[string][]string)
	for id, refs := range referenced {
		parent, _, isSub := strings.Cut(id, module.SubModuleSeparator)
		if !isSub {
			continue
		}
		subReferenced++
		if _, ok := catalog[parent]; !ok {
			missingParents[parent] = append([]string{"parent of " + id}, refs...)
		}
	}
	requireDerivedNonEmpty(t, "code-referenced sub-module", subReferenced)
	failMissing(t, "are the parent of a sub-module referenced in Go but have no row "+
		"in the `modules` table", missingParents)

	// (b) Every seeded sub-module row must point parent_module_id at the parent
	// its ID names. A row inserted with parent_module_id NULL (or at the wrong
	// parent) is the drift this half catches.
	var broken []string
	subRows := 0
	for id, row := range catalog {
		parent, _, isSub := strings.Cut(id, module.SubModuleSeparator)
		if !isSub {
			continue
		}
		subRows++
		if row.parentID != parent {
			got := row.parentID
			if got == "" {
				got = "NULL"
			}
			broken = append(broken, fmt.Sprintf("%s: parent_module_id = %s, expected %q", id, got, parent))
		}
	}
	requireDerivedNonEmpty(t, "seeded sub-module row", subRows)

	if len(broken) > 0 {
		sort.Strings(broken)
		t.Fatalf("%d sub-module row(s) have a parent_module_id that disagrees with their ID:\n  - %s\n\n"+
			"FIX: in a migration, set parent_module_id to the part of the ID before the '.', e.g.\n"+
			"  UPDATE modules SET parent_module_id = split_part(id, '.', 1) WHERE id LIKE '%%.%%';",
			len(broken), strings.Join(broken, "\n  - "))
	}
}
