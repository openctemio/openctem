// Command sensorrename performs the type-aware "agent" -> "sensor" rename of
// the API's Go code (RFC-023 §9.5). It is driven by scripts/rename/sensor-rename.sh
// and is safe to re-run: on a tree that is already renamed it changes nothing.
//
// Why a go/types tool and not one `gopls rename` per symbol: the spike in
// RFC-023 proved the approach with gopls, which resolves every identifier to
// its types.Object so a local variable named `agent` is never confused with
// the package of the same name. This tool uses exactly that resolution, from
// the same go/packages loader, but renames every object in one pass. The tree
// has several thousand distinct objects whose name contains "agent" (every
// local `agentID` is its own object); one gopls invocation each re-type-checks
// the module and would take hours.
//
// The rename is a pure function of the identifier (see newName), so every
// object that shares a name — an interface method and all its
// implementations, a struct field and every composite-literal key — lands on
// the same new name without tracking the relationships explicitly. Before
// writing anything, every renamed occurrence is checked against the scope it
// sits in: if the new name already resolves to a different object there, the
// tool reports the conflict and exits without touching the tree.
//
// What it changes:
//   - identifiers (types, funcs, methods, fields, consts, vars, params,
//     labels, import aliases, package names) declared in this module;
//   - import paths and package clauses of moved packages;
//   - comments (prose and identifier references);
//   - file and directory names (git mv), so history follows.
//
// What it deliberately does not change: string literals and struct tags.
// Those are wire and storage contracts (SQL, JSON, permission ids, audit
// ids, routes) and are migrated by hand in separate, reviewed commits.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"go/ast"
	"go/format"
	"go/token"
	"go/types"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"golang.org/x/tools/go/packages"
)

const modulePath = "github.com/openctemio/openctem/api"

// keep lists identifiers that contain "agent" but do not mean a sensor.
var keep = map[string]bool{
	// AI triage "agent" mode: a self-hosted LLM agent, not a sensor.
	"AIModeAgent":                        true,
	"ModuleAITriageAgent":                true,
	"TestAITriage_GetAIConfig_AgentMode": true,
}

// overrides are names whose mechanical rename would read wrongly.
var overrides = map[string]string{
	// audit_logs.actor_agent is the HTTP User-Agent of the actor.
	"ActorAgent":     "ActorUserAgent",
	"WithActorAgent": "WithActorUserAgent",
	"actorAgent":     "actorUserAgent",
	// The legacy type value "sensor" (an EASM vantage point). "SensorTypeSensor"
	// would read as a tautology now that sensor is the umbrella term.
	"AgentTypeSensor": "SensorTypeEASM",
}

// fileOverrides maps repo-relative paths whose mechanical rename would collide
// or read wrongly.
var fileOverrides = map[string]string{
	"tests/unit/agent_sensor_hardening_test.go": "tests/unit/sensor_hardening_test.go",
}

var userAgentRe = regexp.MustCompile(`(?i)user[-_ ]?agent`)

// newName returns the sensor-vocabulary form of an identifier.
func newName(name string) string {
	if keep[name] {
		return name
	}
	if v, ok := overrides[name]; ok {
		return v
	}
	return replaceWord(name)
}

// replaceWord swaps agent→sensor preserving case, except inside "user agent".
func replaceWord(s string) string {
	var protected []string
	s = userAgentRe.ReplaceAllStringFunc(s, func(m string) string {
		protected = append(protected, m)
		return fmt.Sprintf("\x00%d\x00", len(protected)-1)
	})
	s = strings.ReplaceAll(s, "AGENT", "SENSOR")
	s = strings.ReplaceAll(s, "Agent", "Sensor")
	s = strings.ReplaceAll(s, "agent", "sensor")
	for i, p := range protected {
		s = strings.Replace(s, fmt.Sprintf("\x00%d\x00", i), p, 1)
	}
	return s
}

func needsRename(name string) bool {
	return newName(name) != name
}

type edit struct {
	off, end int
	text     string
}

func main() {
	dir := flag.String("dir", ".", "module root")
	dry := flag.Bool("dry-run", false, "report only, do not write")
	verbose = flag.Bool("v", false, "list pre-existing names the rename also produces")
	flag.Parse()

	root, err := filepath.Abs(*dir)
	must(err)

	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles |
			packages.NeedSyntax | packages.NeedTypes | packages.NeedTypesInfo,
		Dir:   root,
		Tests: true,
		Env:   append(os.Environ(), "GOWORK=off"),
	}
	pkgs, err := packages.Load(cfg, "./...")
	must(err)
	if packages.PrintErrors(pkgs) > 0 {
		fail("the tree does not type-check; fix it before renaming")
	}

	c := &collector{root: root, edits: map[string]map[int]edit{}, seenFile: map[string]bool{}}
	for _, pkg := range pkgs {
		c.collect(pkg)
	}
	edits, conflicts := c.edits, c.conflicts

	// A name that already exists and is also produced by the rename could be
	// captured by an inner-scope renamed object. The per-occurrence check above
	// covers the renamed side; list the pre-existing side for review.
	if *verbose {
		reportExisting(pkgs)
	}

	if len(conflicts) > 0 {
		sort.Strings(conflicts)
		for _, c := range conflicts {
			fmt.Fprintln(os.Stderr, "conflict:", c)
		}
		fail(fmt.Sprintf("%d conflicts; nothing written", len(conflicts)))
	}

	files := make([]string, 0, len(edits))
	for f := range edits {
		files = append(files, f)
	}
	sort.Strings(files)
	total := 0
	for _, f := range files {
		total += len(edits[f])
	}
	fmt.Printf("sensorrename: %d edits in %d files\n", total, len(files))
	if *dry {
		for _, f := range files {
			rel, _ := filepath.Rel(root, f)
			fmt.Printf("  %s (%d)\n", rel, len(edits[f]))
		}
		return
	}

	for _, f := range files {
		must(applyEdits(f, edits[f]))
	}
	must(movePaths(root))
}

var verbose *bool

func reportExisting(pkgs []*packages.Package) {
	produced := map[string]bool{}
	existing := map[string][]string{}
	for _, pkg := range pkgs {
		if pkg.TypesInfo == nil {
			continue
		}
		for id, obj := range pkg.TypesInfo.Defs {
			if obj == nil || !ours(obj) {
				continue
			}
			if needsRename(id.Name) {
				produced[newName(id.Name)] = true
			} else {
				existing[id.Name] = append(existing[id.Name], pkg.Fset.Position(id.Pos()).String())
			}
		}
	}
	for name := range produced {
		if locs, ok := existing[name]; ok {
			sort.Strings(locs)
			fmt.Printf("review: %q already exists (%d defs, e.g. %s)\n", name, len(locs), locs[0])
		}
	}
}

// collector gathers every edit of the rename before anything is written.
type collector struct {
	root      string
	edits     map[string]map[int]edit // file -> offset -> edit
	conflicts []string
	seenFile  map[string]bool
}

func (c *collector) add(fset *token.FileSet, pos token.Pos, oldLen int, text string) {
	p := fset.Position(pos)
	if skipFile(c.root, p.Filename) {
		return
	}
	m := c.edits[p.Filename]
	if m == nil {
		m = map[int]edit{}
		c.edits[p.Filename] = m
	}
	m[p.Offset] = edit{off: p.Offset, end: p.Offset + oldLen, text: text}
}

func (c *collector) collect(pkg *packages.Package) {
	if pkg.TypesInfo == nil {
		return
	}
	for id, obj := range pkg.TypesInfo.Defs {
		c.ident(pkg, id, obj)
	}
	for id, obj := range pkg.TypesInfo.Uses {
		c.ident(pkg, id, obj)
	}
	for _, f := range pkg.Syntax {
		fname := pkg.Fset.Position(f.Pos()).Filename
		if c.seenFile[fname] {
			continue
		}
		c.seenFile[fname] = true
		c.file(pkg.Fset, f)
	}
}

func (c *collector) ident(pkg *packages.Package, id *ast.Ident, obj types.Object) {
	if obj == nil || !needsRename(id.Name) || !ours(obj) {
		return
	}
	nn := newName(id.Name)
	c.add(pkg.Fset, id.Pos(), len(id.Name), nn)
	// Conflict check: at this position the new name must not already resolve
	// to some other object. Fields and methods are not in lexical scope; a
	// duplicate there is a compile error, which the build gate catches.
	if v, ok := obj.(*types.Var); ok && v.IsField() {
		return
	}
	if fn, ok := obj.(*types.Func); ok && fn.Type().(*types.Signature).Recv() != nil {
		return
	}
	if s := pkg.Types.Scope().Innermost(id.Pos()); s != nil {
		if _, other := s.LookupParent(nn, id.Pos()); other != nil && other != obj {
			c.conflicts = append(c.conflicts, fmt.Sprintf("%s: %s -> %s collides with %s",
				pkg.Fset.Position(id.Pos()), id.Name, nn, other))
		}
	}
}

func (c *collector) file(fset *token.FileSet, f *ast.File) {
	if needsRename(f.Name.Name) {
		c.add(fset, f.Name.Pos(), len(f.Name.Name), newName(f.Name.Name))
	}
	for _, imp := range f.Imports {
		path := strings.Trim(imp.Path.Value, `"`)
		if strings.HasPrefix(path, modulePath) && needsRename(path) {
			c.add(fset, imp.Path.Pos(), len(imp.Path.Value), `"`+renamePath(path)+`"`)
		}
	}
	for _, cg := range f.Comments {
		if keepGroup(cg) {
			continue
		}
		for _, cm := range cg.List {
			if nt := rewriteComment(cm.Text); nt != cm.Text {
				c.add(fset, cm.Pos(), len(cm.Text), nt)
			}
		}
	}
}

// keepDirective marks a comment group whose old-vocabulary wording is
// intentional (for example a sentence about the rename itself).
const keepDirective = "//sensorrename:keep"

func keepGroup(cg *ast.CommentGroup) bool {
	for _, c := range cg.List {
		if strings.HasPrefix(c.Text, keepDirective) {
			return true
		}
	}
	return false
}

// ours reports whether obj is declared in this module (so renaming it is
// ours to do). Objects from the standard library or dependencies — for
// example (*http.Request).UserAgent — are never touched.
func ours(obj types.Object) bool {
	if pn, ok := obj.(*types.PkgName); ok {
		return strings.HasPrefix(pn.Imported().Path(), modulePath)
	}
	if obj.Pkg() == nil {
		return false
	}
	p := obj.Pkg().Path()
	return p == modulePath || strings.HasPrefix(p, modulePath+"/") ||
		strings.HasPrefix(p, modulePath+".") // test variants "x [x.test]"
}

func renamePath(p string) string {
	parts := strings.Split(p, "/")
	for i, s := range parts {
		parts[i] = newName(s)
	}
	return strings.Join(parts, "/")
}

// Comment rewriting. Protected spans are left byte-for-byte:
//   - "user agent" in any spelling (the HTTP header);
//   - the frozen protocol v1 routes (/api/v1/agent/..., swag "@Router /agent/...");
//   - ALL-CAPS environment variable names, which describe the released
//     sensor binary's interface (AGENT_ID, AGENT_ALLOW_PRIVATE_TARGETS);
//   - the released binary's repository and image name (openctemio/agent);
//   - the AI-triage "agent" mode, which is an LLM agent, not a sensor.
var protectRes = []*regexp.Regexp{
	userAgentRe,
	regexp.MustCompile(`/api/v1/agent(/[A-Za-z0-9_{}./-]*)?\b`),
	regexp.MustCompile(`(^|[\s(\x60"'])/agent/[A-Za-z0-9_{}./-]*`),
	regexp.MustCompile(`\b[A-Z0-9_]*AGENT[A-Z0-9_]*\b`),
	regexp.MustCompile(`openctemio/agent\b[:A-Za-z0-9_.-]*`),
	regexp.MustCompile(`\bAI(-| )agent\b`),
	regexp.MustCompile(`ai_triage\.agent`),
	regexp.MustCompile(`\bAIModeAgent\b|\bModuleAITriageAgent\b`),
	regexp.MustCompile(`(?i)\bbyok(/|, )agent\b|self-hosted agent mode`),
	// After the rename, comments that name the old vocabulary do so on
	// purpose: the rename itself, quoted stored values and id families, and
	// the deprecated management path. Re-running the tool must keep them.
	regexp.MustCompile(`\bagent ?(→|->) ?sensor\b`),
	regexp.MustCompile("[\"'`]agents?[A-Za-z0-9_.:*-]*[\"'`]"),
	regexp.MustCompile(`\bagents?[.:_]\*`),
	regexp.MustCompile(`/api/v1/agents\b[A-Za-z0-9_{}./*-]*`),
	regexp.MustCompile(`(@Router\s+)/agents\b[A-Za-z0-9_{}./-]*`),
	regexp.MustCompile(`\bfrom /agents\b|\bEvery /agents\b`),
}

// articleRe fixes "an agent" → "an sensor" into "a sensor".
var articleRe = regexp.MustCompile(`\b([Aa])n( [Ss]ensor)`)

var identRe = regexp.MustCompile(`\b[A-Za-z_][A-Za-z0-9_]*\b`)

func rewriteComment(text string) string {
	var protected []string
	for _, re := range protectRes {
		text = re.ReplaceAllStringFunc(text, func(m string) string {
			protected = append(protected, m)
			return fmt.Sprintf("\x00%d\x00", len(protected)-1)
		})
	}
	text = identRe.ReplaceAllStringFunc(text, func(w string) string {
		if !strings.Contains(strings.ToLower(w), "agent") {
			return w
		}
		return newName(w)
	})
	text = articleRe.ReplaceAllString(text, "$1$2")
	// Restore innermost-first: a protected span never contains another marker
	// that was added later, so reverse order is safe.
	for i := len(protected) - 1; i >= 0; i-- {
		text = strings.Replace(text, fmt.Sprintf("\x00%d\x00", i), protected[i], 1)
	}
	return text
}

func applyEdits(file string, m map[int]edit) error {
	src, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	list := make([]edit, 0, len(m))
	for _, e := range m {
		list = append(list, e)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].off > list[j].off })
	for _, e := range list {
		src = append(src[:e.off:e.off], append([]byte(e.text), src[e.end:]...)...)
	}
	if out, ferr := format.Source(src); ferr == nil {
		src = out
	}
	return os.WriteFile(file, src, 0o644) //nolint:gosec // source files are world-readable
}

// movePaths renames tracked files and directories whose path contains
// "agent", with git mv so history follows the file.
func movePaths(root string) error {
	out, err := exec.Command("git", "-C", root, "ls-files").Output()
	if err != nil {
		return err
	}
	moves := map[string]string{}
	for _, f := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if !shouldMove(f) {
			continue
		}
		to, ok := fileOverrides[f]
		if !ok {
			to = renamePath(f)
		}
		if to != f {
			moves[f] = to
		}
	}
	srcs := make([]string, 0, len(moves))
	for f := range moves {
		srcs = append(srcs, f)
	}
	sort.Strings(srcs)
	for _, from := range srcs {
		to := moves[from]
		if err := os.MkdirAll(filepath.Join(root, filepath.Dir(to)), 0o755); err != nil { //nolint:gosec // repo dirs
			return err
		}
		cmd := exec.Command("git", "-C", root, "mv", from, to)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("git mv %s %s: %w: %s", from, to, err, stderr.String())
		}
	}
	fmt.Printf("sensorrename: moved %d files\n", len(moves))
	return nil
}

// skipFile excludes the rename tooling and the vocabulary guard: both name
// the old vocabulary on purpose.
func skipFile(root, file string) bool {
	rel, err := filepath.Rel(root, file)
	if err != nil || strings.HasPrefix(rel, "..") {
		return true // outside the module, e.g. a generated test main in the build cache
	}
	rel = filepath.ToSlash(rel)
	return strings.HasPrefix(rel, "scripts/rename/") || strings.HasPrefix(rel, "tools/lint/sensorvocab/")
}

// shouldMove limits path renames to code and config the API owns. Migrations
// keep their names (they are history) and documentation is renamed by hand.
func shouldMove(f string) bool {
	if !strings.Contains(strings.ToLower(f), "agent") {
		return false
	}
	switch {
	case strings.HasPrefix(f, "migrations/"),
		strings.HasPrefix(f, "docs/"),
		strings.HasPrefix(f, "scripts/rename/"):
		return false
	}
	return strings.HasSuffix(f, ".go") || strings.HasPrefix(f, "configs/")
}

func must(err error) {
	if err != nil {
		fail(err.Error())
	}
}

func fail(msg string) {
	fmt.Fprintln(os.Stderr, "sensorrename:", msg)
	os.Exit(1)
}
