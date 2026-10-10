// Command gen-modules reads configs/modules.yaml (the module registry,
// RFC-064) and emits the generated Go and TypeScript files and the SQL block
// that writes the `modules` rows.
//
// Usage (from api/):
//
//	go run ./cmd/gen-modules          # write the Go and TS files
//	go run ./cmd/gen-modules -sql     # print the SQL block for a new migration
//	go run ./cmd/gen-modules -check   # fail if anything drifted (CI)
//
// Or `make generate-modules`, `make modules-sql` and `make modules-check`.
//
// -check fails when the committed Go file, TS file or the SQL block of the
// newest migration that carries the module-registry markers differs from
// what the YAML produces. The generator never edits a migration: a registry
// change that touches the catalog rows needs a new migration with the block.
package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"go/format"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Paths, relative to the api/ directory.
const (
	yamlPath      = "configs/modules.yaml"
	goPath        = "pkg/domain/module/registry_generated.go"
	tsPath        = "../web/src/config/modules.generated.ts"
	migrationsDir = "migrations"
)

const (
	sqlBeginMarker = "-- BEGIN module-registry"
	sqlEndMarker   = "-- END module-registry"
)

type dependency struct {
	ID     string `yaml:"id"`
	Kind   string `yaml:"kind"`
	Reason string `yaml:"reason"`
}

type module struct {
	ID          string       `yaml:"id"`
	Const       string       `yaml:"const"`
	Slug        string       `yaml:"slug"`
	Name        string       `yaml:"name"`
	Description string       `yaml:"description"`
	Icon        string       `yaml:"icon"`
	Category    string       `yaml:"category"`
	Order       int          `yaml:"order"`
	Core        bool         `yaml:"core"`
	Parent      string       `yaml:"parent"`
	Release     string       `yaml:"release"`
	UserFacing  bool         `yaml:"user_facing"`
	Permission  string       `yaml:"permission"`
	Depends     []dependency `yaml:"depends"`
	Routes      []string     `yaml:"routes"`
	MCP         []string     `yaml:"mcp"`
	Jobs        []string     `yaml:"jobs"`
}

func main() {
	sqlOnly := flag.Bool("sql", false, "print the SQL block for a new migration")
	check := flag.Bool("check", false, "fail if a generated file or the migration block drifted")
	flag.Parse()

	mods, err := load(yamlPath)
	if err != nil {
		fail(err)
	}
	goSrc, err := renderGo(mods)
	if err != nil {
		fail(err)
	}
	tsSrc := renderTS(mods)
	sqlSrc := renderSQL(mods)

	switch {
	case *sqlOnly:
		fmt.Print(sqlSrc)
	case *check:
		var problems []string
		if !fileEquals(goPath, goSrc) {
			problems = append(problems, goPath+" is out of date")
		}
		if !fileEquals(tsPath, []byte(tsSrc)) {
			problems = append(problems, tsPath+" is out of date")
		}
		if msg := checkMigration(sqlSrc); msg != "" {
			problems = append(problems, msg)
		}
		if len(problems) > 0 {
			fail(fmt.Errorf("%s\nrun `make generate-modules` (and add a migration with `make modules-sql` when the rows changed)",
				strings.Join(problems, "\n")))
		}
		fmt.Println("module registry: generated files and migration block are current")
	default:
		if err := os.WriteFile(goPath, goSrc, 0o600); err != nil {
			fail(err)
		}
		if err := os.WriteFile(tsPath, []byte(tsSrc), 0o600); err != nil {
			fail(err)
		}
		fmt.Printf("wrote %s and %s (%d modules)\n", goPath, tsPath, len(mods))
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "gen-modules:", err)
	os.Exit(1)
}

var (
	idRe    = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)?$`)
	constRe = regexp.MustCompile(`^Module[A-Z][A-Za-z0-9]*$`)
)

var releases = map[string]bool{"released": true, "beta": true, "coming_soon": true, "deprecated": true}

// load reads and validates the registry.
func load(path string) ([]module, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var mods []module
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&mods); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return mods, validate(mods)
}

func validate(mods []module) error {
	if len(mods) == 0 {
		return errors.New("the registry is empty")
	}
	var errs []string
	add := func(format string, args ...any) { errs = append(errs, fmt.Sprintf(format, args...)) }
	byID := validateEntries(mods, add)
	validateLinks(mods, byID, add)
	if len(errs) > 0 {
		sort.Strings(errs)
		return errors.New(strings.Join(errs, "\n"))
	}
	return nil
}

// validateEntries checks each module on its own and that ids, constants and
// listed routes, tools and jobs are unique.
func validateEntries(mods []module, add func(string, ...any)) map[string]module {
	byID := map[string]module{}
	consts := map[string]bool{}
	owner := map[string]string{} // route, tool or job -> module
	for _, m := range mods {
		if !idRe.MatchString(m.ID) {
			add("%q: invalid id", m.ID)
		}
		if _, dup := byID[m.ID]; dup {
			add("%q: duplicate id", m.ID)
		}
		byID[m.ID] = m
		if !constRe.MatchString(m.Const) || consts[m.Const] {
			add("%q: const %q is invalid or duplicate", m.ID, m.Const)
		}
		consts[m.Const] = true
		if m.Slug == "" || m.Name == "" || m.Category == "" {
			add("%q: slug, name and category are required", m.ID)
		}
		if m.Release != "" && !releases[m.Release] {
			add("%q: unknown release %q", m.ID, m.Release)
		}
		for _, list := range [][]string{m.Routes, m.MCP, m.Jobs} {
			for _, v := range list {
				if prev, ok := owner[v]; ok {
					add("%q is listed by both %q and %q", v, prev, m.ID)
				}
				owner[v] = m.ID
			}
		}
		for _, r := range m.Routes {
			if !strings.HasPrefix(r, "/api/") || strings.HasSuffix(r, "/") {
				add("%q: route %q must start with /api/ and not end with /", m.ID, r)
			}
			if m.Core {
				add("%q: a core module gates no route (%q)", m.ID, r)
			}
		}
	}
	return byID
}

// validateLinks checks parents and dependencies.
func validateLinks(mods []module, byID map[string]module, add func(string, ...any)) {
	for _, m := range mods {
		if m.Parent != "" {
			p, ok := byID[m.Parent]
			switch {
			case !ok:
				add("%q: parent %q is not a module", m.ID, m.Parent)
			case p.Parent != "":
				add("%q: parent %q is itself a sub-module", m.ID, m.Parent)
			case !strings.HasPrefix(m.ID, m.Parent+"."):
				add("%q: a sub-module id is <parent>.<name>", m.ID)
			}
		} else if strings.Contains(m.ID, ".") {
			add("%q: a dotted id needs a parent", m.ID)
		}
		for _, d := range m.Depends {
			if _, ok := byID[d.ID]; !ok {
				add("%q: depends on unknown module %q", m.ID, d.ID)
			}
			if d.Kind != "hard" && d.Kind != "soft" {
				add("%q: dependency kind %q is not hard or soft", m.ID, d.Kind)
			}
			if d.Reason == "" {
				add("%q: dependency on %q needs a reason", m.ID, d.ID)
			}
		}
		if m.Core && len(m.Depends) > 0 {
			add("%q: a core module declares no dependencies (it is always on)", m.ID)
		}
	}
}

func release(m module) string {
	if m.Release == "" {
		return "released"
	}
	return m.Release
}

var releaseConst = map[string]string{
	"released": "ReleaseStatusReleased", "beta": "ReleaseStatusBeta",
	"coming_soon": "ReleaseStatusComingSoon", "deprecated": "ReleaseStatusDeprecated",
}

func goStrings(list []string) string {
	q := make([]string, len(list))
	for i, s := range list {
		q[i] = strconv.Quote(s)
	}
	return "[]string{" + strings.Join(q, ", ") + "}"
}

func renderGo(mods []module) ([]byte, error) {
	constOf := map[string]string{}
	for _, m := range mods {
		constOf[m.ID] = m.Const
	}
	var b strings.Builder
	b.WriteString("// Code generated by cmd/gen-modules from configs/modules.yaml. DO NOT EDIT.\n\n")
	b.WriteString("package module\n\n")
	b.WriteString("// Module ids (configs/modules.yaml).\nconst (\n")
	for _, m := range mods {
		fmt.Fprintf(&b, "\t%s = %q\n", m.Const, m.ID)
	}
	b.WriteString(")\n\n")
	b.WriteString("// Registry is every module, top-level modules in display order, each\n// followed by its sub-modules.\n")
	b.WriteString("var Registry = []Definition{\n")
	for _, m := range mods {
		fmt.Fprintf(&b, "\t{\n\t\tID: %s, Slug: %q, Name: %q,\n", m.Const, m.Slug, m.Name)
		if m.Description != "" {
			fmt.Fprintf(&b, "\t\tDescription: %q,\n", m.Description)
		}
		if m.Icon != "" {
			fmt.Fprintf(&b, "\t\tIcon: %q,\n", m.Icon)
		}
		fmt.Fprintf(&b, "\t\tCategory: %q, DisplayOrder: %d, Release: %s,\n", m.Category, m.Order, releaseConst[release(m)])
		if m.Core {
			b.WriteString("\t\tCore: true,\n")
		}
		if m.Parent != "" {
			fmt.Fprintf(&b, "\t\tParent: %s,\n", constOf[m.Parent])
		}
		if m.UserFacing {
			b.WriteString("\t\tUserFacing: true,\n")
		}
		if m.Permission != "" {
			fmt.Fprintf(&b, "\t\tPermission: %q,\n", m.Permission)
		}
		if len(m.Depends) > 0 {
			b.WriteString("\t\tDepends: []Dependency{\n")
			for _, d := range m.Depends {
				kind := "DependencyHard"
				if d.Kind == "soft" {
					kind = "DependencySoft"
				}
				fmt.Fprintf(&b, "\t\t\t{ModuleID: %s, Type: %s, Reason: %q},\n", constOf[d.ID], kind, d.Reason)
			}
			b.WriteString("\t\t},\n")
		}
		if len(m.Routes) > 0 {
			fmt.Fprintf(&b, "\t\tRoutes: %s,\n", goStrings(m.Routes))
		}
		if len(m.MCP) > 0 {
			fmt.Fprintf(&b, "\t\tMCP: %s,\n", goStrings(m.MCP))
		}
		if len(m.Jobs) > 0 {
			fmt.Fprintf(&b, "\t\tJobs: %s,\n", goStrings(m.Jobs))
		}
		b.WriteString("\t},\n")
	}
	b.WriteString("}\n")
	return format.Source([]byte(b.String()))
}

func tsString(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `'`, `\'`)
	return "'" + r.Replace(s) + "'"
}

func renderTS(mods []module) string {
	var b strings.Builder
	b.WriteString("// Code generated by api/cmd/gen-modules from api/configs/modules.yaml. DO NOT EDIT.\n")
	b.WriteString("// Run `make generate-modules` in api/ after changing the registry.\n\n")
	b.WriteString("export type ModuleRelease = 'released' | 'beta' | 'coming_soon' | 'deprecated'\n\n")
	b.WriteString("export interface ModuleDefinition {\n  id: string\n  name: string\n  core: boolean\n  parent?: string\n  release: ModuleRelease\n  userFacing: boolean\n  permission?: string\n}\n\n")
	b.WriteString("export const MODULE_REGISTRY: readonly ModuleDefinition[] = [\n")
	for _, m := range mods {
		fmt.Fprintf(&b, "  { id: %s, name: %s, core: %t", tsString(m.ID), tsString(m.Name), m.Core)
		if m.Parent != "" {
			fmt.Fprintf(&b, ", parent: %s", tsString(m.Parent))
		}
		fmt.Fprintf(&b, ", release: %s, userFacing: %t", tsString(release(m)), m.UserFacing)
		if m.Permission != "" {
			fmt.Fprintf(&b, ", permission: %s", tsString(m.Permission))
		}
		b.WriteString(" },\n")
	}
	b.WriteString("]\n\n")
	b.WriteString("export type ModuleId =\n")
	for i, m := range mods {
		sep := ""
		if i == len(mods)-1 {
			sep = ""
		}
		fmt.Fprintf(&b, "  | %s%s\n", tsString(m.ID), sep)
	}
	b.WriteString("\n/** Every module id of the registry. */\n")
	b.WriteString("export const MODULE_IDS: ReadonlySet<string> = new Set(MODULE_REGISTRY.map((m) => m.id))\n\n")
	b.WriteString("/** Modules that are always on. */\n")
	b.WriteString("export const CORE_MODULE_IDS: ReadonlySet<string> = new Set(\n  MODULE_REGISTRY.filter((m) => m.core).map((m) => m.id)\n)\n")
	return b.String()
}

func sqlString(s string) string {
	if s == "" {
		return "NULL"
	}
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

func renderSQL(mods []module) string {
	var b strings.Builder
	b.WriteString(sqlBeginMarker + "\n")
	b.WriteString("-- Generated by cmd/gen-modules from configs/modules.yaml. Do not edit by hand.\n")
	b.WriteString("INSERT INTO modules (id, slug, name, description, icon, category, display_order, is_active, is_core, release_status, parent_module_id)\nVALUES\n")
	ids := make([]string, 0, len(mods))
	for i, m := range mods {
		sep := ","
		if i == len(mods)-1 {
			sep = ""
		}
		fmt.Fprintf(&b, "    (%s, %s, %s, %s, %s, %s, %d, TRUE, %t, %s, %s)%s\n",
			sqlString(m.ID), sqlString(m.Slug), sqlString(m.Name), sqlString(m.Description), sqlString(m.Icon),
			sqlString(m.Category), m.Order, m.Core, sqlString(release(m)), sqlString(m.Parent), sep)
		ids = append(ids, sqlString(m.ID))
	}
	b.WriteString("ON CONFLICT (id) DO UPDATE SET\n")
	b.WriteString("    slug = EXCLUDED.slug, name = EXCLUDED.name, description = EXCLUDED.description,\n")
	b.WriteString("    icon = EXCLUDED.icon, category = EXCLUDED.category, display_order = EXCLUDED.display_order,\n")
	b.WriteString("    is_active = TRUE, is_core = EXCLUDED.is_core, release_status = EXCLUDED.release_status,\n")
	b.WriteString("    parent_module_id = EXCLUDED.parent_module_id, updated_at = NOW();\n")
	b.WriteString("-- A row the registry no longer declares is retired: inactive, so no tenant can reach it.\n")
	fmt.Fprintf(&b, "UPDATE modules SET is_active = FALSE, updated_at = NOW()\n WHERE is_active AND id NOT IN (%s);\n", strings.Join(ids, ", "))
	b.WriteString(sqlEndMarker + "\n")
	return b.String()
}

func fileEquals(path string, want []byte) bool {
	got, err := os.ReadFile(path)
	return err == nil && bytes.Equal(got, want)
}

// checkMigration compares the block of the newest migration that carries the
// markers with the rendered block.
func checkMigration(want string) string {
	files, err := filepath.Glob(filepath.Join(migrationsDir, "*.up.sql"))
	if err != nil {
		return err.Error()
	}
	sort.Strings(files)
	for i := len(files) - 1; i >= 0; i-- {
		raw, err := os.ReadFile(files[i])
		if err != nil {
			return err.Error()
		}
		s := string(raw)
		start := strings.Index(s, sqlBeginMarker)
		if start < 0 {
			continue
		}
		end := strings.Index(s[start:], sqlEndMarker)
		if end < 0 {
			return files[i] + ": " + sqlBeginMarker + " without " + sqlEndMarker
		}
		got := s[start : start+end+len(sqlEndMarker)+1]
		if got != want {
			return files[i] + ": the module-registry block differs from configs/modules.yaml (add a new migration with `make modules-sql`)"
		}
		return ""
	}
	return "no migration carries the module-registry block"
}
