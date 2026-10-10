package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTheRegistryIsValid(t *testing.T) {
	if err := os.Chdir("../.."); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir("cmd/gen-modules") })
	mods, err := load(yamlDir)
	if err != nil {
		t.Fatalf("configs/modules: %v", err)
	}
	if len(mods) < 40 {
		t.Fatalf("only %d modules loaded", len(mods))
	}
}

func TestValidateRefusesBrokenRegistries(t *testing.T) {
	base := func() []module {
		return []module{
			{ID: "findings", Const: "ModuleFindings", Slug: "findings", Name: "Findings", Category: "core", Core: true},
			{ID: "pentest", Const: "ModulePentest", Slug: "pentest", Name: "Pentest", Category: "validation",
				Depends: []dependency{{ID: "findings", Kind: "hard", Reason: "r"}}, Routes: []string{"/api/v1/pentest"}},
			{ID: "pentest.reports", Const: "ModulePentestReports", Slug: "reports", Name: "Reports", Category: "validation", Parent: "pentest"},
		}
	}
	if err := validate(base()); err != nil {
		t.Fatalf("valid registry refused: %v", err)
	}
	cases := map[string]func([]module) []module{
		"duplicate id":           func(m []module) []module { return append(m, m[0]) },
		"unknown parent":         func(m []module) []module { m[2].Parent = "nope"; return m },
		"sub-module id shape":    func(m []module) []module { m[2].ID = "reports"; return m },
		"unknown dependency":     func(m []module) []module { m[1].Depends[0].ID = "nope"; return m },
		"dependency kind":        func(m []module) []module { m[1].Depends[0].Kind = "maybe"; return m },
		"dependency reason":      func(m []module) []module { m[1].Depends[0].Reason = ""; return m },
		"core gating a route":    func(m []module) []module { m[0].Routes = []string{"/api/v1/findings"}; return m },
		"route shape":            func(m []module) []module { m[1].Routes = []string{"/pentest/"}; return m },
		"route listed twice":     func(m []module) []module { m[2].Routes = []string{"/api/v1/pentest"}; return m },
		"core with dependencies": func(m []module) []module { m[0].Depends = m[1].Depends; return m },
		"release":                func(m []module) []module { m[1].Release = "soon"; return m },
		"const":                  func(m []module) []module { m[1].Const = "pentest"; return m },
	}
	for name, mutate := range cases {
		if err := validate(mutate(base())); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestRenderSQLRetiresUndeclaredRows(t *testing.T) {
	sql := renderSQL([]module{{ID: "o'k", Const: "ModuleOK", Slug: "ok", Name: "It's", Category: "core", Order: 1, Core: true}})
	for _, want := range []string{sqlBeginMarker, sqlEndMarker, "'o''k'", "'It''s'", "ON CONFLICT (id) DO UPDATE",
		"is_active = FALSE", "id NOT IN ('o''k')"} {
		if !strings.Contains(sql, want) {
			t.Errorf("SQL lacks %q:\n%s", want, sql)
		}
	}
}

func writeModuleFile(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadFileHoldsOneModuleAndItsSubModules(t *testing.T) {
	dir := t.TempDir()
	ok := writeModuleFile(t, dir, "pentest.yaml", "- {id: pentest, const: ModulePentest, slug: p, name: P, category: c}\n"+
		"- {id: pentest.reports, const: ModulePentestReports, slug: r, name: R, category: c, parent: pentest}\n")
	if mods, err := loadFile(ok); err != nil || len(mods) != 2 {
		t.Fatalf("loadFile = %d, %v", len(mods), err)
	}
	for name, body := range map[string]string{
		"foreign module": "- {id: pentest, const: ModulePentest, slug: p, name: P, category: c}\n- {id: findings, const: ModuleFindings, slug: f, name: F, category: c}\n",
		"missing top":    "- {id: pentest.reports, const: ModulePentestReports, slug: r, name: R, category: c, parent: pentest}\n",
		"foreign sub":    "- {id: pentest, const: ModulePentest, slug: p, name: P, category: c}\n- {id: scans.x, const: ModuleScansX, slug: x, name: X, category: c, parent: scans}\n",
		"unknown field":  "- {id: pentest, const: ModulePentest, slug: p, name: P, category: c, flavor: red}\n",
	} {
		p := writeModuleFile(t, dir, "pentest.yaml", body)
		if _, err := loadFile(p); err == nil {
			t.Errorf("%s: loadFile accepted it", name)
		}
	}
}

func TestSortRegistryOrdersTopLevelThenSubModules(t *testing.T) {
	mods := []module{
		{ID: "b.y", Parent: "b", Order: 2},
		{ID: "c", Order: 10},
		{ID: "b", Order: 10},
		{ID: "b.x", Parent: "b", Order: 1},
		{ID: "a", Order: 20},
		{ID: "b.w", Parent: "b", Order: 2},
	}
	sortRegistry(mods)
	var got []string
	for _, m := range mods {
		got = append(got, m.ID)
	}
	if want := "b b.x b.w b.y c a"; strings.Join(got, " ") != want {
		t.Fatalf("order = %q, want %q", strings.Join(got, " "), want)
	}
}
