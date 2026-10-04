package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestCommittedRegistryIsUpToDate is the asset-types-drift check as a unit
// test: the committed Go file, TS file and the newest migration block must
// equal what configs/asset-types.yaml produces. CI also runs
// `go run ./cmd/gen-asset-types -check` as its own step.
func TestCommittedRegistryIsUpToDate(t *testing.T) {
	t.Chdir("../..") // api/
	m, err := load(yamlPath, relationshipPath)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	goSrc, err := renderGo(m)
	if err != nil {
		t.Fatalf("render go: %v", err)
	}
	if err := checkDrift(goSrc, renderTS(m), renderSQL(m), migrationsDir); err != nil {
		t.Fatal(err)
	}
}

// The drift check must notice an edit on each side.
func TestCheckDrift_DetectsEachKindOfDrift(t *testing.T) {
	t.Chdir("../..")
	m, err := load(yamlPath, relationshipPath)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	goSrc, err := renderGo(m)
	if err != nil {
		t.Fatal(err)
	}
	ts, sql := renderTS(m), renderSQL(m)

	if err := checkDrift(append(goSrc, []byte("// edited\n")...), ts, sql, migrationsDir); err == nil || !strings.Contains(err.Error(), goPath) {
		t.Errorf("edited Go file not detected: %v", err)
	}
	if err := checkDrift(goSrc, ts+"// edited\n", sql, migrationsDir); err == nil || !strings.Contains(err.Error(), tsPath) {
		t.Errorf("edited TS file not detected: %v", err)
	}
	changed := strings.Replace(sql, "'serverless', 'Serverless Function', 'function'", "'serverless', 'Serverless Function', 'host'", 1)
	if changed == sql {
		t.Fatal("fixture no longer matches the SQL block")
	}
	if err := checkDrift(goSrc, ts, changed, migrationsDir); err == nil || !strings.Contains(err.Error(), "asset-type-registry block") {
		t.Errorf("migration block drift not detected: %v", err)
	}
}

func TestNewestMigrationBlock_PicksTheHighestVersion(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("000010_a.up.sql", "x\n"+sqlBeginMarker+" old\n"+sqlEndMarker+"\n")
	write("000011_b.up.sql", "no block here\n")
	write("000012_c.up.sql", "y\n"+sqlBeginMarker+" new\nbody\n"+sqlEndMarker+"\ntrailer\n")
	write("000013_d.down.sql", sqlBeginMarker+" down files are ignored\n"+sqlEndMarker+"\n")

	file, block, err := newestMigrationBlock(dir)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(file) != "000012_c.up.sql" || block != sqlBeginMarker+" new\nbody\n"+sqlEndMarker+"\n" {
		t.Errorf("got %s %q", file, block)
	}

	write("000014_e.up.sql", sqlBeginMarker+" unterminated\n")
	if _, _, err := newestMigrationBlock(dir); err == nil {
		t.Error("unterminated block accepted")
	}
}

// minimal is a valid registry; each case breaks one rule.
const minimal = `
lenses:
  - { id: code, label: Code, description: d, row: table, default_group_by: type }
classes:
  - { id: code_repo, label: Code repository, lens: code, jupiterone: CodeRepo }
  - { id: other, label: Other, jupiterone: Entity }
legacy_categories: [{ id: code, label: Code }, { id: other, label: Other }]
cards: [generic, repository]
sections: [{ id: overview, label: Overview }]
core_fields: [name, findings.open]
identity_kinds: [scm_repo_id]
virtual_types: [{ name: container_image, type: repository, sub_type: image }]
types:
  - type: repository
    label: Repository
    plural: Repositories
    icon: git-branch
    class: code_repo
    legacy_category: code
    identity_keys: [scm_repo_id, name]
    attributes:
      - { name: provider, type: enum, values: [github], facet: true }
    columns: [name, provider]
    card: repository
    sections: [overview]
  - type: unclassified
    label: Unclassified
    plural: Unclassified
    icon: help-circle
    class: other
    legacy_category: other
    identity_keys: [name]
    columns: [name]
    card: generic
    sections: [overview]
`

const minimalRel = `
types:
  - id: contains
    constraints:
      - { sources: [repository], targets: [container_image] }
`

func resolveText(t *testing.T, reg, rel string) error {
	t.Helper()
	var cfg config
	dec := yaml.NewDecoder(strings.NewReader(reg))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return err
	}
	var r relConfig
	if err := yaml.Unmarshal([]byte(rel), &r); err != nil {
		t.Fatal(err)
	}
	_, err := resolve(&cfg, &r)
	return err
}

func TestResolve_RejectsInvalidRegistries(t *testing.T) {
	if err := resolveText(t, minimal, minimalRel); err != nil {
		t.Fatalf("minimal registry rejected: %v", err)
	}
	cases := []struct {
		name, from, to, rel, want string
	}{
		{"unknown class", "class: code_repo\n    legacy", "class: nope\n    legacy", "", "unknown class"},
		{"identity keys without name", "identity_keys: [scm_repo_id, name]", "identity_keys: [scm_repo_id]", "", "must end with name"},
		{"unknown identity kind", "identity_keys: [scm_repo_id, name]", "identity_keys: [ssn, name]", "", "identity key"},
		{"facet on a list", "{ name: provider, type: enum, values: [github], facet: true }", "{ name: provider, type: list, facet: true }", "", "cannot be a facet"},
		{"enum without values", "{ name: provider, type: enum, values: [github], facet: true }", "{ name: provider, type: enum }", "", "enum needs values"},
		{"unknown column", "columns: [name, provider]", "columns: [name, stars]", "", "column"},
		{"unknown section", "sections: [overview]\n  - type: unclassified", "sections: [overview, nope]\n  - type: unclassified", "", "unknown section"},
		{"other with a lens", "{ id: other, label: Other, jupiterone: Entity }", "{ id: other, label: Other, lens: code, jupiterone: Entity }", "", "must not have a lens"},
		{"unknown field", "icon: git-branch", "icon: git-branch\n    unknown_key: red", "", "unknown_key"},
		{"unresolved relationship type", "", "", "types:\n  - id: contains\n    constraints:\n      - { sources: [repository], targets: [k8s_thing] }\n", "k8s_thing"},
		{"type named after an /assets page", "  - type: unclassified", "  - type: groups", "", "reserved"},
		{"lens named after an /assets page", "id: code, label: Code,", "id: changes, label: Code,", "", "reserved"},
		{"class named after an /assets page", "{ id: code_repo, label: Code repository", "{ id: duplicates, label: Code repository", "", "reserved"},
		{"alias of an unknown type", "class: code_repo\n    legacy", "class: code_repo\n    alias_of: { type: nope, sub_type: x }\n    legacy", "", "alias_of unknown type"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reg := minimal
			if tc.from != "" {
				reg = strings.Replace(minimal, tc.from, tc.to, 1)
				if reg == minimal {
					t.Fatalf("fixture %q not found", tc.from)
				}
			}
			rel := minimalRel
			if tc.rel != "" {
				rel = tc.rel
			}
			err := resolveText(t, reg, rel)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("want an error containing %q, got %v", tc.want, err)
			}
		})
	}
}
