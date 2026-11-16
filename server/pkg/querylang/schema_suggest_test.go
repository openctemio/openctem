package querylang

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/openctemio/openctem/server/pkg/filterspec"
)

func schemaPaths(s Schema) []string {
	out := make([]string, 0, len(s.Fields))
	for _, f := range s.Fields {
		out = append(out, f.Path)
	}
	return out
}

func schemaField(s Schema, path string) (FieldInfo, bool) {
	for _, f := range s.Fields {
		if f.Path == path {
			return f, true
		}
	}
	return FieldInfo{}, false
}

// The schema lists the suggested paths first, in their declared order,
// then relation groups, more and identifiers: an editor that shows the
// list as it comes leads with what people filter by, not record ids.
func TestSchemaSuggestionOrder(t *testing.T) {
	all := func(string) bool { return true }
	for _, e := range []*Entity{Findings, Assets, Scans} {
		s := e.Schema(all)
		paths := schemaPaths(s)
		if !slices.Equal(paths[:len(e.suggested)], e.suggested) {
			t.Errorf("%s: schema starts %v, want the suggested paths %v", e.Name, paths[:len(e.suggested)], e.suggested)
		}
		rank := map[string]int{GroupCommon: 0, GroupMore: 2, GroupIdentifier: 3}
		last := -1
		for _, f := range s.Fields {
			r, ok := rank[f.Group]
			if !ok {
				r = 1
			}
			if r < last {
				t.Errorf("%s: %s (%s) comes after a later group", e.Name, f.Path, f.Group)
			}
			last = r
		}
		if id, _ := schemaField(s, "id"); id.Group != GroupIdentifier {
			t.Errorf("%s: id is in group %q, want identifier", e.Name, id.Group)
		}
	}
	s := Findings.Schema(all)
	for path, group := range map[string]string{
		"severity": GroupCommon, "asset.domain": GroupCommon, "asset.type": "asset", "asset_id": GroupIdentifier,
		"branch_id": GroupIdentifier, "vulnerability_id": GroupIdentifier, "scan_id": GroupIdentifier,
		"rule_id": GroupMore, "informational": GroupMore,
	} {
		if f, ok := schemaField(s, path); !ok || f.Group != group {
			t.Errorf("findings %s: group %q, want %q", path, f.Group, group)
		}
	}
	paths := schemaPaths(s)
	if slices.Index(paths, "asset_id") < slices.Index(paths, "informational") {
		t.Error("findings: asset_id is offered before plain fields")
	}
}

// Each field carries its short names, shortest first, so an editor can
// offer "kev" for is_in_kev and still find a former name such as
// asset_domain.
func TestSchemaAliases(t *testing.T) {
	s := Findings.Schema(func(string) bool { return true })
	for path, want := range map[string][]string{
		"is_in_kev": {"kev"}, "asset.domain": {"domain", "asset_domain"}, "epss_score": {"epss"},
		"severity": nil,
	} {
		f, _ := schemaField(s, path)
		if !slices.Equal(f.Aliases, want) {
			t.Errorf("%s: aliases %v, want %v", path, f.Aliases, want)
		}
	}
}

// Internal fields and fields the caller may not use stay out of the
// schema whatever the suggestion order says.
func TestSchemaSuggestionsKeepPermissionsAndInternal(t *testing.T) {
	s := Findings.Schema(hasOnly("findings:read"))
	for _, p := range schemaPaths(s) {
		if p == "asset.domain" || p == "asset.ip" || p == "asset.criticality" || p == "asset.type" {
			t.Errorf("%s offered without assets:read", p)
		}
	}
	if paths := schemaPaths(s); paths[0] != "severity" || paths[1] != "state" {
		t.Errorf("findings without assets:read starts %v", paths[:2])
	}
	for _, e := range []*Entity{Findings, Assets, Scans} {
		for _, f := range e.Schema(func(string) bool { return true }).Fields {
			if e.internal[e.fieldName(f.Path)] {
				t.Errorf("%s: internal field %s in the schema", e.Name, f.Path)
			}
		}
	}
}

func TestEntitySuggestedValidation(t *testing.T) {
	reg := filterspec.MustRegistry(filterspec.Registry{Name: "x", TenantSQL: "x.tenant_id", ScopeAssetSQL: "x.asset_id", IDSQL: "x.id"},
		filterspec.Field{Name: "severity", Type: filterspec.TypeEnum, Enum: []string{"high"}, Ops: []filterspec.Op{filterspec.OpIn}, SQL: "x.severity"},
		filterspec.Field{Name: "asset_type", Type: filterspec.TypeEnum, Enum: []string{"host"}, Ops: []filterspec.Op{filterspec.OpIn}, SQL: "x.asset_type"},
		filterspec.Field{Name: "secret", Type: filterspec.TypeBool, Ops: []filterspec.Op{filterspec.OpEq}, SQL: "x.secret"},
	)
	for name, suggested := range map[string][]string{
		"unknown":      {"nope"},
		"alias":        {"sev"},
		"relation raw": {"asset_type"},
		"internal":     {"secret"},
		"twice":        {"severity", "severity"},
	} {
		_, err := NewEntity(EntityDef{Name: "x", Permission: "p", Registry: reg,
			Paths: map[string]string{"asset.type": "asset_type"}, Aliases: map[string]string{"sev": "severity"},
			Internal: []string{"secret"}, Suggested: suggested})
		if err == nil {
			t.Errorf("%s: entity accepted suggested %v", name, suggested)
		}
	}
	if _, err := NewEntity(EntityDef{Name: "x", Permission: "p", Registry: reg,
		Paths: map[string]string{"asset.type": "asset_type"}, Suggested: []string{"asset.type", "severity"}}); err != nil {
		t.Errorf("valid suggested refused: %v", err)
	}
}

// The web console describes every field in plain words (en and vi): a path
// added to an entity needs its description in the queryFields catalogs.
func TestSchemaFieldsHaveDescriptions(t *testing.T) {
	for _, lang := range []string{"en", "vi"} {
		raw, err := os.ReadFile(filepath.Join("..", "..", "..", "web", "src", "lib", "i18n", "dictionaries", lang, "queryFields.json"))
		if err != nil {
			t.Fatalf("read %s catalog: %v", lang, err)
		}
		var dict map[string]string
		if err := json.Unmarshal(raw, &dict); err != nil {
			t.Fatalf("%s catalog: %v", lang, err)
		}
		for _, name := range EntityNames() {
			e, _ := Lookup(name)
			for _, f := range e.Schema(func(string) bool { return true }).Fields {
				if dict["queryFields."+name+"."+f.Path] == "" {
					t.Errorf("%s: no description for %s %s", lang, name, f.Path)
				}
			}
		}
	}
}
