// Command gen-asset-types reads configs/asset-types.yaml (the asset type
// registry, RFC-042 §6.3) and emits the generated Go and TypeScript files.
// It also prints, and checks, the SQL block that seeds asset_types and
// re-derives assets.asset_class / assets.asset_lens.
//
// Usage (from api/):
//
//	go run ./cmd/gen-asset-types          # write the Go and TS files
//	go run ./cmd/gen-asset-types -sql     # print the SQL block for a new migration
//	go run ./cmd/gen-asset-types -check   # fail if anything drifted (CI)
//
// Or `make generate-asset-types`, `make asset-types-sql` and
// `make asset-types-check`.
//
// -check fails when the committed Go file, TS file or the SQL block in the
// newest migration that carries the asset-type-registry markers differs from
// what the YAML produces. The generator never edits a migration: a registry
// change that touches class, lens or alias data needs a new migration.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"go/format"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Paths, relative to the api/ directory.
const (
	yamlPath         = "configs/asset-types.yaml"
	relationshipPath = "configs/relationship-types.yaml"
	goPath           = "pkg/domain/asset/registry_generated.go"
	tsPath           = "../web/src/features/asset-types/registry.generated.ts"
	migrationsDir    = "migrations"
)

// SQL block markers. The block between them in a migration must equal
// renderSQL's output.
const (
	sqlBeginMarker = "-- BEGIN asset-type-registry"
	sqlEndMarker   = "-- END asset-type-registry"
)

func main() {
	check := flag.Bool("check", false, "fail if the generated files or the newest migration block drifted from the YAML")
	printSQL := flag.Bool("sql", false, "print the SQL block for a new migration")
	flag.Parse()

	if err := run(*check, *printSQL); err != nil {
		fmt.Fprintf(os.Stderr, "gen-asset-types: %v\n", err)
		os.Exit(1)
	}
}

func run(check, printSQL bool) error {
	m, err := load(yamlPath, relationshipPath)
	if err != nil {
		return err
	}
	goSrc, err := renderGo(m)
	if err != nil {
		return fmt.Errorf("render go: %w", err)
	}
	tsSrc := renderTS(m)
	sqlSrc := renderSQL(m)

	switch {
	case printSQL:
		fmt.Print(sqlSrc)
		return nil
	case check:
		return checkDrift(goSrc, tsSrc, sqlSrc, migrationsDir)
	}

	if err := os.WriteFile(goPath, goSrc, 0o644); err != nil { //nolint:gosec // generated source, committed
		return err
	}
	if err := os.MkdirAll(filepath.Dir(tsPath), 0o755); err != nil { //nolint:gosec // source tree directory
		return err
	}
	if err := os.WriteFile(tsPath, []byte(tsSrc), 0o644); err != nil { //nolint:gosec // generated source, committed
		return err
	}
	fmt.Printf("generated %d asset types (%d classes, %d lenses), registry version %s:\n    %s\n    %s\n",
		len(m.Types), len(m.Classes), len(m.Lenses), m.Version, goPath, tsPath)
	return nil
}

// checkDrift compares the generated output with the committed files.
func checkDrift(goSrc []byte, tsSrc, sqlSrc, migDir string) error {
	var problems []string
	if cur, err := os.ReadFile(goPath); err != nil || !bytes.Equal(cur, goSrc) {
		problems = append(problems, goPath+" is out of date: run `make generate-asset-types`")
	}
	if cur, err := os.ReadFile(tsPath); err != nil || string(cur) != tsSrc {
		problems = append(problems, tsPath+" is out of date: run `make generate-asset-types`")
	}
	file, block, err := newestMigrationBlock(migDir)
	switch {
	case err != nil:
		problems = append(problems, err.Error())
	case block != sqlSrc:
		problems = append(problems, fmt.Sprintf(
			"%s: the asset-type-registry block does not match configs/asset-types.yaml. "+
				"Do not edit an applied migration: add a new one whose body is `make asset-types-sql`", file))
	}
	if len(problems) > 0 {
		return errors.New("asset type registry drift:\n  - " + strings.Join(problems, "\n  - "))
	}
	fmt.Println("asset type registry: YAML, generated code and migration block agree")
	return nil
}

// newestMigrationBlock returns the registry block of the highest-numbered
// *.up.sql file that has one.
func newestMigrationBlock(dir string) (string, string, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.up.sql"))
	if err != nil {
		return "", "", err
	}
	sort.Strings(files)
	for i := len(files) - 1; i >= 0; i-- {
		raw, err := os.ReadFile(files[i])
		if err != nil {
			return "", "", err
		}
		s := string(raw)
		b := strings.Index(s, sqlBeginMarker)
		if b < 0 {
			continue
		}
		e := strings.Index(s[b:], sqlEndMarker)
		if e < 0 {
			return files[i], "", fmt.Errorf("%s: %q without %q", files[i], sqlBeginMarker, sqlEndMarker)
		}
		end := b + e + len(sqlEndMarker)
		if end < len(s) && s[end] == '\n' {
			end++
		}
		return files[i], s[b:end], nil
	}
	return "", "", fmt.Errorf("no migration in %s carries the %q block", dir, sqlBeginMarker)
}

// =============================================================================
// YAML schema
// =============================================================================

type config struct {
	Lenses           []lensCfg    `yaml:"lenses"`
	Classes          []classCfg   `yaml:"classes"`
	LegacyCategories []idLabel    `yaml:"legacy_categories"`
	Cards            []string     `yaml:"cards"`
	Sections         []idLabel    `yaml:"sections"`
	CoreFields       []string     `yaml:"core_fields"`
	IdentityKinds    []string     `yaml:"identity_kinds"`
	VirtualTypes     []virtualCfg `yaml:"virtual_types"`
	Types            []typeCfg    `yaml:"types"`
}

type idLabel struct {
	ID    string `yaml:"id" json:"id"`
	Label string `yaml:"label" json:"label"`
}

type lensCfg struct {
	ID             string `yaml:"id"`
	Label          string `yaml:"label"`
	Description    string `yaml:"description"`
	Row            string `yaml:"row"`
	DefaultGroupBy string `yaml:"default_group_by"`
}

type classCfg struct {
	ID         string `yaml:"id"`
	Label      string `yaml:"label"`
	Lens       string `yaml:"lens"`
	JupiterOne string `yaml:"jupiterone"`
}

type virtualCfg struct {
	Name    string `yaml:"name"`
	Type    string `yaml:"type"`
	SubType string `yaml:"sub_type"`
}

type typeRef struct {
	Type    string `yaml:"type" json:"type"`
	SubType string `yaml:"sub_type" json:"sub_type,omitempty"`
}

type attrCfg struct {
	Name   string   `yaml:"name" json:"name"`
	Type   string   `yaml:"type" json:"type"`
	Values []string `yaml:"values" json:"values,omitempty"`
	Facet  bool     `yaml:"facet" json:"facet"`
	Group  bool     `yaml:"group" json:"group"`
}

type typeCfg struct {
	Type           string    `yaml:"type"`
	Label          string    `yaml:"label"`
	Plural         string    `yaml:"plural"`
	Icon           string    `yaml:"icon"`
	Class          string    `yaml:"class"`
	AliasOf        *typeRef  `yaml:"alias_of"`
	SubTypes       []string  `yaml:"sub_types"`
	LegacyCategory string    `yaml:"legacy_category"`
	Storage        string    `yaml:"storage"`
	IdentityKeys   []string  `yaml:"identity_keys"`
	Attributes     []attrCfg `yaml:"attributes"`
	Columns        []string  `yaml:"columns"`
	Card           string    `yaml:"card"`
	Sections       []string  `yaml:"sections"`
}

type relConfig struct {
	Types []struct {
		ID          string `yaml:"id"`
		Constraints []struct {
			Sources []string `yaml:"sources"`
			Targets []string `yaml:"targets"`
		} `yaml:"constraints"`
	} `yaml:"types"`
}

// =============================================================================
// Resolved model (JSON tags match pkg/domain/asset.Registry; the version is
// the hash of this model's JSON)
// =============================================================================

type model struct {
	Version          string       `json:"-"`
	Lenses           []lensOut    `json:"lenses"`
	Classes          []classOut   `json:"classes"`
	Types            []typeOut    `json:"types"`
	Sections         []idLabel    `json:"sections"`
	Cards            []string     `json:"cards"`
	CoreFields       []string     `json:"core_fields"`
	LegacyCategories []idLabel    `json:"legacy_categories"`
	VirtualTypes     []virtualCfg `json:"-"`
}

type lensOut struct {
	ID             string   `json:"id"`
	Label          string   `json:"label"`
	Description    string   `json:"description"`
	Row            string   `json:"row"`
	DefaultGroupBy string   `json:"default_group_by"`
	Classes        []string `json:"classes"`
}

type classOut struct {
	ID         string   `json:"id"`
	Label      string   `json:"label"`
	Lens       string   `json:"lens,omitempty"`
	JupiterOne string   `json:"jupiterone"`
	Types      []string `json:"types"`
}

type relRule struct {
	Relationship string    `json:"relationship"`
	Peers        []typeRef `json:"peers"`
}

type typeRels struct {
	Out []relRule `json:"out"`
	In  []relRule `json:"in"`
}

type typeOut struct {
	Type           string    `json:"type"`
	Label          string    `json:"label"`
	Plural         string    `json:"plural"`
	Icon           string    `json:"icon"`
	Class          string    `json:"class"`
	Lens           string    `json:"lens,omitempty"`
	AliasOf        *typeRef  `json:"alias_of,omitempty"`
	SubTypes       []string  `json:"sub_types"`
	LegacyCategory string    `json:"legacy_category"`
	Storage        string    `json:"storage"`
	IdentityKeys   []string  `json:"identity_keys"`
	Attributes     []attrCfg `json:"attributes"`
	Facets         []string  `json:"facets"`
	GroupBy        []string  `json:"group_by"`
	Columns        []string  `json:"columns"`
	Card           string    `json:"card"`
	Sections       []string  `json:"sections"`
	Relationships  typeRels  `json:"relationships"`
}

// =============================================================================
// Load, validate, resolve
// =============================================================================

var identRe = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

const (
	classOther = "other"
	// fieldName is the core field every row starts with and the identity key
	// every type ends with (the exact-name match).
	fieldName = "name"
)

func decodeStrict(path string, out any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(out); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

func load(registryPath, relPath string) (*model, error) {
	var cfg config
	if err := decodeStrict(registryPath, &cfg); err != nil {
		return nil, err
	}
	var rel relConfig
	raw, err := os.ReadFile(relPath)
	if err != nil {
		return nil, err
	}
	if err := yaml.Unmarshal(raw, &rel); err != nil {
		return nil, fmt.Errorf("%s: %w", relPath, err)
	}
	m, err := resolve(&cfg, &rel)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", registryPath, err)
	}
	return m, nil
}

func set(items []string) map[string]bool {
	s := make(map[string]bool, len(items))
	for _, i := range items {
		s[i] = true
	}
	return s
}

func idSet(items []idLabel) map[string]bool {
	s := make(map[string]bool, len(items))
	for _, i := range items {
		s[i.ID] = true
	}
	return s
}

func dup(kind string, items []string) error {
	seen := map[string]bool{}
	for _, i := range items {
		if !identRe.MatchString(strings.ReplaceAll(i, ".", "_")) {
			return fmt.Errorf("%s %q: must be lower snake_case", kind, i)
		}
		if seen[i] {
			return fmt.Errorf("duplicate %s %q", kind, i)
		}
		seen[i] = true
	}
	return nil
}

// reservedSlugs are the fixed page segments under the web inventory URL
// /assets/<segment> (static routes that sit next to /assets/[id]). Lens,
// class and type ids travel in inventory URLs (?lens=, ?types=, q=type:),
// and RFC-042 folds the typed pages into lenses, so an id that equals one of
// these segments would read as, or later collide with, a page such as
// /assets/groups. Keep in sync with the folders in
// web/src/app/(dashboard)/(discovery)/assets/ and RFC-042 §6.3.6 URLs.
var reservedSlugs = set([]string{"all", "changes", "duplicates", "groups", "services", "suggestions"})

var attrKinds = set([]string{"string", "int", "number", "bool", "time", "enum", "list", "object"})
var facetKinds = set([]string{"string", "int", "enum", "bool"})

// resolve validates the configuration and builds the model. Every rule here
// is also asserted on the generated data by pkg/domain/asset registry_test.
func resolve(cfg *config, rel *relConfig) (*model, error) { //nolint:gocognit,gocyclo,cyclop // one linear validation pass
	ids := func(xs []idLabel) []string {
		out := make([]string, len(xs))
		for i, x := range xs {
			out[i] = x.ID
		}
		return out
	}
	lensIDs := make([]string, len(cfg.Lenses))
	for i, l := range cfg.Lenses {
		lensIDs[i] = l.ID
		if l.Label == "" || l.Row == "" || l.DefaultGroupBy == "" {
			return nil, fmt.Errorf("lens %q: label, row and default_group_by are required", l.ID)
		}
	}
	classIDs := make([]string, len(cfg.Classes))
	for i, c := range cfg.Classes {
		classIDs[i] = c.ID
	}
	typeIDs := make([]string, len(cfg.Types))
	for i, t := range cfg.Types {
		typeIDs[i] = t.Type
	}
	for kind, items := range map[string][]string{
		"lens": lensIDs, "class": classIDs, "type": typeIDs, "card": cfg.Cards,
		"section": ids(cfg.Sections), "legacy category": ids(cfg.LegacyCategories),
		"core field": cfg.CoreFields, "identity kind": cfg.IdentityKinds,
	} {
		if len(items) == 0 {
			return nil, fmt.Errorf("no %s defined", kind)
		}
		if err := dup(kind, items); err != nil {
			return nil, err
		}
		if kind == "lens" || kind == "class" || kind == "type" {
			for _, id := range items {
				if reservedSlugs[id] {
					return nil, fmt.Errorf("%s %q: reserved, it is a page under /assets/ in the web", kind, id)
				}
			}
		}
	}

	lenses, classes, types := set(lensIDs), set(classIDs), set(typeIDs)
	cards, sections := set(cfg.Cards), idSet(cfg.Sections)
	categories, coreFields, identityKinds := idSet(cfg.LegacyCategories), set(cfg.CoreFields), set(cfg.IdentityKinds)
	if !classes[classOther] {
		return nil, fmt.Errorf("class %q is required", classOther)
	}

	m := &model{
		Sections:         cfg.Sections,
		Cards:            cfg.Cards,
		CoreFields:       cfg.CoreFields,
		LegacyCategories: cfg.LegacyCategories,
		VirtualTypes:     cfg.VirtualTypes,
	}
	classLens := map[string]string{}
	for _, c := range cfg.Classes {
		switch {
		case c.Label == "":
			return nil, fmt.Errorf("class %q: label is required", c.ID)
		case c.ID == classOther && c.Lens != "":
			return nil, fmt.Errorf("class %q must not have a lens (it shows under All assets only)", c.ID)
		case c.ID != classOther && !lenses[c.Lens]:
			return nil, fmt.Errorf("class %q: unknown lens %q", c.ID, c.Lens)
		}
		classLens[c.ID] = c.Lens
	}

	byType := map[string]*typeCfg{}
	for i := range cfg.Types {
		byType[cfg.Types[i].Type] = &cfg.Types[i]
	}
	aliasPairs := map[typeRef]string{}
	classTypes := map[string][]string{}
	for i := range cfg.Types {
		t := &cfg.Types[i]
		where := "type " + t.Type
		switch {
		case t.Label == "" || t.Plural == "" || t.Icon == "":
			return nil, fmt.Errorf("%s: label, plural and icon are required", where)
		case !classes[t.Class]:
			return nil, fmt.Errorf("%s: unknown class %q", where, t.Class)
		case !categories[t.LegacyCategory]:
			return nil, fmt.Errorf("%s: unknown legacy_category %q", where, t.LegacyCategory)
		case !cards[t.Card]:
			return nil, fmt.Errorf("%s: unknown card %q", where, t.Card)
		case len(t.Sections) == 0 || t.Sections[0] != "overview":
			return nil, fmt.Errorf("%s: sections must start with overview", where)
		case len(t.Columns) == 0 || t.Columns[0] != fieldName:
			return nil, fmt.Errorf("%s: columns must start with name", where)
		case len(t.IdentityKeys) == 0 || t.IdentityKeys[len(t.IdentityKeys)-1] != fieldName:
			return nil, fmt.Errorf("%s: identity_keys must end with name (the exact-name fallback)", where)
		}
		if err := dup(where+" sub_type", t.SubTypes); err != nil {
			return nil, err
		}
		if err := dup(where+" section", t.Sections); err != nil {
			return nil, err
		}
		for _, s := range t.Sections {
			if !sections[s] {
				return nil, fmt.Errorf("%s: unknown section %q", where, s)
			}
		}
		if t.AliasOf != nil {
			core, ok := byType[t.AliasOf.Type]
			switch {
			case !ok:
				return nil, fmt.Errorf("%s: alias_of unknown type %q", where, t.AliasOf.Type)
			case core.AliasOf != nil:
				return nil, fmt.Errorf("%s: alias_of %q, which is itself an alias", where, t.AliasOf.Type)
			case t.AliasOf.SubType == "":
				return nil, fmt.Errorf("%s: alias_of needs a sub_type", where)
			}
			if other, taken := aliasPairs[*t.AliasOf]; taken {
				return nil, fmt.Errorf("%s: alias_of %v is already used by %s", where, *t.AliasOf, other)
			}
			aliasPairs[*t.AliasOf] = t.Type
		}

		attrNames := map[string]bool{}
		var facets, groupBy []string
		for _, a := range t.Attributes {
			aw := fmt.Sprintf("%s attribute %q", where, a.Name)
			switch {
			case !identRe.MatchString(a.Name):
				return nil, fmt.Errorf("%s: name must be lower snake_case", aw)
			case attrNames[a.Name]:
				return nil, fmt.Errorf("%s: duplicate", aw)
			case !attrKinds[a.Type]:
				return nil, fmt.Errorf("%s: unknown type %q", aw, a.Type)
			case a.Type == "enum" && len(a.Values) == 0:
				return nil, fmt.Errorf("%s: enum needs values", aw)
			case a.Type != "enum" && len(a.Values) > 0:
				return nil, fmt.Errorf("%s: only enums take values", aw)
			case (a.Facet || a.Group) && !facetKinds[a.Type]:
				return nil, fmt.Errorf("%s: a %s attribute cannot be a facet or group-by field", aw, a.Type)
			case coreFields[a.Name]:
				return nil, fmt.Errorf("%s: shadows the core field of the same name", aw)
			}
			attrNames[a.Name] = true
			if a.Facet {
				facets = append(facets, t.Type+"."+a.Name)
			}
			if a.Group {
				groupBy = append(groupBy, t.Type+"."+a.Name)
			}
		}
		for _, c := range t.Columns {
			if !coreFields[c] && !attrNames[c] {
				return nil, fmt.Errorf("%s: column %q is neither a core field nor an attribute", where, c)
			}
		}
		for _, k := range t.IdentityKeys {
			attr, isAttr := strings.CutPrefix(k, "attr.")
			switch {
			case k == fieldName, identityKinds[k]:
			case isAttr && attrNames[attr]:
			default:
				return nil, fmt.Errorf("%s: identity key %q is not an RFC-028 identifier kind, name, or attr.<attribute>", where, k)
			}
		}

		storage := t.Storage
		if storage == "" {
			storage = "core"
		}
		out := typeOut{
			Type: t.Type, Label: t.Label, Plural: t.Plural, Icon: t.Icon,
			Class: t.Class, Lens: classLens[t.Class], AliasOf: t.AliasOf,
			SubTypes: nonNil(t.SubTypes), LegacyCategory: t.LegacyCategory, Storage: storage,
			IdentityKeys: t.IdentityKeys, Attributes: nonNilAttrs(t.Attributes),
			Facets: nonNil(facets), GroupBy: nonNil(groupBy),
			Columns: t.Columns, Card: t.Card, Sections: t.Sections,
		}
		m.Types = append(m.Types, out)
		classTypes[t.Class] = append(classTypes[t.Class], t.Type)
	}

	for _, c := range cfg.Classes {
		if len(classTypes[c.ID]) == 0 {
			return nil, fmt.Errorf("class %q has no types", c.ID)
		}
		m.Classes = append(m.Classes, classOut{ID: c.ID, Label: c.Label, Lens: c.Lens, JupiterOne: c.JupiterOne, Types: classTypes[c.ID]})
	}
	for _, l := range cfg.Lenses {
		var cs []string
		for _, c := range cfg.Classes {
			if c.Lens == l.ID {
				cs = append(cs, c.ID)
			}
		}
		if len(cs) == 0 {
			return nil, fmt.Errorf("lens %q has no classes", l.ID)
		}
		m.Lenses = append(m.Lenses, lensOut{ID: l.ID, Label: l.Label, Description: l.Description, Row: l.Row, DefaultGroupBy: l.DefaultGroupBy, Classes: cs})
	}

	if err := resolveRelationships(m, types, rel); err != nil {
		return nil, err
	}

	raw, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(raw)
	m.Version = hex.EncodeToString(sum[:8])
	return m, nil
}

// resolveRelationships turns the constraints of relationship-types.yaml into
// per-type out/in rules over real types. A constraint name is a registry
// type or a virtual type declared in asset-types.yaml; anything else fails,
// so the constraints can no longer name types the backend does not have.
func resolveRelationships(m *model, types map[string]bool, rel *relConfig) error {
	virtual := map[string]typeRef{}
	for _, v := range m.VirtualTypes {
		switch {
		case types[v.Name]:
			return fmt.Errorf("virtual type %q shadows a registry type", v.Name)
		case !types[v.Type]:
			return fmt.Errorf("virtual type %q: unknown type %q", v.Name, v.Type)
		}
		if _, dupName := virtual[v.Name]; dupName {
			return fmt.Errorf("duplicate virtual type %q", v.Name)
		}
		virtual[v.Name] = typeRef{Type: v.Type, SubType: v.SubType}
	}
	resolveName := func(rt, name string) (typeRef, error) {
		if types[name] {
			return typeRef{Type: name}, nil
		}
		if v, ok := virtual[name]; ok {
			return v, nil
		}
		return typeRef{}, fmt.Errorf("%s: relationship %q names %q, which is neither an asset type nor a virtual_types entry", relationshipPath, rt, name)
	}

	type key struct{ typ, rel string }
	out, in := map[key][]typeRef{}, map[key][]typeRef{}
	add := func(m map[key][]typeRef, k key, r typeRef) {
		for _, x := range m[k] {
			if x == r {
				return
			}
		}
		m[k] = append(m[k], r)
	}
	relOrder := make([]string, 0, len(rel.Types))
	for _, rt := range rel.Types {
		relOrder = append(relOrder, rt.ID)
		for _, c := range rt.Constraints {
			for _, s := range c.Sources {
				src, err := resolveName(rt.ID, s)
				if err != nil {
					return err
				}
				for _, t := range c.Targets {
					tgt, err := resolveName(rt.ID, t)
					if err != nil {
						return err
					}
					add(out, key{src.Type, rt.ID}, tgt)
					add(in, key{tgt.Type, rt.ID}, src)
				}
			}
		}
	}
	for i := range m.Types {
		t := &m.Types[i]
		t.Relationships = typeRels{Out: []relRule{}, In: []relRule{}}
		for _, r := range relOrder {
			if peers := out[key{t.Type, r}]; len(peers) > 0 {
				t.Relationships.Out = append(t.Relationships.Out, relRule{Relationship: r, Peers: peers})
			}
			if peers := in[key{t.Type, r}]; len(peers) > 0 {
				t.Relationships.In = append(t.Relationships.In, relRule{Relationship: r, Peers: peers})
			}
		}
	}
	return nil
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func nonNilAttrs(s []attrCfg) []attrCfg {
	if s == nil {
		return []attrCfg{}
	}
	return s
}

// =============================================================================
// Go
// =============================================================================

func goIdent(prefix, id string) string {
	var b strings.Builder
	b.WriteString(prefix)
	for _, part := range strings.FieldsFunc(id, func(r rune) bool { return r == '_' || r == '-' }) {
		switch part {
		case "ip", "api", "url", "id":
			b.WriteString(strings.ToUpper(part)) // Go initialisms: ClassIPAddress
		default:
			b.WriteString(strings.ToUpper(part[:1]) + part[1:])
		}
	}
	return b.String()
}

func goStrings(items []string) string {
	q := make([]string, len(items))
	for i, s := range items {
		q[i] = fmt.Sprintf("%q", s)
	}
	return "[]string{" + strings.Join(q, ", ") + "}"
}

func goTyped(typ, prefix string, items []string) string {
	q := make([]string, len(items))
	for i, s := range items {
		q[i] = goIdent(prefix, s)
	}
	return "[]" + typ + "{" + strings.Join(q, ", ") + "}"
}

func goTypeRef(r typeRef) string {
	if r.SubType == "" {
		return fmt.Sprintf("{Type: %q}", r.Type)
	}
	return fmt.Sprintf("{Type: %q, SubType: %q}", r.Type, r.SubType)
}

func goRules(rules []relRule) string {
	var b strings.Builder
	b.WriteString("[]RelationshipRule{")
	for _, r := range rules {
		refs := make([]string, len(r.Peers))
		for i, p := range r.Peers {
			refs[i] = goTypeRef(p)
		}
		fmt.Fprintf(&b, "\n{Relationship: %q, Peers: []TypeRef{%s}},", r.Relationship, strings.Join(refs, ", "))
	}
	if len(rules) > 0 {
		b.WriteString("\n")
	}
	b.WriteString("}")
	return b.String()
}

func renderGo(m *model) ([]byte, error) {
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format, args...) }

	w("// Code generated by api/cmd/gen-asset-types. DO NOT EDIT.\n//\n")
	w("// Source of truth: api/configs/asset-types.yaml (RFC-042 §6.3).\n")
	w("// Run `make generate-asset-types` to regenerate.\n\npackage asset\n\n")
	w("// RegistryVersion identifies this registry. It changes whenever the\n// registry content changes.\nconst RegistryVersion = %q\n\n", m.Version)

	w("// Lenses.\nconst (\n")
	for _, l := range m.Lenses {
		w("%s Lens = %q\n", goIdent("Lens", l.ID), l.ID)
	}
	w(")\n\n// Classes.\nconst (\n")
	for _, c := range m.Classes {
		w("%s Class = %q\n", goIdent("Class", c.ID), c.ID)
	}
	w(")\n\n// Legacy categories (the `category` field of asset responses).\nconst (\n")
	for _, c := range m.LegacyCategories {
		w("%s Category = %q\n", goIdent("Category", c.ID), c.ID)
	}
	w(")\n\n")

	w("var registryLenses = []LensDefinition{\n")
	for _, l := range m.Lenses {
		w("{ID: %s, Label: %q, Description: %q, Row: %q, DefaultGroupBy: %q, Classes: %s},\n",
			goIdent("Lens", l.ID), l.Label, l.Description, l.Row, l.DefaultGroupBy, goTyped("Class", "Class", l.Classes))
	}
	w("}\n\nvar registryClasses = []ClassDefinition{\n")
	for _, c := range m.Classes {
		lens := `""`
		if c.Lens != "" {
			lens = goIdent("Lens", c.Lens)
		}
		types := make([]string, len(c.Types))
		for i, t := range c.Types {
			types[i] = fmt.Sprintf("%q", t)
		}
		w("{ID: %s, Label: %q, Lens: %s, JupiterOne: %q, Types: []AssetType{%s}},\n",
			goIdent("Class", c.ID), c.Label, lens, c.JupiterOne, strings.Join(types, ", "))
	}
	w("}\n\nvar registryTypes = []TypeDefinition{\n")
	for _, t := range m.Types {
		w("{\nType: %q,\nLabel: %q,\nPlural: %q,\nIcon: %q,\nClass: %s,\n", t.Type, t.Label, t.Plural, t.Icon, goIdent("Class", t.Class))
		if t.Lens != "" {
			w("Lens: %s,\n", goIdent("Lens", t.Lens))
		}
		if t.AliasOf != nil {
			w("AliasOf: &TypeRef%s,\n", goTypeRef(*t.AliasOf))
		}
		w("SubTypes: %s,\nLegacyCategory: %s,\nStorage: %q,\nIdentityKeys: %s,\n",
			goStrings(t.SubTypes), goIdent("Category", t.LegacyCategory), t.Storage, goStrings(t.IdentityKeys))
		w("Attributes: []AttributeDefinition{")
		for _, a := range t.Attributes {
			w("\n{Name: %q, Kind: %q", a.Name, a.Type)
			if len(a.Values) > 0 {
				w(", Values: %s", goStrings(a.Values))
			}
			if a.Facet {
				w(", Facet: true")
			}
			if a.Group {
				w(", Group: true")
			}
			w("},")
		}
		if len(t.Attributes) > 0 {
			w("\n")
		}
		w("},\nFacets: %s,\nGroupBy: %s,\nColumns: %s,\nCard: %q,\nSections: %s,\n",
			goStrings(t.Facets), goStrings(t.GroupBy), goStrings(t.Columns), t.Card, goStrings(t.Sections))
		w("Relationships: TypeRelationships{\nOut: %s,\nIn: %s,\n},\n},\n", goRules(t.Relationships.Out), goRules(t.Relationships.In))
	}
	w("}\n\nvar registrySections = []SectionDefinition{\n")
	for _, s := range m.Sections {
		w("{ID: %q, Label: %q},\n", s.ID, s.Label)
	}
	w("}\n\nvar registryCards = %s\n\nvar registryCoreFields = %s\n\n", goStrings(m.Cards), goStrings(m.CoreFields))
	w("var registryLegacyCategories = []legacyCategoryDefinition{\n")
	for _, c := range m.LegacyCategories {
		w("{ID: %s, Label: %q},\n", goIdent("Category", c.ID), c.Label)
	}
	w("}\n\n")
	w("// TypeAliases maps legacy types to their consolidated core type + sub_type,\n")
	w("// from the `alias_of` entries of the registry. Used by ingest to normalize\n// incoming data.\n")
	w("var TypeAliases = map[AssetType]struct {\nCoreType AssetType\nSubType  string\n}{\n")
	for _, t := range m.Types {
		if t.AliasOf != nil {
			w("%q: {CoreType: %q, SubType: %q},\n", t.Type, t.AliasOf.Type, t.AliasOf.SubType)
		}
	}
	w("}\n")
	return format.Source([]byte(b.String()))
}

// =============================================================================
// TypeScript
// =============================================================================

// tsUnion renders a string-literal union one member per line, the shape
// prettier gives a union longer than the print width.
func tsUnion(items []string) string {
	var b strings.Builder
	for _, s := range items {
		fmt.Fprintf(&b, "\n  | '%s'", s)
	}
	return b.String()
}

func tsString(s string) string {
	return "'" + strings.ReplaceAll(strings.ReplaceAll(s, `\`, `\\`), "'", `\'`) + "'"
}

func renderTS(m *model) string {
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format, args...) }
	lensIDs := make([]string, len(m.Lenses))
	for i, l := range m.Lenses {
		lensIDs[i] = l.ID
	}
	classIDs := make([]string, len(m.Classes))
	for i, c := range m.Classes {
		classIDs[i] = c.ID
	}
	typeIDs := make([]string, len(m.Types))
	for i, t := range m.Types {
		typeIDs[i] = t.Type
	}
	catIDs := make([]string, len(m.LegacyCategories))
	for i, c := range m.LegacyCategories {
		catIDs[i] = c.ID
	}

	w("/**\n * Code generated by api/cmd/gen-asset-types. DO NOT EDIT.\n *\n")
	w(" * Source of truth: api/configs/asset-types.yaml (RFC-042 §6.3).\n")
	w(" * Run `make generate-asset-types` in api/ to regenerate.\n *\n")
	w(" * The full registry (attributes, facets, columns, sections, relationships)\n")
	w(" * is served by GET /api/v1/asset-types; this file carries the closed sets\n")
	w(" * and labels for compile-time checks and for rendering before it loads.\n */\n\n")
	w("export const ASSET_REGISTRY_VERSION = '%s'\n\n", m.Version)
	w("export type AssetLens =%s\n\n", tsUnion(lensIDs))
	w("export type AssetClass =%s\n\n", tsUnion(classIDs))
	w("export type RegistryAssetType =%s\n\n", tsUnion(typeIDs))
	w("export type LegacyAssetCategory =%s\n\n", tsUnion(catIDs))

	w("export const ASSET_LENSES: ReadonlyArray<{\n  id: AssetLens\n  label: string\n  classes: readonly AssetClass[]\n}> = [\n")
	for _, l := range m.Lenses {
		cs := make([]string, len(l.Classes))
		for i, c := range l.Classes {
			cs[i] = "'" + c + "'"
		}
		w("  {\n    id: '%s',\n    label: %s,\n    classes: [%s],\n  },\n", l.ID, tsString(l.Label), strings.Join(cs, ", "))
	}
	w("]\n\n")
	w("export const ASSET_CLASSES: ReadonlyArray<{\n  id: AssetClass\n  label: string\n  lens: AssetLens | null\n}> = [\n")
	for _, c := range m.Classes {
		lens := "null"
		if c.Lens != "" {
			lens = "'" + c.Lens + "'"
		}
		w("  { id: '%s', label: %s, lens: %s },\n", c.ID, tsString(c.Label), lens)
	}
	w("]\n\n")
	w("/** The class of each type. Stored aliases keep their own class: see ASSET_ALIAS_CLASSES. */\n")
	w("export const ASSET_TYPE_CLASSES: Readonly<Record<RegistryAssetType, AssetClass>> = {\n")
	for _, t := range m.Types {
		w("  %s: '%s',\n", t.Type, t.Class)
	}
	w("}\n\n")
	w("/**\n * Stored (type, sub_type) pairs whose class differs from the type's class,\n")
	w(" * keyed `type/sub_type`: a host with sub_type serverless is a function.\n */\n")
	w("export const ASSET_ALIAS_CLASSES: Readonly<Record<string, AssetClass>> = {\n")
	for _, t := range m.Types {
		if t.AliasOf == nil {
			continue
		}
		var core string
		for _, c := range m.Types {
			if c.Type == t.AliasOf.Type {
				core = c.Class
			}
		}
		if core != t.Class {
			w("  '%s/%s': '%s',\n", t.AliasOf.Type, t.AliasOf.SubType, t.Class)
		}
	}
	w("}\n\n")
	w("export const LEGACY_ASSET_CATEGORY_LABELS: Readonly<Record<LegacyAssetCategory, string>> = {\n")
	for _, c := range m.LegacyCategories {
		w("  %s: %s,\n", c.ID, tsString(c.Label))
	}
	w("}\n")
	return b.String()
}

// =============================================================================
// SQL
// =============================================================================

func sqlString(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

func sqlNullable(s string) string {
	if s == "" {
		return "NULL"
	}
	return sqlString(s)
}

func sqlList(items []string) string {
	q := make([]string, len(items))
	for i, s := range items {
		q[i] = sqlString(s)
	}
	return strings.Join(q, ", ")
}

// renderSQL is the migration block: the class and lens CHECKs, one upsert
// row per registry type, `other` for every legacy code, and the backfill of
// assets.asset_class / asset_lens (asset_registry_backfill, created by the
// migration that introduced the columns).
func renderSQL(m *model) string {
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format, args...) }
	classIDs := make([]string, len(m.Classes))
	for i, c := range m.Classes {
		classIDs[i] = c.ID
	}
	lensIDs := make([]string, len(m.Lenses))
	for i, l := range m.Lenses {
		lensIDs[i] = l.ID
	}
	typeIDs := make([]string, len(m.Types))
	for i, t := range m.Types {
		typeIDs[i] = t.Type
	}

	w("%s (registry version %s)\n", sqlBeginMarker, m.Version)
	w("-- Generated from api/configs/asset-types.yaml by `make asset-types-sql`.\n")
	w("-- Do not edit: `go run ./cmd/gen-asset-types -check` compares this block\n-- with the YAML.\n")
	w("ALTER TABLE asset_types DROP CONSTRAINT IF EXISTS chk_asset_types_class;\n")
	w("ALTER TABLE asset_types ADD CONSTRAINT chk_asset_types_class CHECK (class IN (%s));\n", sqlList(classIDs))
	w("ALTER TABLE asset_types DROP CONSTRAINT IF EXISTS chk_asset_types_lens;\n")
	w("ALTER TABLE asset_types ADD CONSTRAINT chk_asset_types_lens CHECK (lens IS NULL OR lens IN (%s));\n", sqlList(lensIDs))
	w("\nINSERT INTO asset_types (code, name, class, lens, alias_of, alias_sub_type) VALUES\n")
	for i, t := range m.Types {
		alias, sub := "", ""
		if t.AliasOf != nil {
			alias, sub = t.AliasOf.Type, t.AliasOf.SubType
		}
		sep := ","
		if i == len(m.Types)-1 {
			sep = ""
		}
		w("    (%s, %s, %s, %s, %s, %s)%s\n", sqlString(t.Type), sqlString(t.Label), sqlString(t.Class),
			sqlNullable(t.Lens), sqlNullable(alias), sqlNullable(sub), sep)
	}
	w("ON CONFLICT (code) DO UPDATE SET\n    class = EXCLUDED.class,\n    lens = EXCLUDED.lens,\n")
	w("    alias_of = EXCLUDED.alias_of,\n    alias_sub_type = EXCLUDED.alias_sub_type;\n\n")
	w("-- Codes that are not registry types (legacy rows kept for the assets FK).\n")
	w("UPDATE asset_types SET class = 'other', lens = NULL, alias_of = NULL, alias_sub_type = NULL\n")
	w("WHERE code NOT IN (%s);\n\n", sqlList(typeIDs))
	w("-- Re-derive assets.asset_class / asset_lens in batches, without touching\n-- updated_at.\n")
	w("ALTER TABLE assets DISABLE TRIGGER trigger_assets_updated_at;\n")
	w("DO $$\nDECLARE\n    cursor_id uuid := NULL;\nBEGIN\n    LOOP\n")
	w("        SELECT b.last_id INTO cursor_id FROM asset_registry_backfill(cursor_id, 5000) b;\n")
	w("        EXIT WHEN cursor_id IS NULL;\n    END LOOP;\nEND $$;\n")
	w("ALTER TABLE assets ENABLE TRIGGER trigger_assets_updated_at;\n")
	w("%s\n", sqlEndMarker)
	return b.String()
}
