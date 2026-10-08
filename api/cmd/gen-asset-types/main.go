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
// change that touches class, lens or alias data needs a new migration. When
// no migration above the migration baseline carries the block (RFC-053: the
// baseline is a pg_dump and keeps no markers), the migration half is checked
// against a migrated database instead (TestAssetTypeRegistry_* in
// internal/infra/postgres).
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
	"slices"
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
	case errors.Is(err, errNoRegistryMigration):
		fmt.Println("asset type registry: no migration above the baseline carries the block; " +
			"the database tests (TestAssetTypeRegistry_*) compare the schema with the YAML")
	case err != nil:
		problems = append(problems, err.Error())
	case block != sqlSrc:
		problems = append(problems, fmt.Sprintf(
			"%s: the asset-type-registry block does not match configs/asset-types.yaml. "+
				"Do not edit an applied migration: add a new one whose body is `make asset-types-sql`", file))
	case strings.Contains(block, "chk_assets_core_type CHECK") && strings.Contains(block, "NOT VALID") && !validatesAfterBlock(file):
		problems = append(problems, fmt.Sprintf(
			"%s: the block adds chk_assets_core_type NOT VALID; validate it after the block "+
				"(%q), once the rows the registry change moves are moved", file, validateCoreType))
	}
	if len(problems) > 0 {
		return errors.New("asset type registry drift:\n  - " + strings.Join(problems, "\n  - "))
	}
	if file != "" {
		fmt.Println("asset type registry: YAML, generated code and migration block agree")
	}
	return nil
}

// errNoRegistryMigration: no migration carries the asset-type-registry block.
var errNoRegistryMigration = errors.New("no migration carries the asset-type-registry block")

// validateCoreType is the statement a registry migration runs after its block.
const validateCoreType = "ALTER TABLE assets VALIDATE CONSTRAINT chk_assets_core_type;"

// validatesAfterBlock reports whether the migration validates the core-type
// CHECK after its registry block.
func validatesAfterBlock(file string) bool {
	raw, err := os.ReadFile(file)
	if err != nil {
		return false
	}
	s := string(raw)
	end := strings.Index(s, sqlEndMarker)
	if end < 0 {
		return false
	}
	return strings.Contains(s[end:], validateCoreType)
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
	return "", "", fmt.Errorf("%s: %w", dir, errNoRegistryMigration)
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
	// TypeInputs maps a legacy type name that is still accepted on input,
	// but is no type of its own, to what it is stored as (RFC-042 §6.3.8:
	// web_application is stored as (application, website), O3).
	TypeInputs map[string]inputCfg `yaml:"type_inputs"`
	// CommonProperties are the property keys every type may hold (platform
	// keys and the CTIS technical blocks), Properties the dictionary of every
	// property key (RFC-042 §6.3.9).
	CommonProperties []string           `yaml:"common_properties"`
	Properties       map[string]propCfg `yaml:"properties"`
	Types            []typeCfg          `yaml:"types"`
}

// propCfg is one property dictionary entry.
type propCfg struct {
	Label    string   `yaml:"label"`
	LabelVI  string   `yaml:"label_vi"`
	Format   string   `yaml:"format"`
	Synonyms []string `yaml:"synonyms"`
	Classes  []string `yaml:"classes"`
}

// propOut is one property of the resolved model, in key order.
type propOut struct {
	Key      string   `json:"key"`
	Label    string   `json:"label"`
	LabelVI  string   `json:"label_vi"`
	Format   string   `json:"format,omitempty"`
	Synonyms []string `json:"synonyms,omitempty"`
	Classes  []string `json:"classes,omitempty"`
	// List: every type declares the key as a list, so synonyms fold into
	// one array; otherwise a synonym's value moves to the key unchanged.
	List bool `json:"list,omitempty"`
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
	ID    string `yaml:"id"`
	Label string `yaml:"label"`
	Lens  string `yaml:"lens"`
}

type virtualCfg struct {
	Name    string `yaml:"name"`
	Type    string `yaml:"type"`
	SubType string `yaml:"sub_type"`
	// Unmodelled marks a name the relationship constraints use for a
	// concept that has no core type yet (for example `credential`, a secret:
	// RFC-042 §6.3.8 O4). Its constraints are skipped, not resolved to a
	// wrong type.
	Unmodelled bool `yaml:"unmodelled"`
}

// inputCfg is what an input resolves to: a core type (the declaring type
// when empty), a sub-type from that type's closed list ("" for none), an
// assets.provider value and attribute values. Provider and attributes are
// only set when the asset has none: an existing value is never overwritten.
type inputCfg struct {
	Type       string            `yaml:"type" json:"type,omitempty"`
	SubType    string            `yaml:"sub_type" json:"sub_type,omitempty"`
	Provider   string            `yaml:"provider" json:"provider,omitempty"`
	Attributes map[string]string `yaml:"attributes" json:"attributes,omitempty"`
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
	Type     string    `yaml:"type"`
	Label    string    `yaml:"label"`
	Plural   string    `yaml:"plural"`
	Icon     string    `yaml:"icon"`
	Class    string    `yaml:"class"`
	AliasOf  *inputCfg `yaml:"alias_of"`
	SubTypes []string  `yaml:"sub_types"`
	// SubTypeInputs maps a legacy sub-type value, still accepted on input,
	// to what it is stored as (RFC-042 §6.3.8 R2).
	SubTypeInputs map[string]inputCfg `yaml:"sub_type_inputs"`
	// ScannableBy lists the tool target types (a tool's supported_targets
	// vocabulary) that can scan the type. On an alias it is the sub-type's
	// own list; otherwise an alias inherits its core type's list.
	ScannableBy []string `yaml:"scannable_by"`
	// ExposureDefault is the exposure an asset has by nature (domains and
	// web applications are internet-facing); ingest applies it when the
	// scanner sent none. "" = no default.
	ExposureDefault string    `yaml:"exposure_default"`
	LegacyCategory  string    `yaml:"legacy_category"`
	Storage         string    `yaml:"storage"`
	IdentityKeys    []string  `yaml:"identity_keys"`
	Attributes      []attrCfg `yaml:"attributes"`
	Columns         []string  `yaml:"columns"`
	Card            string    `yaml:"card"`
	Sections        []string  `yaml:"sections"`
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
	Version string `json:"-"`
	// Inputs maps every accepted input (type, sub_type) that is not stored
	// as such to what it is stored as: aliases (sub_type "") and the legacy
	// sub-types of core types. Part of the version hash.
	Inputs           []inputOut   `json:"inputs"`
	Lenses           []lensOut    `json:"lenses"`
	Classes          []classOut   `json:"classes"`
	Types            []typeOut    `json:"types"`
	Sections         []idLabel    `json:"sections"`
	Cards            []string     `json:"cards"`
	CoreFields       []string     `json:"core_fields"`
	LegacyCategories []idLabel    `json:"legacy_categories"`
	Properties       []propOut    `json:"properties"`
	CommonProperties []string     `json:"common_properties"`
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
	ID    string   `json:"id"`
	Label string   `json:"label"`
	Lens  string   `json:"lens,omitempty"`
	Types []string `json:"types"`
}

type relRule struct {
	Relationship string `json:"relationship"`
	// SubType restricts the rule to this type's assets of one sub-type
	// ("" = any sub-type).
	SubType string    `json:"sub_type,omitempty"`
	Peers   []typeRef `json:"peers"`
}

type typeRels struct {
	Out []relRule `json:"out"`
	In  []relRule `json:"in"`
}

// inputOut is one entry of model.Inputs.
type inputOut struct {
	From typeRef  `json:"from"`
	To   inputCfg `json:"to"`
}

type typeOut struct {
	Type            string    `json:"type"`
	Label           string    `json:"label"`
	Plural          string    `json:"plural"`
	Icon            string    `json:"icon"`
	Class           string    `json:"class"`
	Lens            string    `json:"lens,omitempty"`
	AliasOf         *typeRef  `json:"alias_of,omitempty"`
	SubTypes        []string  `json:"sub_types"`
	LegacyCategory  string    `json:"legacy_category"`
	Storage         string    `json:"storage"`
	IdentityKeys    []string  `json:"identity_keys"`
	Attributes      []attrCfg `json:"attributes"`
	Facets          []string  `json:"facets"`
	GroupBy         []string  `json:"group_by"`
	Columns         []string  `json:"columns"`
	Card            string    `json:"card"`
	Sections        []string  `json:"sections"`
	Relationships   typeRels  `json:"relationships"`
	ScannableBy     []string  `json:"scannable_by"`
	ExposureDefault string    `json:"exposure_default,omitempty"`
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
var reservedSlugs = set([]string{"changes", "duplicates", "groups", "suggestions", "web"})

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
			case len(t.SubTypes) > 0 || len(t.SubTypeInputs) > 0:
				return nil, fmt.Errorf("%s: an alias has no sub_types or sub_type_inputs of its own", where)
			case t.AliasOf.SubType == "" && t.Class != core.Class:
				// The class of a stored pair is looked up by its sub-type;
				// without one the alias could not keep a class of its own.
				return nil, fmt.Errorf("%s: alias_of needs a sub_type (class %q differs from %s's %q)", where, t.Class, core.Type, core.Class)
			case t.AliasOf.SubType != "" && !slices.Contains(core.SubTypes, t.AliasOf.SubType):
				return nil, fmt.Errorf("%s: alias_of sub_type %q is not in %s's sub_types", where, t.AliasOf.SubType, core.Type)
			}
			if t.AliasOf.SubType != "" {
				pair := typeRef{Type: t.AliasOf.Type, SubType: t.AliasOf.SubType}
				if other, taken := aliasPairs[pair]; taken {
					return nil, fmt.Errorf("%s: alias_of %v is already used by %s", where, pair, other)
				}
				aliasPairs[pair] = t.Type
			}
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

		if err := dup(where+" sub_type_inputs", sortedKeys(t.SubTypeInputs)); err != nil {
			return nil, err
		}
		if err := dup(where+" scannable_by", t.ScannableBy); err != nil {
			return nil, err
		}
		for _, tt := range t.ScannableBy {
			if !knownTargetTypes[tt] {
				return nil, fmt.Errorf("%s: scannable_by %q is not a tool target type", where, tt)
			}
		}
		if t.ExposureDefault != "" && !knownExposures[t.ExposureDefault] {
			return nil, fmt.Errorf("%s: exposure_default %q is not an exposure", where, t.ExposureDefault)
		}
		storage := t.Storage
		if storage == "" {
			storage = "core"
		}
		out := typeOut{
			Type: t.Type, Label: t.Label, Plural: t.Plural, Icon: t.Icon,
			Class: t.Class, Lens: classLens[t.Class], AliasOf: aliasRef(t.AliasOf),
			SubTypes: nonNil(t.SubTypes), LegacyCategory: t.LegacyCategory, Storage: storage,
			IdentityKeys: t.IdentityKeys, Attributes: nonNilAttrs(t.Attributes),
			Facets: nonNil(facets), GroupBy: nonNil(groupBy),
			Columns: t.Columns, Card: t.Card, Sections: t.Sections,
			ScannableBy: nonNil(t.ScannableBy), ExposureDefault: t.ExposureDefault,
		}
		m.Types = append(m.Types, out)
		classTypes[t.Class] = append(classTypes[t.Class], t.Type)
	}

	inputs, err := resolveInputs(cfg, byType)
	if err != nil {
		return nil, err
	}
	m.Inputs = inputs

	for _, c := range cfg.Classes {
		if len(classTypes[c.ID]) == 0 {
			return nil, fmt.Errorf("class %q has no types", c.ID)
		}
		m.Classes = append(m.Classes, classOut{ID: c.ID, Label: c.Label, Lens: c.Lens, Types: classTypes[c.ID]})
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
	if err := resolveProperties(m, cfg); err != nil {
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

// propertyFormats are the display formats a property may declare.
// "expiry" marks a timestamp after which the asset is no longer valid (a
// certificate's not_after, a domain's expires_at): shown against today
// and filtered by the list's expires_before / expires_after.
var propertyFormats = set([]string{"", "ip", "url", "code", formatExpiry})

const formatExpiry = "expiry"

// resolveProperties validates the property dictionary against the types'
// attributes and builds model.Properties (RFC-042 §6.3.9):
//
//   - every attribute and common key has an entry, and every entry is used;
//   - a synonym is never stored: no type declares it as an attribute, it
//     names one canonical key only, and it may share its name with a
//     dictionary key only when that key is a common one (an object such as
//     the CTIS `ip_address` block, which never folds);
//   - a key restricted to classes is declared only by types of those
//     classes and is not common.
func resolveProperties(m *model, cfg *config) error { //nolint:gocognit,gocyclo,cyclop // one linear validation pass
	if len(cfg.Properties) == 0 {
		return errors.New("no properties defined")
	}
	if err := dup("common property", cfg.CommonProperties); err != nil {
		return err
	}
	classes := map[string]bool{}
	for _, c := range m.Classes {
		classes[c.ID] = true
	}
	common := set(cfg.CommonProperties)
	used := map[string]bool{}
	attrClasses := map[string]map[string]bool{}
	shape := map[string]string{}
	attrKinds := map[string]map[string]bool{}
	for _, t := range m.Types {
		for _, a := range t.Attributes {
			if err := checkPropertyName(a.Name, a.Type); err != nil {
				return fmt.Errorf("type %s attribute %q: %w", t.Type, a.Name, err)
			}
			// One shape per key on every type, so a synonym folds the same way
			// whatever the asset (list: merged into one array; scalar: moved).
			s := attrShape(a.Type)
			if prev, ok := shape[a.Name]; ok && prev != s {
				return fmt.Errorf("type %s attribute %q: is a %s here but a %s on another type", t.Type, a.Name, s, prev)
			}
			shape[a.Name] = s
			if attrKinds[a.Name] == nil {
				attrKinds[a.Name] = map[string]bool{}
			}
			attrKinds[a.Name][a.Type] = true
			if len(cfg.Properties[a.Name].Synonyms) > 0 && s == kindObject {
				return fmt.Errorf("type %s attribute %q: an object property cannot have synonyms", t.Type, a.Name)
			}
			used[a.Name] = true
			if attrClasses[a.Name] == nil {
				attrClasses[a.Name] = map[string]bool{}
			}
			attrClasses[a.Name][t.Class] = true
		}
	}
	for _, k := range cfg.CommonProperties {
		used[k] = true
	}
	for k := range used {
		if _, ok := cfg.Properties[k]; !ok {
			return fmt.Errorf("property %q: used by a type or common_properties but not in properties", k)
		}
	}
	synonymOf := map[string]string{}
	for _, k := range sortedKeys(cfg.Properties) {
		p := cfg.Properties[k]
		where := fmt.Sprintf("property %q", k)
		switch {
		case !identRe.MatchString(k):
			return fmt.Errorf("%s: must be lower snake_case", where)
		case !used[k]:
			return fmt.Errorf("%s: no type declares it and it is not common", where)
		case p.Label == "" || p.LabelVI == "":
			return fmt.Errorf("%s: label and label_vi are required", where)
		case !propertyFormats[p.Format]:
			return fmt.Errorf("%s: unknown format %q", where, p.Format)
		case len(p.Classes) > 0 && common[k]:
			return fmt.Errorf("%s: a common property cannot be restricted to classes", where)
		case p.Format == formatExpiry && (common[k] || len(attrKinds[k]) != 1 || !attrKinds[k]["time"]):
			return fmt.Errorf("%s: an expiry property must be a time attribute of its types", where)
		}
		if err := dup(where+" synonym", p.Synonyms); err != nil {
			return err
		}
		for _, syn := range p.Synonyms {
			_, isKey := cfg.Properties[syn]
			switch {
			case syn == k:
				return fmt.Errorf("%s: is its own synonym", where)
			case synonymOf[syn] != "":
				return fmt.Errorf("%s: synonym %q is already a synonym of %q", where, syn, synonymOf[syn])
			case attrClasses[syn] != nil:
				return fmt.Errorf("%s: synonym %q is an attribute of a type; a synonym is never stored", where, syn)
			case isKey && !common[syn]:
				return fmt.Errorf("%s: synonym %q is also a property; only a common one (an object that never folds) may be", where, syn)
			}
			synonymOf[syn] = k
		}
		if err := dup(where+" class", p.Classes); err != nil {
			return err
		}
		for _, c := range p.Classes {
			if !classes[c] {
				return fmt.Errorf("%s: unknown class %q", where, c)
			}
		}
		if len(p.Classes) > 0 {
			for c := range attrClasses[k] {
				if !slices.Contains(p.Classes, c) {
					return fmt.Errorf("%s: restricted to classes %v but a type of class %q declares it", where, p.Classes, c)
				}
			}
		}
		m.Properties = append(m.Properties, propOut{
			Key: k, Label: p.Label, LabelVI: p.LabelVI, Format: p.Format,
			Synonyms: p.Synonyms, Classes: p.Classes, List: shape[k] == kindList,
		})
	}
	m.CommonProperties = cfg.CommonProperties
	return nil
}

// Attribute kinds the property schema treats specially.
const (
	kindList   = "list"
	kindObject = "object"
)

// attrShape is how a value of an attribute type is stored: a list, an
// opaque object or one scalar.
func attrShape(kind string) string {
	switch kind {
	case kindList, kindObject:
		return kind
	}
	return "scalar"
}

// specTimeTerms are timestamps named by the spec they come from (X.509
// validity), kept as the spec spells them instead of `<event>_at`.
var specTimeTerms = set([]string{"not_before", "not_after"})

// checkPropertyName enforces the property naming convention
// (docs/architecture/asset-inventory-v2.md, "Property names"): a boolean
// starts with is_ or has_, a timestamp ends with _at (or is a spec term),
// a list is plural.
func checkPropertyName(name, kind string) error {
	switch kind {
	case "bool":
		if !strings.HasPrefix(name, "is_") && !strings.HasPrefix(name, "has_") {
			return errors.New("a boolean property is named is_<state> or has_<thing>")
		}
	case "time":
		if !strings.HasSuffix(name, "_at") && !specTimeTerms[name] {
			return errors.New("a timestamp property is named <event>_at")
		}
	case kindList:
		if !strings.HasSuffix(name, "s") {
			return errors.New("a list property has a plural name")
		}
	}
	return nil
}

// resolveRelationships turns the constraints of relationship-types.yaml into
// per-type out/in rules over real types. A constraint name is a registry
// type or a virtual type declared in asset-types.yaml; anything else fails,
// so the constraints can no longer name types the backend does not have.
func resolveRelationships(m *model, types map[string]bool, rel *relConfig) error {
	virtual := map[string]typeRef{}
	unmodelled := map[string]bool{}
	subTypes := map[string][]string{}
	for _, t := range m.Types {
		subTypes[t.Type] = t.SubTypes
	}
	aliasOf := map[string]bool{}
	for _, t := range m.Types {
		aliasOf[t.Type] = t.AliasOf != nil
	}
	for _, v := range m.VirtualTypes {
		switch {
		case types[v.Name]:
			return fmt.Errorf("virtual type %q shadows a registry type", v.Name)
		case v.Unmodelled && (v.Type != "" || v.SubType != ""):
			return fmt.Errorf("virtual type %q: an unmodelled name has no type", v.Name)
		case v.Unmodelled:
		case !types[v.Type]:
			return fmt.Errorf("virtual type %q: unknown type %q", v.Name, v.Type)
		case aliasOf[v.Type]:
			return fmt.Errorf("virtual type %q: %q is an alias; name the core type and sub_type", v.Name, v.Type)
		case v.SubType != "" && !slices.Contains(subTypes[v.Type], v.SubType):
			return fmt.Errorf("virtual type %q: sub_type %q is not in %s's sub_types", v.Name, v.SubType, v.Type)
		}
		if _, dupName := virtual[v.Name]; dupName || unmodelled[v.Name] {
			return fmt.Errorf("duplicate virtual type %q", v.Name)
		}
		if v.Unmodelled {
			unmodelled[v.Name] = true
			continue
		}
		virtual[v.Name] = typeRef{Type: v.Type, SubType: v.SubType}
	}
	aliasPair := map[string]typeRef{}
	for _, t := range m.Types {
		if t.AliasOf != nil {
			aliasPair[t.Type] = *t.AliasOf
		}
	}
	errSkip := errors.New("unmodelled")
	resolveName := func(rt, name string) (typeRef, error) {
		// An alias names its stored pair: `website` is (application, website).
		if p, ok := aliasPair[name]; ok {
			return p, nil
		}
		if types[name] {
			return typeRef{Type: name}, nil
		}
		if v, ok := virtual[name]; ok {
			return v, nil
		}
		if unmodelled[name] {
			return typeRef{}, errSkip
		}
		return typeRef{}, fmt.Errorf("%s: relationship %q names %q, which is neither an asset type nor a virtual_types entry", relationshipPath, rt, name)
	}

	type key struct{ typ, sub, rel string }
	out, in := map[key][]typeRef{}, map[key][]typeRef{}
	subsOf := map[string][]string{} // own sub-types seen per type, in order
	noteSub := func(r typeRef) {
		if !slices.Contains(subsOf[r.Type], r.SubType) {
			subsOf[r.Type] = append(subsOf[r.Type], r.SubType)
		}
	}
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
				if errors.Is(err, errSkip) {
					continue
				}
				if err != nil {
					return err
				}
				for _, t := range c.Targets {
					tgt, err := resolveName(rt.ID, t)
					if errors.Is(err, errSkip) {
						continue
					}
					if err != nil {
						return err
					}
					add(out, key{src.Type, src.SubType, rt.ID}, tgt)
					add(in, key{tgt.Type, tgt.SubType, rt.ID}, src)
					noteSub(src)
					noteSub(tgt)
				}
			}
		}
	}
	for i := range m.Types {
		t := &m.Types[i]
		t.Relationships = typeRels{Out: []relRule{}, In: []relRule{}}
		subs := slices.Clone(subsOf[t.Type])
		sort.Strings(subs) // "" (any sub-type) first
		for _, r := range relOrder {
			for _, sub := range subs {
				if peers := out[key{t.Type, sub, r}]; len(peers) > 0 {
					t.Relationships.Out = append(t.Relationships.Out, relRule{Relationship: r, SubType: sub, Peers: peers})
				}
				if peers := in[key{t.Type, sub, r}]; len(peers) > 0 {
					t.Relationships.In = append(t.Relationships.In, relRule{Relationship: r, SubType: sub, Peers: peers})
				}
			}
		}
	}
	return nil
}

// knownTargetTypes are the tool target types (pkg/domain/tool
// ValidTargetTypes; a test keeps the two equal).
var knownTargetTypes = set([]string{"url", "domain", "ip", "host", "repository", "file", "container", "kubernetes",
	"cloud_account", "compute", "storage", "serverless", "network", "service", "port", "database", "mobile", "api", "certificate"})

// knownExposures are the assets.exposure values a type may default to.
var knownExposures = set([]string{"public", "restricted", "private", "isolated"})

// knownProviders are the assets.provider values (pkg/domain/asset
// AllProviders; a test keeps the two equal).
var knownProviders = set([]string{"github", "gitlab", "bitbucket", "azure_devops", "aws", "azure", "gcp", "manual", "other"})

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func aliasRef(a *inputCfg) *typeRef {
	if a == nil {
		return nil
	}
	return &typeRef{Type: a.Type, SubType: a.SubType}
}

// checkTarget validates what an input resolves to: a core type, a sub-type
// from its closed list, a known provider and declared attribute values.
func checkTarget(where string, to inputCfg, byType map[string]*typeCfg) error {
	core, ok := byType[to.Type]
	switch {
	case !ok:
		return fmt.Errorf("%s: unknown type %q", where, to.Type)
	case core.AliasOf != nil:
		return fmt.Errorf("%s: resolves to %q, which is an alias, not a core type", where, to.Type)
	case to.SubType != "" && !slices.Contains(core.SubTypes, to.SubType):
		return fmt.Errorf("%s: sub_type %q is not in %s's sub_types", where, to.SubType, to.Type)
	case to.Provider != "" && !knownProviders[to.Provider]:
		return fmt.Errorf("%s: provider %q is not an assets.provider value", where, to.Provider)
	}
	for _, k := range sortedKeys(to.Attributes) {
		var def *attrCfg
		for i := range core.Attributes {
			if core.Attributes[i].Name == k {
				def = &core.Attributes[i]
			}
		}
		switch {
		case def == nil:
			return fmt.Errorf("%s: attribute %q is not an attribute of %s", where, k, to.Type)
		case def.Type == "enum" && !slices.Contains(def.Values, to.Attributes[k]):
			return fmt.Errorf("%s: attribute %s=%q is not one of %v", where, k, to.Attributes[k], def.Values)
		case def.Type != "enum" && def.Type != "string":
			return fmt.Errorf("%s: attribute %q is a %s; inputs set only string and enum attributes", where, k, def.Type)
		}
	}
	return nil
}

// typeInputNames are the `type_inputs` names, in input order.
func typeInputNames(m *model) []string {
	isType := make(map[string]bool, len(m.Types))
	for _, t := range m.Types {
		isType[t.Type] = true
	}
	var out []string
	for _, in := range m.Inputs {
		if in.From.SubType == "" && !isType[in.From.Type] {
			out = append(out, in.From.Type)
		}
	}
	return out
}

// resolveInputs lists every accepted input that is not stored as such:
// each alias (keyed by its name, sub_type "") and each legacy sub-type of a
// core type, in registry order with the sub-type inputs sorted.
func resolveInputs(cfg *config, byType map[string]*typeCfg) ([]inputOut, error) {
	var out []inputOut
	for i := range cfg.Types {
		t := &cfg.Types[i]
		if t.AliasOf != nil {
			if err := checkTarget("type "+t.Type+" alias_of", *t.AliasOf, byType); err != nil {
				return nil, err
			}
			out = append(out, inputOut{From: typeRef{Type: t.Type}, To: *t.AliasOf})
			continue
		}
		for _, legacy := range sortedKeys(t.SubTypeInputs) {
			to := t.SubTypeInputs[legacy]
			where := fmt.Sprintf("type %s sub_type_inputs %q", t.Type, legacy)
			if slices.Contains(t.SubTypes, legacy) {
				return nil, fmt.Errorf("%s: is already one of the type's sub_types", where)
			}
			if to.Type == "" {
				to.Type = t.Type
			}
			if err := checkTarget(where, to, byType); err != nil {
				return nil, err
			}
			out = append(out, inputOut{From: typeRef{Type: t.Type, SubType: legacy}, To: to})
		}
	}
	for _, name := range sortedKeys(cfg.TypeInputs) {
		to := cfg.TypeInputs[name]
		where := fmt.Sprintf("type_inputs %q", name)
		if _, isType := byType[name]; isType {
			return nil, fmt.Errorf("%s: is a registry type; a type input names a type that is not one", where)
		}
		if to.Type == "" {
			return nil, fmt.Errorf("%s: needs a type", where)
		}
		if err := checkTarget(where, to, byType); err != nil {
			return nil, err
		}
		out = append(out, inputOut{From: typeRef{Type: name}, To: to})
	}
	return out, nil
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
		sub := ""
		if r.SubType != "" {
			sub = fmt.Sprintf(" SubType: %q,", r.SubType)
		}
		fmt.Fprintf(&b, "\n{Relationship: %q,%s Peers: []TypeRef{%s}},", r.Relationship, sub, strings.Join(refs, ", "))
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
		w("{ID: %s, Label: %q, Lens: %s, Types: []AssetType{%s}},\n",
			goIdent("Class", c.ID), c.Label, lens, strings.Join(types, ", "))
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
		w("Relationships: TypeRelationships{\nOut: %s,\nIn: %s,\n},\n", goRules(t.Relationships.Out), goRules(t.Relationships.In))
		w("ScannableBy: %s,\n", goStrings(t.ScannableBy))
		if t.ExposureDefault != "" {
			w("ExposureDefault: %q,\n", t.ExposureDefault)
		}
		w("},\n")
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
	w("var registryProperties = []PropertyDefinition{\n")
	for _, p := range m.Properties {
		w("{Key: %q, Label: %q, LabelVI: %q", p.Key, p.Label, p.LabelVI)
		if p.Format != "" {
			w(", Format: %q", p.Format)
		}
		if len(p.Synonyms) > 0 {
			w(", Synonyms: %s", goStrings(p.Synonyms))
		}
		if len(p.Classes) > 0 {
			w(", Classes: %s", goTyped("Class", "Class", p.Classes))
		}
		if p.List {
			w(", List: true")
		}
		w("},\n")
	}
	w("}\n\n")
	w("var registryCommonProperties = %s\n\n", goStrings(m.CommonProperties))
	w("// TypeAliases maps legacy types to their consolidated core type + sub_type,\n")
	w("// from the `alias_of` entries and the `type_inputs` of the registry. Used by\n// ingest to normalize incoming data.\n")
	w("var TypeAliases = map[AssetType]struct {\nCoreType AssetType\nSubType  string\n}{\n")
	for _, t := range m.Types {
		if t.AliasOf != nil {
			w("%q: {CoreType: %q, SubType: %q},\n", t.Type, t.AliasOf.Type, t.AliasOf.SubType)
		}
	}
	for _, name := range typeInputNames(m) {
		for _, in := range m.Inputs {
			if in.From.Type == name && in.From.SubType == "" {
				w("%q: {CoreType: %q, SubType: %q},\n", name, in.To.Type, in.To.SubType)
			}
		}
	}
	w("}\n\n")
	w("// registryTypeInputs are the legacy type names accepted on input that are no\n")
	w("// type of their own (`type_inputs`).\nvar registryTypeInputs = []AssetType{")
	for _, name := range typeInputNames(m) {
		w("%q, ", name)
	}
	w("}\n\n")

	w("// registryStoredTypes are the core types, in registry order: the only values\n")
	w("// assets.asset_type may hold (RFC-042 §6.3.8 R1).\nvar registryStoredTypes = []AssetType{")
	for _, t := range m.Types {
		if t.AliasOf == nil {
			w("%q, ", t.Type)
		}
	}
	w("}\n\n")
	w("// registryInputs maps every accepted input that is not stored as such to\n")
	w("// what it is stored as: an alias by its name ({Type: alias}) and a legacy\n")
	w("// sub-type of a core type ({Type: core, SubType: legacy}).\n")
	w("var registryInputs = map[TypeRef]TypeInput{\n")
	for _, in := range m.Inputs {
		w("%s: {Type: %q", goTypeRef(in.From), in.To.Type)
		if in.To.SubType != "" {
			w(", SubType: %q", in.To.SubType)
		}
		if in.To.Provider != "" {
			w(", Provider: %q", in.To.Provider)
		}
		if len(in.To.Attributes) > 0 {
			w(", Attributes: map[string]string{")
			for _, k := range sortedKeys(in.To.Attributes) {
				w("%q: %q, ", k, in.To.Attributes[k])
			}
			w("}")
		}
		w("},\n")
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
	w("}\n\n")

	var stored []string
	for _, t := range m.Types {
		if t.AliasOf == nil {
			stored = append(stored, t.Type)
		}
	}
	w("/** The core types: the only values an asset's `type` holds (RFC-042 §6.3.8). */\n")
	w("export type StoredAssetType =%s\n\n", tsUnion(stored))
	w("export const STORED_ASSET_TYPES: readonly StoredAssetType[] = [\n")
	for _, t := range stored {
		w("  '%s',\n", t)
	}
	w("]\n\n")
	w("/** The closed sub-type list of each core type (a sub-type is a kind). */\n")
	w("export const ASSET_SUB_TYPES: Readonly<Record<StoredAssetType, readonly string[]>> = {\n")
	for _, t := range m.Types {
		if t.AliasOf != nil {
			continue
		}
		q := make([]string, len(t.SubTypes))
		for i, st := range t.SubTypes {
			q[i] = "'" + st + "'"
		}
		line := fmt.Sprintf("  %s: [%s],", t.Type, strings.Join(q, ", "))
		if len(line) > 100 {
			w("  %s: [\n", t.Type)
			for _, x := range q {
				w("    %s,\n", x)
			}
			w("  ],\n")
			continue
		}
		w("%s\n", line)
	}
	w("}\n\n")
	w("/**\n * Every non-core name the relationship constraints use (aliases and virtual\n")
	w(" * names), resolved to the stored (core type, sub-type). A core type name\n")
	w(" * stands for itself with any sub-type.\n */\n")
	w("export const ASSET_RELATIONSHIP_NAMES: Readonly<\n  Record<string, { type: StoredAssetType; subType?: string }>\n> = {\n")
	for _, t := range m.Types {
		if t.AliasOf == nil {
			continue
		}
		if t.AliasOf.SubType == "" {
			w("  %s: { type: '%s' },\n", t.Type, t.AliasOf.Type)
			continue
		}
		w("  %s: { type: '%s', subType: '%s' },\n", t.Type, t.AliasOf.Type, t.AliasOf.SubType)
	}
	for _, v := range m.VirtualTypes {
		if v.Unmodelled {
			continue
		}
		if v.SubType == "" {
			w("  %s: { type: '%s' },\n", v.Name, v.Type)
			continue
		}
		w("  %s: { type: '%s', subType: '%s' },\n", v.Name, v.Type, v.SubType)
	}
	w("}\n\n")
	w("/** Input-only alias names and the (core type, sub-type) they are stored as. */\n")
	w("export const ASSET_TYPE_ALIASES: Readonly<\n  Record<string, { type: StoredAssetType; subType?: string }>\n> = {\n")
	for _, t := range m.Types {
		if t.AliasOf == nil {
			continue
		}
		if t.AliasOf.SubType == "" {
			w("  %s: { type: '%s' },\n", t.Type, t.AliasOf.Type)
			continue
		}
		w("  %s: { type: '%s', subType: '%s' },\n", t.Type, t.AliasOf.Type, t.AliasOf.SubType)
	}
	isType := make(map[string]bool, len(m.Types))
	for _, t := range m.Types {
		isType[t.Type] = true
	}
	for _, in := range m.Inputs {
		if in.From.SubType != "" || isType[in.From.Type] {
			continue // a sub-type input, or an alias written above
		}
		if in.To.SubType == "" {
			w("  %s: { type: '%s' },\n", in.From.Type, in.To.Type)
			continue
		}
		w("  %s: { type: '%s', subType: '%s' },\n", in.From.Type, in.To.Type, in.To.SubType)
	}
	w("}\n\n")
	renderTSProperties(w, m)
	return b.String()
}

// renderTSProperties writes the property schema (RFC-042 §6.3.9): the
// dictionary, the common keys and each type's attribute keys, so the web can
// label and group an asset's properties without waiting for the registry.
func renderTSProperties(w func(string, ...any), m *model) {
	formats := make([]string, 0, len(propertyFormats))
	for _, f := range sortedKeys(propertyFormats) {
		if f != "" {
			formats = append(formats, "'"+f+"'")
		}
	}
	w("export type AssetPropertyFormat = %s\n\n", strings.Join(formats, " | "))
	w("export interface AssetPropertyDefinition {\n  label: string\n  labelVi: string\n")
	w("  format?: AssetPropertyFormat\n  synonyms?: readonly string[]\n  classes?: readonly AssetClass[]\n")
	w("  /** Stored as an array (synonyms merge into it). */\n  list?: boolean\n}\n\n")
	keys := make([]string, len(m.Properties))
	for i, p := range m.Properties {
		keys[i] = p.Key
	}
	w("/**\n * A property key of the schema. Web code names a key through this type, never\n")
	w(" * as a free string, so a key outside the registry does not compile.\n */\n")
	w("export type AssetPropertyKey =%s\n\n", tsUnion(keys))
	w("/** Every property key of the schema, with its labels and display format. */\n")
	w("export const ASSET_PROPERTIES: Readonly<Record<AssetPropertyKey, AssetPropertyDefinition>> = {\n")
	quoted := func(items []string) string {
		q := make([]string, len(items))
		for i, s := range items {
			q[i] = "'" + s + "'"
		}
		return "[" + strings.Join(q, ", ") + "]"
	}
	for _, p := range m.Properties {
		fields := []string{"label: " + tsString(p.Label), "labelVi: " + tsString(p.LabelVI)}
		if p.Format != "" {
			fields = append(fields, "format: '"+p.Format+"'")
		}
		if len(p.Synonyms) > 0 {
			fields = append(fields, "synonyms: "+quoted(p.Synonyms))
		}
		if len(p.Classes) > 0 {
			fields = append(fields, "classes: "+quoted(p.Classes))
		}
		if p.List {
			fields = append(fields, "list: true")
		}
		line := fmt.Sprintf("  %s: { %s },", p.Key, strings.Join(fields, ", "))
		if len(line) <= 100 {
			w("%s\n", line)
			continue
		}
		w("  %s: {\n", p.Key)
		for _, f := range fields {
			w("    %s,\n", f)
		}
		w("  },\n")
	}
	w("}\n\n")
	w("/** The property keys every type may hold (platform keys, CTIS technical blocks). */\n")
	w("export const ASSET_COMMON_PROPERTIES: readonly AssetPropertyKey[] = [\n")
	for _, k := range m.CommonProperties {
		w("  '%s',\n", k)
	}
	w("]\n\n")
	w("/** The attribute keys of each type, in display order. */\n")
	w("export const ASSET_TYPE_PROPERTIES: Readonly<Record<RegistryAssetType, readonly AssetPropertyKey[]>> = {\n")
	for _, t := range m.Types {
		keys := make([]string, len(t.Attributes))
		for i, a := range t.Attributes {
			keys[i] = a.Name
		}
		line := fmt.Sprintf("  %s: %s,", t.Type, quoted(keys))
		if len(line) <= 100 {
			w("%s\n", line)
			continue
		}
		w("  %s: [\n", t.Type)
		for _, k := range keys {
			w("    '%s',\n", k)
		}
		w("  ],\n")
	}
	w("}\n")
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

// sqlArray renders a text[] literal.
func sqlArray(items []string) string {
	if len(items) == 0 {
		return "'{}'"
	}
	return "ARRAY[" + sqlList(items) + "]::text[]"
}

// renderSQL is the migration block: the class and lens CHECKs, one upsert
// row per registry type, `other` for every legacy code, the backfill of
// assets.asset_class / asset_lens (asset_registry_backfill, created by the
// migration that introduced the columns) and the CHECK that assets store only
// core types (added by the data normalisation, migration 000684: a block may
// only be emitted after every stored row is a core type).
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
	w("\nINSERT INTO asset_types (code, name, class, lens, alias_of, alias_sub_type, sub_types, is_storable) VALUES\n")
	for i, t := range m.Types {
		alias, sub := "", ""
		if t.AliasOf != nil {
			alias, sub = t.AliasOf.Type, t.AliasOf.SubType
		}
		sep := ","
		if i == len(m.Types)-1 {
			sep = ""
		}
		w("    (%s, %s, %s, %s, %s, %s, %s, %t)%s\n", sqlString(t.Type), sqlString(t.Label), sqlString(t.Class),
			sqlNullable(t.Lens), sqlNullable(alias), sqlNullable(sub), sqlArray(t.SubTypes), t.AliasOf == nil, sep)
	}
	w("ON CONFLICT (code) DO UPDATE SET\n    class = EXCLUDED.class,\n    lens = EXCLUDED.lens,\n")
	w("    alias_of = EXCLUDED.alias_of,\n    alias_sub_type = EXCLUDED.alias_sub_type,\n")
	w("    sub_types = EXCLUDED.sub_types,\n    is_storable = EXCLUDED.is_storable;\n\n")
	w("-- Codes that are not registry types (legacy rows kept for the assets FK).\n")
	w("UPDATE asset_types SET class = 'other', lens = NULL, alias_of = NULL, alias_sub_type = NULL,\n")
	w("    sub_types = '{}', is_storable = false\n")
	w("WHERE code NOT IN (%s);\n\n", sqlList(typeIDs))
	w("-- Accepted inputs that are not stored as such: aliases (from_sub_type '')\n")
	w("-- and legacy sub-types, with what they are stored as.\n")
	w("DELETE FROM asset_type_input_map;\n")
	w("INSERT INTO asset_type_input_map (from_type, from_sub_type, to_type, to_sub_type, provider, attributes) VALUES\n")
	for i, in := range m.Inputs {
		sep := ","
		if i == len(m.Inputs)-1 {
			sep = ";"
		}
		attrs := "'{}'"
		if len(in.To.Attributes) > 0 {
			raw, _ := json.Marshal(in.To.Attributes) // map keys are sorted
			attrs = sqlString(string(raw))
		}
		w("    (%s, %s, %s, %s, %s, %s)%s\n", sqlString(in.From.Type), sqlString(in.From.SubType),
			sqlString(in.To.Type), sqlNullable(in.To.SubType), sqlNullable(in.To.Provider), attrs, sep)
	}
	w("\n")
	w("-- Re-derive assets.asset_class / asset_lens in batches, without touching\n-- updated_at.\n")
	w("ALTER TABLE assets DISABLE TRIGGER trigger_assets_updated_at;\n")
	w("DO $$\nDECLARE\n    cursor_id uuid := NULL;\nBEGIN\n    LOOP\n")
	w("        SELECT b.last_id INTO cursor_id FROM asset_registry_backfill(cursor_id, 5000) b;\n")
	w("        EXIT WHEN cursor_id IS NULL;\n    END LOOP;\nEND $$;\n")
	w("ALTER TABLE assets ENABLE TRIGGER trigger_assets_updated_at;\n\n")
	stored := make([]string, 0, len(m.Types))
	for _, t := range m.Types {
		if t.AliasOf == nil {
			stored = append(stored, t.Type)
		}
	}
	w("-- Only core types are stored (RFC-042 §6.3.8). Added NOT VALID: the\n")
	w("-- migration moves the rows a registry change leaves outside the list,\n")
	w("-- then validates it after this block (SHARE UPDATE EXCLUSIVE lock).\n")
	w("ALTER TABLE assets DROP CONSTRAINT IF EXISTS chk_assets_core_type;\n")
	w("ALTER TABLE assets ADD CONSTRAINT chk_assets_core_type CHECK (asset_type IN (%s)) NOT VALID;\n", sqlList(stored))
	w("%s\n", sqlEndMarker)
	return b.String()
}
