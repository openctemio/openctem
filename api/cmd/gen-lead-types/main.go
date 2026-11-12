// Command gen-lead-types reads configs/lead-types.yaml, checks every entry
// against the stage catalog and the asset type registry, and writes the Go
// and TypeScript lead type catalogs (docs/architecture/exploration.md).
//
// Usage (from api/):
//
//	go run ./cmd/gen-lead-types          # write the generated files
//	go run ./cmd/gen-lead-types -check   # fail when they are stale
//
// The YAML is the single source of truth; the generated files are committed
// and never edited by hand. The tier of an action is always the stage
// catalog's, so a lead type can never make a capability less intrusive than
// it is.
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

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
)

const (
	yamlPath = "configs/lead-types.yaml"
	goPath   = "pkg/domain/exploration/lead_types_generated.go"
	tsPath   = "../web/src/features/exploration/lib/lead-types.generated.ts"
)

type catalog struct {
	Version int        `yaml:"version"`
	Types   []leadType `yaml:"types"`
}

type leadType struct {
	ID          string   `yaml:"id"`
	Version     int      `yaml:"version"`
	Subject     string   `yaml:"subject"`
	Likelihood  string   `yaml:"likelihood"`
	ValueWeight float64  `yaml:"value_weight"`
	MaxAttempts int      `yaml:"max_attempts"`
	Reasons     []string `yaml:"reasons"`
	Settle      string   `yaml:"settle"`
	Actions     []action `yaml:"actions"`
}

type action struct {
	Capability string   `yaml:"capability"`
	AssetTypes []string `yaml:"asset_types"`
	Params     []string `yaml:"params"`
	tier       stage.Tier
}

var (
	keyRe    = regexp.MustCompile(`^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$`)
	reasonRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
)

func main() {
	check := flag.Bool("check", false, "fail when the generated files differ from the YAML")
	flag.Parse()
	if err := run(*check); err != nil {
		fmt.Fprintf(os.Stderr, "gen-lead-types: %v\n", err)
		os.Exit(1)
	}
}

func run(check bool) error {
	raw, err := os.ReadFile(yamlPath)
	if err != nil {
		return fmt.Errorf("read %s (run from api/): %w", yamlPath, err)
	}
	c, err := parse(raw)
	if err != nil {
		return err
	}
	goSrc, err := renderGo(c)
	if err != nil {
		return err
	}
	outputs := map[string][]byte{goPath: goSrc, tsPath: renderTS(c)}
	paths := make([]string, 0, len(outputs))
	for p := range outputs {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		if check {
			cur, err := os.ReadFile(p)
			if err != nil || !bytes.Equal(cur, outputs[p]) {
				return fmt.Errorf("%s is stale: run make generate-lead-types", p)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			return err
		}
		if err := os.WriteFile(p, outputs[p], 0o600); err != nil {
			return err
		}
	}
	return nil
}

// parse reads and validates the catalog.
func parse(raw []byte) (*catalog, error) {
	var c catalog
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	if err := validate(&c); err != nil {
		return nil, err
	}
	return &c, nil
}

//nolint:cyclop,gocognit // one pass of flat checks, one per field
func validate(c *catalog) error {
	if c.Version != 1 {
		return errors.New("catalog version must be 1")
	}
	if len(c.Types) == 0 {
		return errors.New("no lead types")
	}
	seen := map[string]bool{}
	for i := range c.Types {
		t := &c.Types[i]
		at := fmt.Sprintf("type %q", t.ID)
		switch {
		case !keyRe.MatchString(t.ID) || len(t.ID) > 64:
			return fmt.Errorf("%s: id must be <area>.<question>", at)
		case seen[t.ID]:
			return fmt.Errorf("%s: duplicate id", at)
		case t.Version < 1:
			return fmt.Errorf("%s: version must be at least 1", at)
		case t.Subject != "asset":
			return fmt.Errorf("%s: subject must be asset", at)
		case t.Likelihood != "low" && t.Likelihood != "medium" && t.Likelihood != "high":
			return fmt.Errorf("%s: likelihood must be low, medium or high", at)
		case t.ValueWeight < 0.1 || t.ValueWeight > 5:
			return fmt.Errorf("%s: value_weight must be between 0.1 and 5", at)
		case t.MaxAttempts < 1 || t.MaxAttempts > 5:
			return fmt.Errorf("%s: max_attempts must be between 1 and 5", at)
		case t.Settle != "finding" && t.Settle != "liveness" && t.Settle != "match":
			return fmt.Errorf("%s: settle must be finding, liveness or match", at)
		case len(t.Reasons) == 0:
			return fmt.Errorf("%s: at least one reason", at)
		case len(t.Actions) == 0:
			return fmt.Errorf("%s: at least one action", at)
		}
		seen[t.ID] = true
		for _, r := range t.Reasons {
			if !reasonRe.MatchString(r) {
				return fmt.Errorf("%s: reason %q must be snake_case", at, r)
			}
		}
		caps := map[string]bool{}
		for j := range t.Actions {
			a := &t.Actions[j]
			st, ok := stage.Lookup(stage.Key(a.Capability))
			if !ok {
				return fmt.Errorf("%s: capability %q is not in the stage catalog", at, a.Capability)
			}
			if caps[a.Capability] {
				return fmt.Errorf("%s: capability %q listed twice", at, a.Capability)
			}
			caps[a.Capability] = true
			a.tier = st.Tier
			for _, name := range a.AssetTypes {
				if _, known := asset.LookupType(asset.AssetType(name)); !known {
					return fmt.Errorf("%s: unknown asset type %q", at, name)
				}
				if !st.Accepts(asset.CanonicalPair(asset.AssetType(name), "")) {
					return fmt.Errorf("%s: %s does not take %s", at, a.Capability, name)
				}
			}
			for _, p := range a.Params {
				if !reasonRe.MatchString(p) {
					return fmt.Errorf("%s: param %q must be snake_case", at, p)
				}
			}
		}
	}
	return nil
}

func goStrings(xs []string) string {
	if len(xs) == 0 {
		return "nil"
	}
	q := make([]string, len(xs))
	for i, x := range xs {
		q[i] = strconv.Quote(x)
	}
	return "[]string{" + strings.Join(q, ", ") + "}"
}

func renderGo(c *catalog) ([]byte, error) {
	var b bytes.Buffer
	b.WriteString("// Code generated by cmd/gen-lead-types from configs/lead-types.yaml. DO NOT EDIT.\n\n")
	b.WriteString("package exploration\n\nimport \"github.com/openctemio/openctem/api/pkg/domain/stage\"\n\n")
	b.WriteString("// leadTypes is the lead type catalog (configs/lead-types.yaml).\nvar leadTypes = []LeadType{\n")
	for _, t := range c.Types {
		fmt.Fprintf(&b, "\t{ID: %q, Version: %d, Subject: %q, Likelihood: %q, ValueWeight: %s, MaxAttempts: %d, Reasons: %s, Settle: %q, Actions: []LeadTypeAction{\n",
			t.ID, t.Version, t.Subject, t.Likelihood, strconv.FormatFloat(t.ValueWeight, 'f', -1, 64), t.MaxAttempts, goStrings(t.Reasons), t.Settle)
		for _, a := range t.Actions {
			fmt.Fprintf(&b, "\t\t{Capability: %q, Tier: stage.Tier(%d), AssetTypes: %s, Params: %s},\n",
				a.Capability, int(a.tier), goStrings(a.AssetTypes), goStrings(a.Params))
		}
		b.WriteString("\t}},\n")
	}
	b.WriteString("}\n")
	return format.Source(b.Bytes())
}

func renderTS(c *catalog) []byte {
	var b bytes.Buffer
	b.WriteString("// Code generated by api/cmd/gen-lead-types from api/configs/lead-types.yaml. DO NOT EDIT.\n\n")
	b.WriteString("export const LEAD_TYPE_IDS = [\n")
	for _, t := range c.Types {
		fmt.Fprintf(&b, "  '%s',\n", t.ID)
	}
	b.WriteString("] as const\n\nexport type LeadTypeId = (typeof LEAD_TYPE_IDS)[number]\n\n")
	b.WriteString("/** Reason codes each lead type may give (i18n keys under exploration.reasons). */\n")
	b.WriteString("export const LEAD_TYPE_REASONS: Record<LeadTypeId, readonly string[]> = {\n")
	for _, t := range c.Types {
		q := make([]string, len(t.Reasons))
		for i, r := range t.Reasons {
			q[i] = "'" + r + "'"
		}
		fmt.Fprintf(&b, "  '%s': [%s],\n", t.ID, strings.Join(q, ", "))
	}
	b.WriteString("}\n\n/** The i18n key segment of a lead type (dots are not allowed in a key segment). */\n")
	b.WriteString("export function leadTypeKey(id: string): string {\n  return id.replace(/\\./g, '_')\n}\n")
	return b.Bytes()
}
