// Package openapischema checks that the committed OpenAPI spec describes the
// same request and response shapes as a fresh `make swagger` run.
//
// openapicontract compares the SETS OF OPERATIONS and deliberately avoids a
// byte comparison: swag is not hermetic across environments (a clean runner
// drops `format: int64` on some map fields a developer machine emits). That
// left schema drift unguarded: a struct field added to a response type
// without `make swagger` never reached the spec or the generated web types
// (the asset type registry's scannable_by, exposure_default and sub_type
// went missing that way).
//
// This compares the shape only, which is stable across environments: the
// definition names and, per definition, its required list and each
// property's name, type, $ref, items type/$ref and enum. Descriptions,
// examples and format keywords are ignored.
package openapischema

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

type schema struct {
	Type                 any                `yaml:"type"`
	Ref                  string             `yaml:"$ref"`
	Enum                 []any              `yaml:"enum"`
	Required             []string           `yaml:"required"`
	Items                *schema            `yaml:"items"`
	Properties           map[string]*schema `yaml:"properties"`
	AdditionalProperties any                `yaml:"additionalProperties"`
	AllOf                []*schema          `yaml:"allOf"`
}

type spec struct {
	Definitions map[string]*schema `yaml:"definitions"`
}

// Load reads the definitions of a swagger 2.0 file.
func Load(path string) (map[string]*schema, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s spec
	if err := yaml.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return s.Definitions, nil
}

// shape renders a schema's structure on one line, ignoring descriptions,
// examples and format.
func shape(s *schema) string {
	if s == nil {
		return "-"
	}
	var b strings.Builder
	if s.Ref != "" {
		b.WriteString("ref=" + s.Ref)
	}
	if s.Type != nil {
		fmt.Fprintf(&b, " type=%v", s.Type)
	}
	if len(s.Enum) > 0 {
		vals := make([]string, len(s.Enum))
		for i, v := range s.Enum {
			vals[i] = fmt.Sprint(v)
		}
		sort.Strings(vals)
		b.WriteString(" enum=" + strings.Join(vals, ","))
	}
	if s.Items != nil {
		b.WriteString(" items=(" + shape(s.Items) + ")")
	}
	if s.AdditionalProperties != nil {
		if m, ok := s.AdditionalProperties.(map[string]any); ok {
			if r, ok := m["$ref"].(string); ok {
				b.WriteString(" additional=ref=" + r)
			} else if t, ok := m["type"]; ok {
				fmt.Fprintf(&b, " additional=type=%v", t)
			} else {
				b.WriteString(" additional")
			}
		} else {
			fmt.Fprintf(&b, " additional=%v", s.AdditionalProperties)
		}
	}
	for _, a := range s.AllOf {
		b.WriteString(" allOf=(" + shape(a) + ")")
	}
	return strings.TrimSpace(b.String())
}

// Flatten lists every structural fact of the definitions, one per line:
// "def", "def required=a,b", "def.prop <shape>".
func Flatten(defs map[string]*schema) []string {
	out := make([]string, 0, 4*len(defs))
	for name, d := range defs {
		out = append(out, name)
		if d == nil {
			continue
		}
		if len(d.Required) > 0 {
			req := append([]string(nil), d.Required...)
			sort.Strings(req)
			out = append(out, name+" required="+strings.Join(req, ","))
		}
		if top := shape(&schema{Type: d.Type, Ref: d.Ref, Enum: d.Enum, Items: d.Items, AdditionalProperties: d.AdditionalProperties, AllOf: d.AllOf}); top != "" {
			out = append(out, name+" "+top)
		}
		for p, ps := range d.Properties {
			out = append(out, name+"."+p+" "+shape(ps))
		}
	}
	sort.Strings(out)
	return out
}

// Diff returns the facts only in want (missing from got) and only in got.
func Diff(want, got []string) (missing, extra []string) {
	w := make(map[string]bool, len(want))
	for _, s := range want {
		w[s] = true
	}
	g := make(map[string]bool, len(got))
	for _, s := range got {
		g[s] = true
		if !w[s] {
			extra = append(extra, s)
		}
	}
	for _, s := range want {
		if !g[s] {
			missing = append(missing, s)
		}
	}
	return missing, extra
}
