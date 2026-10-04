package filterspec

import (
	"fmt"
	"strings"
)

// Generated swag annotations (RFC-048 §3.10). A handler's filter params are
// generated from its registry, between two marker comments, so the OpenAPI
// spec and the parser cannot disagree:
//
//	// filterspec-params: findings GET /findings
//	// @Param  severity  query  []string  false  "..."  collectionFormat(csv) Enums(...)
//	// end filterspec-params
//
// api/tools/gen/filterparams rewrites the blocks; a test fails when a block,
// or the committed spec, differs from the registry.

// ParamMarker and ParamEndMarker delimit a generated block.
const (
	ParamMarker    = "// filterspec-params: "
	ParamEndMarker = "// end filterspec-params"
)

// SwagParam is one generated query parameter.
type SwagParam struct {
	Name        string
	Type        string // string, integer, number, boolean
	Array       bool
	Enum        []string
	Description string
}

// SwagParams returns the filter query params of the registry in a stable
// order: per field (declaration order) the plain name, then each operator
// suffix. Permission-gated fields are documented too: the spec describes the
// API, the compiler decides per caller.
func (r *Registry) SwagParams() []SwagParam {
	var out []SwagParam
	for _, n := range r.order {
		f := r.fields[n]
		typ := swagType(f.Type)
		label := strings.ReplaceAll(f.Name, "_", " ")
		add := func(name string, array bool, t string, desc string) {
			p := SwagParam{Name: name, Type: t, Array: array, Description: desc}
			if t == "string" && f.Type == TypeEnum && name != f.Name+"_null" {
				p.Enum = f.Enum
			}
			out = append(out, p)
		}
		switch {
		case f.allows(OpIn):
			add(f.Name, true, typ, label+": any of (comma list)")
		case f.allows(OpEq):
			add(f.Name, false, typ, label+" equals")
		case f.allows(OpContains):
			add(f.Name, false, "string", label+" contains")
		}
		for _, s := range suffixOps {
			switch {
			case s.op == OpNotIn && f.allows(OpNotIn):
				add(f.Name+s.suffix, true, typ, label+": none of (comma list)")
			case s.op == OpNotIn && f.allows(OpNe):
				add(f.Name+s.suffix, false, typ, label+" not equal")
			case s.op == OpContains && f.allows(OpContains):
				add(f.Name+s.suffix, false, "string", label+" contains")
			case s.op == OpIsNull && f.allows(OpIsNull):
				add(f.Name+s.suffix, false, "boolean", label+" is unset (true) or set (false)")
			case (s.op == OpGte || s.op == OpGt || s.op == OpLte || s.op == OpLt) && f.allows(s.op):
				add(f.Name+s.suffix, false, typ, label+" "+rangeWord(s.op)+timeHint(f))
			}
		}
	}
	return out
}

// SwagLines renders SwagParams as swag @Param comment lines.
func (r *Registry) SwagLines() []string {
	params := r.SwagParams()
	lines := make([]string, 0, len(params))
	for _, p := range params {
		t := p.Type
		if p.Array {
			t = "[]" + t
		}
		line := fmt.Sprintf("// @Param  %s  query  %s  false  %q", p.Name, t, p.Description)
		if p.Array {
			line += "  collectionFormat(csv)"
		}
		if len(p.Enum) > 0 {
			line += "  Enums(" + strings.Join(p.Enum, ", ") + ")"
		}
		lines = append(lines, line)
	}
	return lines
}

func swagType(t Type) string {
	switch t {
	case TypeInt:
		return "integer"
	case TypeNumber:
		return "number"
	case TypeBool:
		return "boolean"
	}
	return "string"
}

func rangeWord(op Op) string {
	switch op {
	case OpGte:
		return "at least"
	case OpGt:
		return "greater than"
	case OpLte:
		return "at most"
	}
	return "less than"
}

func timeHint(f *Field) string {
	if f.Type == TypeTime {
		return " (RFC 3339, YYYY-MM-DD, or -P30D)"
	}
	return ""
}

// RewriteParamBlocks replaces every generated block in src with the lines
// of the registry its marker names. registries maps a marker's registry name
// to the registry. It returns the new source and the names of the blocks.
func RewriteParamBlocks(src string, registries map[string]*Registry) (string, []string, error) {
	lines := strings.Split(src, "\n")
	out := make([]string, 0, len(lines))
	var blocks []string
	for i := 0; i < len(lines); i++ {
		l := lines[i]
		trimmed := strings.TrimSpace(l)
		if !strings.HasPrefix(trimmed, ParamMarker) {
			out = append(out, l)
			continue
		}
		spec := strings.TrimPrefix(trimmed, ParamMarker)
		name := strings.Fields(spec)
		if len(name) == 0 {
			return "", nil, fmt.Errorf("line %d: marker without a registry name", i+1)
		}
		reg, ok := registries[name[0]]
		if !ok {
			return "", nil, fmt.Errorf("line %d: unknown registry %q", i+1, name[0])
		}
		end := -1
		for j := i + 1; j < len(lines); j++ {
			if strings.TrimSpace(lines[j]) == ParamEndMarker {
				end = j
				break
			}
		}
		if end < 0 {
			return "", nil, fmt.Errorf("line %d: block %q has no end marker", i+1, spec)
		}
		out = append(out, l)
		out = append(out, reg.SwagLines()...)
		out = append(out, lines[end])
		blocks = append(blocks, spec)
		i = end
	}
	return strings.Join(out, "\n"), blocks, nil
}
