package filterspec

import (
	"net/url"
	"sort"
	"strings"
)

// Document keys used to build a document.
const (
	docKeyField = "field"
	docKeyAll   = "all"
	docKeyOp    = "op"
	docKeyValue = "value"
)

// ParamsDocument converts flat list params to the version 1 FilterDocument
// they mean, with every value kept as written ("-P7D" stays relative), for
// an editor that shows a list URL as query text. The params are checked
// with ParseValues first (opts as given); params read outside the filter
// (sort, page, view, the options' Extra) are left out.
func ParamsDocument(q url.Values, reg *Registry, opts Options) (map[string]any, error) {
	if _, err := ParseValues(q, reg, opts); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(q))
	for k := range q {
		names = append(names, k)
	}
	sort.Strings(names)
	doc := map[string]any{"v": DocumentVersion}
	var leaves []any
	for _, name := range names {
		if opts.isExtra(name) {
			continue
		}
		target, values := name, q[name]
		if a, ok := reg.Aliases[name]; ok && !opts.NoAliases {
			target = a.To
			if a.Value != nil {
				kept := make([]string, 0, len(values))
				for _, v := range values {
					if nv, keep := a.Value(v); keep {
						kept = append(kept, nv)
					}
				}
				values = kept
			}
		}
		if target == "q" {
			if len(values) == 1 && strings.TrimSpace(values[0]) != "" {
				doc["q"] = strings.TrimSpace(values[0])
			}
			continue
		}
		if reserved[target] {
			continue
		}
		f, op, err := reg.resolveParam(target)
		if err != nil {
			continue // warn mode: ParseValues ignored it too
		}
		raw := splitValues(f, op, values)
		if len(raw) == 0 {
			continue
		}
		var value any
		switch op {
		case OpIn, OpNotIn:
			list := make([]any, len(raw))
			for i, r := range raw {
				list[i] = r
			}
			value = list
		case OpIsNull:
			value = strings.EqualFold(raw[0], "true") || raw[0] == "1"
		default:
			value = raw[0]
			if f.Type == TypeBool {
				value = strings.EqualFold(raw[0], "true") || raw[0] == "1"
			}
		}
		leaves = append(leaves, map[string]any{docKeyField: f.Name, docKeyOp: string(op), docKeyValue: value})
	}
	switch len(leaves) {
	case 0:
	case 1:
		doc["filter"] = leaves[0]
	default:
		doc["filter"] = map[string]any{docKeyAll: leaves}
	}
	return doc, nil
}

// LeafParam returns the flat param name and value of one document leaf
// (the inverse of ParamsDocument for one condition): ok is false when the
// leaf has no flat spelling (a value with a comma in a list, an unknown
// field or operator).
func (r *Registry) LeafParam(field string, op Op, values []string) (name, value string, ok bool) {
	f, found := r.fields[field]
	if !found || !f.allows(op) {
		return "", "", false
	}
	switch op {
	case OpIn, OpEq:
		if !f.allows(OpIn) && !f.allows(OpEq) {
			return "", "", false
		}
		if f.allows(OpIn) && f.allows(OpEq) && op == OpEq {
			return "", "", false // the plain name means in
		}
		name = f.Name
	case OpContains:
		name = f.Name + "_contains"
	default:
		for _, s := range suffixOps {
			if s.op == op {
				name = f.Name + s.suffix
			}
		}
		if op == OpNotIn {
			name = f.Name + "_not"
		}
		if op == OpNe {
			if f.allows(OpNotIn) {
				return "", "", false
			}
			name = f.Name + "_not"
		}
	}
	if name == "" || len(values) == 0 {
		return "", "", false
	}
	if op == OpContains || f.FreeText {
		if len(values) != 1 {
			return "", "", false
		}
		return name, values[0], true
	}
	for _, v := range values {
		if strings.Contains(v, ",") {
			return "", "", false
		}
	}
	return name, strings.Join(values, ","), true
}
