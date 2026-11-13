package filterspec

import (
	"encoding/json"
	"time"
)

// Document returns the spec as a FilterDocument (RFC-048 §3.6), the stored
// form of saved views: {"v":1, "filter":{...}, "q":..., "sort":[...]}. Page
// state is not part of it. ParseDocument of the result gives the same spec.
func (s *Spec) Document() map[string]any {
	doc := map[string]any{"v": DocumentVersion}
	if s.Root != nil {
		doc["filter"] = nodeDocument(s.Root)
	}
	if s.Q != "" {
		doc["q"] = s.Q
	}
	if len(s.Sort) > 0 {
		keys := make([]string, 0, len(s.Sort))
		for _, k := range s.Sort {
			if k.Desc {
				keys = append(keys, "-"+k.Field)
			} else {
				keys = append(keys, k.Field)
			}
		}
		doc["sort"] = keys
	}
	return doc
}

// DocumentJSON is Document encoded as JSON.
func (s *Spec) DocumentJSON() ([]byte, error) {
	return json.Marshal(s.Document())
}

func nodeDocument(n *Node) map[string]any {
	switch {
	case n.Leaf != nil:
		vals := make([]any, len(n.Leaf.Values))
		for i, v := range n.Leaf.Values {
			if t, ok := v.(time.Time); ok {
				v = t.UTC().Format(time.RFC3339Nano)
			}
			vals[i] = v
		}
		var value any = vals
		if n.Leaf.Op != OpIn && n.Leaf.Op != OpNotIn {
			value = vals[0]
		}
		return map[string]any{"field": n.Leaf.Field, "op": string(n.Leaf.Op), "value": value}
	case n.Not != nil:
		return map[string]any{"not": nodeDocument(n.Not)}
	case n.Any != nil:
		return map[string]any{"any": nodeList(n.Any)}
	default:
		return map[string]any{"all": nodeList(n.All)}
	}
}

func nodeList(nodes []*Node) []any {
	out := make([]any, 0, len(nodes))
	for _, c := range nodes {
		out = append(out, nodeDocument(c))
	}
	return out
}

// Overlay applies explicit request params on top of a stored spec (a saved
// view, RFC-048 §3.8): every top-level leaf of the request replaces the
// stored top-level leaves on the same field, the request's other leaves are
// added, and the request's q, sort and page win when set. The stored tree
// below the top level is kept as is. The result is within MaxLeaves or an
// error.
func Overlay(stored, request *Spec) (*Spec, error) {
	out := &Spec{Q: stored.Q, Sort: stored.Sort, Page: request.Page, PerPage: request.PerPage,
		UnknownParams: request.UnknownParams, AliasesUsed: request.AliasesUsed}
	if request.Q != "" {
		out.Q = request.Q
	}
	if len(request.Sort) > 0 {
		out.Sort = request.Sort
	}
	base := stored
	for _, l := range request.Leaves() {
		base = base.Without(l.Field)
	}
	var kids []*Node
	if base.Root != nil {
		if base.Root.All != nil {
			kids = append(kids, base.Root.All...)
		} else {
			kids = append(kids, base.Root)
		}
	}
	if request.Root != nil {
		kids = append(kids, request.Root.All...)
	}
	if len(kids) > 0 {
		out.Root = &Node{All: kids}
	}
	if n := len(out.Leaves()); n > MaxLeaves {
		return nil, &Error{Details: []Detail{{Param: "view", Reason: "the view and the request params together have too many conditions"}}}
	}
	return out, nil
}
