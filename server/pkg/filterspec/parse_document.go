package filterspec

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"strconv"
	"strings"
)

// DocumentVersion is the FilterDocument version this package reads.
const DocumentVersion = 1

// ParseDocument decodes a FilterDocument (RFC-048 §3.6):
//
//	{"v":1, "filter":{...}, "q":"...", "sort":["-x"], "page":{"page":1,"per_page":50}}
//
// Unknown keys are errors (a document is a new contract, there is nothing to
// stay compatible with). Unknown fields are errors in every mode.
func ParseDocument(body []byte, reg *Registry, opts Options) (*Spec, error) {
	if len(body) > MaxBodyBytes {
		return nil, &Error{Details: []Detail{{Path: "$", Reason: "document is larger than " + strconv.Itoa(MaxBodyBytes>>10) + " KB"}}}
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var top any
	if err := dec.Decode(&top); err != nil {
		return nil, &Error{Details: []Detail{{Path: "$", Reason: "not valid JSON"}}}
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, &Error{Details: []Detail{{Path: "$", Reason: "trailing data after the document"}}}
	}
	obj, ok := top.(map[string]any)
	if !ok {
		return nil, &Error{Details: []Detail{{Path: "$", Reason: "must be a JSON object"}}}
	}
	return parseDocObject(obj, reg, opts)
}

// ParseDocumentValue is ParseDocument for an already-decoded document (a
// stored JSONB filter). Numbers must have been decoded with UseNumber or be
// float64.
func ParseDocumentValue(doc map[string]any, reg *Registry, opts Options) (*Spec, error) {
	raw, err := json.Marshal(doc)
	if err != nil {
		return nil, &Error{Details: []Detail{{Path: "$", Reason: "not encodable"}}}
	}
	return ParseDocument(raw, reg, opts)
}

type docParser struct {
	reg    *Registry
	opts   Options
	e      errs
	leaves int
}

func parseDocObject(obj map[string]any, reg *Registry, opts Options) (*Spec, error) {
	p := &docParser{reg: reg, opts: opts}
	spec := &Spec{}
	for _, k := range sortedKeys(obj) {
		v := obj[k]
		switch k {
		case "v":
			n, ok := v.(json.Number)
			if !ok || n.String() != strconv.Itoa(DocumentVersion) {
				p.e.path("v", "unsupported document version (expected 1)", "", false)
			}
		case "filter":
			spec.Root = p.filterRoot(v)
		case "q":
			s, ok := v.(string)
			if !ok {
				p.e.path("q", "must be a string", "", true)
				break
			}
			s = strings.TrimSpace(s)
			if err := checkText(s, MaxQLen); err != nil {
				p.e.path("q", err.Error(), "", true)
				break
			}
			spec.Q = s
		case "sort":
			p.sort(spec, v)
		case paramPage:
			p.page(spec, v)
		default:
			p.e.path(safePathKey(k), "unknown key", "", true)
		}
	}
	if p.leaves > MaxLeaves {
		p.e.path("filter", "too many conditions (max "+strconv.Itoa(MaxLeaves)+")", "", true)
	}
	checkOffset(spec, &p.e, opts)
	if err := p.e.err(); err != nil {
		return nil, err
	}
	return spec, nil
}

// filterRoot accepts a node or the leaf shorthand (flat param names).
func (p *docParser) filterRoot(v any) *Node {
	if v == nil {
		return nil
	}
	obj, ok := v.(map[string]any)
	if !ok {
		p.e.path("filter", "must be an object", "", true)
		return nil
	}
	if isNodeObject(obj) {
		return p.node(obj, "filter", 0)
	}
	// Shorthand: {"severity": ["critical"], "epss_score_gte": 0.1}.
	children := make([]*Node, 0, len(obj))
	for _, k := range sortedKeys(obj) {
		path := "filter." + safePathKey(k)
		f, op, err := p.reg.resolveParam(k)
		if err != nil {
			p.e.path(path, "unknown field", "", true)
			continue
		}
		if leaf := p.leaf(f, op, obj[k], path); leaf != nil {
			children = append(children, &Node{Leaf: leaf})
		}
	}
	if len(children) == 0 {
		return nil
	}
	return &Node{All: children}
}

func isNodeObject(obj map[string]any) bool {
	for _, k := range []string{"all", "any", "not", "field"} {
		if _, ok := obj[k]; ok {
			return true
		}
	}
	return false
}

// node parses an all/any/not group or a {field, op, value} leaf. depth is
// the number of groups above it.
func (p *docParser) node(obj map[string]any, path string, depth int) *Node {
	if len(obj) == 0 {
		p.e.path(path, "empty node", "", true)
		return nil
	}
	if _, isLeaf := obj["field"]; isLeaf {
		return p.leafNode(obj, path)
	}
	if len(obj) != 1 {
		p.e.path(path, "a node has exactly one of all, any, not, or a field leaf", "", true)
		return nil
	}
	if depth >= MaxDepth {
		p.e.path(path, "nested too deep (max "+strconv.Itoa(MaxDepth)+")", "", true)
		return nil
	}
	for k, v := range obj {
		sub := path + "." + safePathKey(k)
		switch k {
		case "not":
			child, ok := v.(map[string]any)
			if !ok {
				p.e.path(sub, "must be a node object", "", true)
				return nil
			}
			c := p.node(child, sub, depth+1)
			if c == nil {
				return nil
			}
			return &Node{Not: c}
		case "all", "any":
			arr, ok := v.([]any)
			if !ok || len(arr) == 0 {
				p.e.path(sub, "must be a non-empty array", "", true)
				return nil
			}
			if len(arr) > MaxLeaves {
				p.e.path(sub, "too many conditions", "", true)
				return nil
			}
			kids := make([]*Node, 0, len(arr))
			for i, item := range arr {
				ip := sub + "[" + strconv.Itoa(i) + "]"
				child, ok := item.(map[string]any)
				if !ok {
					p.e.path(ip, "must be a node object", "", true)
					continue
				}
				if c := p.node(child, ip, depth+1); c != nil {
					kids = append(kids, c)
				}
			}
			if k == "all" {
				return &Node{All: kids}
			}
			return &Node{Any: kids}
		default:
			p.e.path(sub, "unknown key", "", true)
			return nil
		}
	}
	return nil
}

func (p *docParser) leafNode(obj map[string]any, path string) *Node {
	for k := range obj {
		if k != "field" && k != "op" && k != "value" {
			p.e.path(path+"."+safePathKey(k), "unknown key", "", true)
			return nil
		}
	}
	name, _ := obj["field"].(string)
	opName, _ := obj["op"].(string)
	f, ok := p.reg.fields[name]
	if !ok {
		p.e.path(path+".field", "unknown field", "", true)
		return nil
	}
	op := Op(opName)
	if !f.allows(op) {
		p.e.path(path+".op", "operator not allowed on this field", "", true)
		return nil
	}
	v, has := obj["value"]
	if !has {
		p.e.path(path+".value", "value is required", "", true)
		return nil
	}
	leaf := p.leaf(f, op, v, path+".value")
	if leaf == nil {
		return nil
	}
	leaf.src = path + ".field"
	return &Node{Leaf: leaf}
}

// leaf converts a JSON value (scalar or array) into a validated leaf.
func (p *docParser) leaf(f *Field, op Op, v any, path string) *Leaf {
	p.leaves++
	var items []any
	if arr, isArr := v.([]any); isArr {
		if op != OpIn && op != OpNotIn {
			p.e.path(path, "takes a single value, not an array", "", true)
			return nil
		}
		items = arr
	} else {
		items = []any{v}
	}
	if len(items) == 0 {
		p.e.path(path, "must not be empty", "", true)
		return nil
	}
	if len(items) > f.MaxValuesDocument {
		p.e.path(path, "too many values (max "+strconv.Itoa(f.MaxValuesDocument)+")", "", true)
		return nil
	}
	raw := make([]string, 0, len(items))
	for i, it := range items {
		target := f
		if op == OpIsNull {
			target = &Field{Type: TypeBool}
		}
		s, err := jsonScalar(target, it)
		if err != nil {
			ip := path
			if len(items) > 1 {
				ip = path + "[" + strconv.Itoa(i) + "]"
			}
			p.e.path(ip, err.Error(), "", true)
			return nil
		}
		raw = append(raw, s)
	}
	leaf, ok := buildLeaf(f, op, raw, f.MaxValuesDocument, p.opts.now(), func(reason, val string) {
		p.e.path(path, reason, val, f.FreeText)
	})
	if !ok {
		return nil
	}
	leaf.src, leaf.srcPath = path, true
	return leaf
}

func (p *docParser) sort(spec *Spec, v any) {
	var keys []string
	switch x := v.(type) {
	case string:
		for _, k := range strings.Split(x, ",") {
			if k = strings.TrimSpace(k); k != "" {
				keys = append(keys, k)
			}
		}
	case []any:
		for i, it := range x {
			s, ok := it.(string)
			if !ok {
				p.e.path("sort["+strconv.Itoa(i)+"]", "must be a string", "", true)
				return
			}
			keys = append(keys, strings.TrimSpace(s))
		}
	default:
		p.e.path("sort", "must be an array of strings", "", true)
		return
	}
	sk, probs := parseSortKeys(p.reg, keys)
	for _, pr := range probs {
		p.e.path("sort", pr.reason, pr.value, false)
	}
	spec.Sort = sk
}

func (p *docParser) page(spec *Spec, v any) {
	obj, ok := v.(map[string]any)
	if !ok {
		p.e.path("page", "must be an object", "", true)
		return
	}
	for _, k := range sortedKeys(obj) {
		switch k {
		case paramPage, paramPerPage:
			n, ok := obj[k].(json.Number)
			i, err := n.Int64()
			if !ok || err != nil || i < 1 || i > 1<<31 {
				p.e.path("page."+k, "must be a positive integer", "", true)
				continue
			}
			if k == paramPage {
				spec.Page = int(i)
			} else {
				spec.PerPage = min(int(i), p.opts.maxPerPage())
			}
		case paramCursor:
			// Reserved: keyset cursors arrive with export (RFC-048 §3.5).
			if obj[k] != nil {
				p.e.path("page.cursor", "cursors are not supported on this endpoint yet", "", true)
			}
		default:
			p.e.path("page."+safePathKey(k), "unknown key", "", true)
		}
	}
}

func sortedKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// safePathKey keeps request-controlled keys in error paths bounded.
func safePathKey(k string) string {
	if s := safeName(k); s != otherName {
		return s
	}
	return "<invalid>"
}
