// Package apispec reads an API description (OpenAPI 3, Swagger 2, a Postman
// 2.1 collection, a HAR 1.2 capture, or a GraphQL introspection result) into
// the operations it declares: a method, a path template and the parameter
// NAMES (docs/rfcs/RFC-056-web-attack-surface.md WS13). The platform compares
// them with the endpoints scans observed (drift: shadow, orphan, zombie).
//
// Hostile input is expected:
//   - the document is bounded (MaxSpecBytes), YAML aliases are bounded by
//     the decoder, operations and parameters are capped;
//   - no $ref is ever fetched: only local "#/..." parameter and schema
//     references are read, one level deep;
//   - values are never kept: a HAR capture's query values, form values,
//     headers and cookies, and every example in a spec, are dropped; only
//     names are read.
package apispec

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

// Limits.
const (
	MaxSpecBytes        = 10 << 20
	MaxOperations       = 5000
	MaxParamsPerOp      = 100
	maxPathBytes        = 2048
	maxNameBytes        = 128
	maxPostmanItemDepth = 16
)

// Format of a description.
type Format string

// Formats.
const (
	FormatOpenAPI3 Format = "openapi3"
	FormatSwagger2 Format = "swagger2"
	FormatPostman  Format = "postman"
	FormatHAR      Format = "har"
	FormatGraphQL  Format = "graphql"
)

// ErrUnsupported: the document is none of the formats.
var ErrUnsupported = errors.New("apispec: not an OpenAPI, Swagger, Postman, HAR or GraphQL introspection document")

// Param is one parameter name of an operation.
type Param struct {
	// Location is query, path, header, cookie, form, json, multipart or
	// graphql_arg.
	Location string `json:"location"`
	Name     string `json:"name"`
	Required bool   `json:"required,omitempty"`
}

// Operation is one declared method and path.
type Operation struct {
	Method     string
	Path       string // "/users/{id}"
	Deprecated bool
	Params     []Param
}

// Spec is a parsed description.
type Spec struct {
	Format     Format
	Title      string
	Version    string
	Operations []Operation
	// Truncated counts operations beyond MaxOperations.
	Truncated int
}

// Parse reads a JSON or YAML description. graphQLPath is the path a GraphQL
// introspection result is served at ("" for /graphql).
func Parse(data []byte, graphQLPath string) (*Spec, error) {
	if len(data) > MaxSpecBytes {
		return nil, fmt.Errorf("apispec: larger than %d bytes", MaxSpecBytes)
	}
	doc, err := decode(data)
	if err != nil {
		return nil, err
	}
	root, ok := doc.(map[string]any)
	if !ok {
		return nil, ErrUnsupported
	}
	var s *Spec
	switch {
	case strings.HasPrefix(str(root["openapi"]), "3."):
		s = parseOpenAPI(root, FormatOpenAPI3, "")
	case str(root["swagger"]) == "2.0":
		s = parseOpenAPI(root, FormatSwagger2, str(root["basePath"]))
	case strings.Contains(str(obj(root["info"])["schema"]), "postman"):
		s = parsePostman(root)
	case obj(root["log"])["entries"] != nil:
		s = parseHAR(root)
	case obj(obj(root["data"])["__schema"]) != nil || obj(root["__schema"]) != nil:
		s = parseGraphQL(root, graphQLPath)
	default:
		return nil, ErrUnsupported
	}
	s.Operations = dedup(s.Operations)
	return s, nil
}

func decode(data []byte) (any, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[') {
		var v any
		dec := json.NewDecoder(bytes.NewReader(trimmed))
		dec.UseNumber()
		if err := dec.Decode(&v); err != nil {
			return nil, fmt.Errorf("apispec: invalid JSON: %w", err)
		}
		return v, nil
	}
	var v any
	// yaml.v3 refuses documents with excessive aliasing (alias bombs).
	if err := yaml.Unmarshal(trimmed, &v); err != nil {
		return nil, fmt.Errorf("apispec: invalid YAML: %w", err)
	}
	return normalizeYAML(v), nil
}

// normalizeYAML turns map[string]any trees from yaml.v3 into the same shape
// as JSON (it already yields map[string]any for string keys).
func normalizeYAML(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, x := range t {
			t[k] = normalizeYAML(x)
		}
		return t
	case []any:
		for i, x := range t {
			t[i] = normalizeYAML(x)
		}
		return t
	}
	return v
}

func obj(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func arr(v any) []any {
	a, _ := v.([]any)
	return a
}

func str(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case json.Number:
		return t.String()
	}
	return ""
}

func boolean(v any) bool {
	b, _ := v.(bool)
	return b
}

// cleanName keeps a printable parameter name of bounded length.
func cleanName(n string) string {
	n = strings.TrimSpace(n)
	if n == "" || len(n) > maxNameBytes || !utf8.ValidString(n) || strings.IndexFunc(n, unicode.IsControl) >= 0 {
		return ""
	}
	return n
}

// cleanPath normalises a declared path: absolute, no query or fragment,
// bounded, printable.
func cleanPath(p string) string {
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	p = strings.TrimSpace(p)
	if p == "" {
		p = "/"
	}
	if p[0] != '/' {
		p = "/" + p
	}
	for strings.Contains(p, "//") {
		p = strings.ReplaceAll(p, "//", "/")
	}
	if len(p) > 1 {
		p = strings.TrimSuffix(p, "/")
	}
	if len(p) > maxPathBytes || !utf8.ValidString(p) || strings.IndexFunc(p, unicode.IsControl) >= 0 {
		return ""
	}
	return p
}

var openAPIMethods = []string{"get", "put", "post", "delete", "options", "head", "patch", "trace"}

func parseOpenAPI(root map[string]any, f Format, basePath string) *Spec {
	s := &Spec{Format: f, Title: str(obj(root["info"])["title"]), Version: str(obj(root["info"])["version"])}
	paths := obj(root["paths"])
	keys := make([]string, 0, len(paths))
	for k := range paths {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, p := range keys {
		item := obj(paths[p])
		if item == nil {
			continue
		}
		path := cleanPath(strings.TrimSuffix(basePath, "/") + "/" + strings.TrimPrefix(p, "/"))
		if path == "" {
			continue
		}
		shared := arr(item["parameters"])
		for _, m := range openAPIMethods {
			op := obj(item[m])
			if op == nil {
				continue
			}
			if len(s.Operations) >= MaxOperations {
				s.Truncated++
				continue
			}
			o := Operation{Method: strings.ToUpper(m), Path: path, Deprecated: boolean(op["deprecated"])}
			for _, raw := range append(append([]any{}, shared...), arr(op["parameters"])...) {
				addOpenAPIParam(root, &o, obj(raw))
			}
			addBodyParams(root, &o, op, f)
			s.Operations = append(s.Operations, o)
		}
	}
	return s
}

// resolve follows one local reference ("#/components/parameters/x").
func resolve(root, v map[string]any) map[string]any {
	ref := str(v["$ref"])
	if ref == "" {
		return v
	}
	if !strings.HasPrefix(ref, "#/") {
		return nil // never fetched
	}
	cur := any(root)
	for _, part := range strings.Split(strings.TrimPrefix(ref, "#/"), "/") {
		part = strings.ReplaceAll(strings.ReplaceAll(part, "~1", "/"), "~0", "~")
		cur = obj(cur)[part]
		if cur == nil {
			return nil
		}
	}
	return obj(cur)
}

var openAPIIn = map[string]string{"query": "query", "path": "path", "header": "header", "cookie": "cookie", "formData": "form"}

func addOpenAPIParam(root map[string]any, o *Operation, p map[string]any) {
	p = resolve(root, p)
	if p == nil {
		return
	}
	loc, ok := openAPIIn[str(p["in"])]
	if !ok {
		return
	}
	o.addParam(loc, str(p["name"]), boolean(p["required"]))
}

// addBodyParams reads the top-level property names of a JSON or form
// request body (one local $ref level).
func addBodyParams(root map[string]any, o *Operation, op map[string]any, f Format) {
	if f == FormatSwagger2 {
		for _, raw := range arr(op["parameters"]) {
			p := resolve(root, obj(raw))
			if p != nil && str(p["in"]) == "body" {
				addSchemaProps(root, o, "json", obj(p["schema"]))
			}
		}
		return
	}
	content := obj(resolve(root, obj(op["requestBody"]))["content"])
	for ct, media := range content {
		loc := "json"
		switch {
		case strings.Contains(ct, "x-www-form-urlencoded"):
			loc = "form"
		case strings.Contains(ct, "multipart"):
			loc = "multipart"
		case !strings.Contains(ct, "json"):
			continue
		}
		addSchemaProps(root, o, loc, obj(obj(media)["schema"]))
	}
}

func addSchemaProps(root map[string]any, o *Operation, loc string, schema map[string]any) {
	schema = resolve(root, schema)
	if schema == nil {
		return
	}
	required := map[string]bool{}
	for _, r := range arr(schema["required"]) {
		required[str(r)] = true
	}
	props := obj(schema["properties"])
	names := make([]string, 0, len(props))
	for n := range props {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		name := n
		if loc == "json" {
			name = "/" + n
		}
		o.addParam(loc, name, required[n])
	}
}

func (o *Operation) addParam(loc, name string, required bool) {
	name = cleanName(name)
	if name == "" || len(o.Params) >= MaxParamsPerOp {
		return
	}
	for _, p := range o.Params {
		if p.Location == loc && p.Name == name {
			return
		}
	}
	o.Params = append(o.Params, Param{Location: loc, Name: name, Required: required})
}

func parsePostman(root map[string]any) *Spec {
	s := &Spec{Format: FormatPostman, Title: str(obj(root["info"])["name"])}
	var walk func(items []any, depth int)
	walk = func(items []any, depth int) {
		if depth > maxPostmanItemDepth {
			return
		}
		for _, raw := range items {
			it := obj(raw)
			if it == nil {
				continue
			}
			if sub := arr(it["item"]); sub != nil {
				walk(sub, depth+1)
				continue
			}
			req := obj(it["request"])
			if req == nil {
				continue
			}
			if len(s.Operations) >= MaxOperations {
				s.Truncated++
				continue
			}
			o, ok := postmanOperation(req)
			if ok {
				s.Operations = append(s.Operations, o)
			}
		}
	}
	walk(arr(root["item"]), 0)
	return s
}

// postmanVar turns ":id" and "{{id}}" path segments into "{id}".
func postmanVar(seg string) string {
	switch {
	case strings.HasPrefix(seg, ":") && len(seg) > 1:
		return "{" + seg[1:] + "}"
	case strings.HasPrefix(seg, "{{") && strings.HasSuffix(seg, "}}") && len(seg) > 4:
		return "{" + seg[2:len(seg)-2] + "}"
	}
	return seg
}

func postmanOperation(req map[string]any) (Operation, bool) {
	method := strings.ToUpper(str(req["method"]))
	if method == "" {
		method = "GET"
	}
	o := Operation{Method: method}
	var segs []string
	switch u := req["url"].(type) {
	case string:
		segs = rawURLSegments(u)
	case map[string]any:
		if p := arr(u["path"]); p != nil {
			for _, s := range p {
				segs = append(segs, str(s))
			}
		} else {
			segs = rawURLSegments(str(u["raw"]))
		}
		for _, q := range arr(u["query"]) {
			o.addParam("query", str(obj(q)["key"]), false)
		}
	default:
		return o, false
	}
	for i, s := range segs {
		segs[i] = postmanVar(s)
	}
	o.Path = cleanPath("/" + strings.Join(segs, "/"))
	if o.Path == "" {
		return o, false
	}
	body := obj(req["body"])
	switch str(body["mode"]) {
	case "urlencoded":
		for _, kv := range arr(body["urlencoded"]) {
			o.addParam("form", str(obj(kv)["key"]), false)
		}
	case "formdata":
		for _, kv := range arr(body["formdata"]) {
			o.addParam("multipart", str(obj(kv)["key"]), false)
		}
	}
	return o, true
}

// rawURLSegments returns the path segments of a raw URL, dropping a
// {{baseUrl}}-style host, the query and the fragment.
func rawURLSegments(raw string) []string {
	if i := strings.IndexAny(raw, "?#"); i >= 0 {
		raw = raw[:i]
	}
	if i := strings.Index(raw, "://"); i >= 0 {
		raw = raw[i+3:]
	}
	parts := strings.Split(raw, "/")
	if len(parts) > 0 {
		parts = parts[1:] // the host or {{baseUrl}}
	}
	out := parts[:0]
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parseHAR(root map[string]any) *Spec {
	s := &Spec{Format: FormatHAR, Title: "HAR capture"}
	for _, raw := range arr(obj(root["log"])["entries"]) {
		req := obj(obj(raw)["request"])
		if req == nil {
			continue
		}
		u, err := url.Parse(str(req["url"]))
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			continue
		}
		if len(s.Operations) >= MaxOperations {
			s.Truncated++
			continue
		}
		o := Operation{Method: strings.ToUpper(str(req["method"])), Path: cleanPath(u.EscapedPath())}
		if o.Method == "" || o.Path == "" {
			continue
		}
		// Names only: a capture's values (tokens, sessions) are never read.
		for _, q := range arr(req["queryString"]) {
			o.addParam("query", str(obj(q)["name"]), false)
		}
		for n := range u.Query() {
			o.addParam("query", n, false)
		}
		post := obj(req["postData"])
		loc := "form"
		if strings.Contains(str(post["mimeType"]), "multipart") {
			loc = "multipart"
		}
		for _, p := range arr(post["params"]) {
			o.addParam(loc, str(obj(p)["name"]), false)
		}
		s.Operations = append(s.Operations, o)
	}
	return s
}

func parseGraphQL(root map[string]any, path string) *Spec {
	schema := obj(obj(root["data"])["__schema"])
	if schema == nil {
		schema = obj(root["__schema"])
	}
	if path == "" {
		path = "/graphql"
	}
	o := Operation{Method: "POST", Path: cleanPath(path)}
	roots := map[string]bool{}
	for _, k := range []string{"queryType", "mutationType", "subscriptionType"} {
		if n := str(obj(schema[k])["name"]); n != "" {
			roots[n] = true
		}
	}
	for _, raw := range arr(schema["types"]) {
		t := obj(raw)
		if !roots[str(t["name"])] {
			continue
		}
		for _, f := range arr(t["fields"]) {
			o.addParam("graphql_arg", str(obj(f)["name"]), false)
		}
	}
	return &Spec{Format: FormatGraphQL, Title: "GraphQL schema", Operations: []Operation{o}}
}

// dedup merges operations of the same method and path, joining parameters.
func dedup(ops []Operation) []Operation {
	index := map[string]int{}
	out := make([]Operation, 0, len(ops))
	for _, o := range ops {
		k := o.Method + " " + o.Path
		i, ok := index[k]
		if !ok {
			index[k] = len(out)
			out = append(out, o)
			continue
		}
		for _, p := range o.Params {
			out[i].addParam(p.Location, p.Name, p.Required)
		}
		out[i].Deprecated = out[i].Deprecated || o.Deprecated
	}
	return out
}

// MatchKey is the comparison key of a method and a path template across
// spec and scan notations: every variable segment ("{id}", "{userId}",
// "{int}", "{uuid}") is "{}", so "/users/{userId}" matches "/users/{int}".
func MatchKey(method, path string) string {
	segs := strings.Split(path, "/")
	for i, s := range segs {
		if strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}") {
			segs[i] = "{}"
		}
	}
	return strings.ToUpper(method) + " " + strings.Join(segs, "/")
}
