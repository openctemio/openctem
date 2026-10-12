package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/openctemio/openctem/api/tools/lint/openapischema"
)

// Marker identifies the report, so CI updates its own pull request comment
// instead of adding a new one on every push.
const Marker = "<!-- openctem-contract-diff -->"

// maxLines caps each section of the report; a pull request comment holds at
// most 65,536 characters.
const maxLines = 120

// bundle is one side's generated contract files.
type bundle struct {
	ops         map[string]operation // "METHOD /api/v1/path"
	defs        openapischema.Definitions
	permissions map[string]string // route -> canonical gate JSON
	routes      map[string]bool
}

type param struct {
	Name     string         `yaml:"name"`
	In       string         `yaml:"in"`
	Required bool           `yaml:"required"`
	Type     string         `yaml:"type"`
	Schema   map[string]any `yaml:"schema"`
}

type response struct {
	Schema map[string]any `yaml:"schema"`
}

type operation struct {
	Parameters []param             `yaml:"parameters"`
	Responses  map[string]response `yaml:"responses"`
}

var methods = []string{"get", "put", "post", "delete", "patch", "head", "options"}

func readOptional(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) || (err == nil && len(bytes.TrimSpace(raw)) == 0) {
		return nil, nil
	}
	return raw, err
}

func loadBundle(dir string) (*bundle, error) {
	b := &bundle{ops: map[string]operation{}, permissions: map[string]string{}, routes: map[string]bool{}}
	raw, err := readOptional(filepath.Join(dir, "swagger.yaml"))
	if err != nil {
		return nil, err
	}
	if raw != nil {
		if err := b.parseSpec(raw); err != nil {
			return nil, fmt.Errorf("swagger.yaml: %w", err)
		}
	}
	raw, err = readOptional(filepath.Join(dir, "api-route-permissions.json"))
	if err != nil {
		return nil, err
	}
	if raw != nil {
		var m map[string]json.RawMessage
		if err := json.Unmarshal(raw, &m); err != nil {
			return nil, fmt.Errorf("api-route-permissions.json: %w", err)
		}
		for k, v := range m {
			b.permissions[k] = canonicalJSON(v)
		}
	}
	raw, err = readOptional(filepath.Join(dir, "routes.txt"))
	if err != nil {
		return nil, err
	}
	for _, l := range strings.Split(string(raw), "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
			b.routes[l] = true
		}
	}
	return b, nil
}

func (b *bundle) parseSpec(raw []byte) error {
	var s struct {
		BasePath string                          `yaml:"basePath"`
		Paths    map[string]map[string]yaml.Node `yaml:"paths"`
	}
	if err := yaml.Unmarshal(raw, &s); err != nil {
		return err
	}
	for path, item := range s.Paths {
		for _, m := range methods {
			node, ok := item[m]
			if !ok {
				continue
			}
			var op operation
			if err := node.Decode(&op); err != nil {
				return fmt.Errorf("%s %s: %w", m, path, err)
			}
			b.ops[strings.ToUpper(m)+" "+s.BasePath+path] = op
		}
	}
	defs, err := openapischema.Parse(raw)
	if err != nil {
		return err
	}
	b.defs = defs
	return nil
}

// canonicalSchema renders a schema without its prose (description, example,
// title, format), with sorted keys, so two renderings compare equal exactly
// when the shapes do.
func canonicalSchema(s map[string]any) string {
	if s == nil {
		return ""
	}
	out, _ := json.Marshal(stripProse(s))
	return string(out)
}

func stripProse(v any) any {
	switch t := v.(type) {
	case map[string]any:
		m := make(map[string]any, len(t))
		for k, x := range t {
			switch k {
			case "description", "example", "title", "format":
				continue
			}
			m[k] = stripProse(x)
		}
		return m
	case []any:
		l := make([]any, len(t))
		for i, x := range t {
			l[i] = stripProse(x)
		}
		return l
	}
	return v
}

func canonicalJSON(raw json.RawMessage) string {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return string(bytes.TrimSpace(raw))
	}
	out, _ := json.Marshal(v)
	return string(out)
}

// report is the difference between two bundles.
type report struct {
	Breaking  []string
	Additions []string
	Other     []string
	Gates     []gateChange
	RoutesAdd []string
	RoutesDel []string
}

type gateChange struct{ Route, Before, After string }

func (r report) empty() bool {
	return len(r.Breaking)+len(r.Additions)+len(r.Other)+len(r.Gates)+len(r.RoutesAdd)+len(r.RoutesDel) == 0
}

func compare(base, head *bundle) report {
	var r report
	compareOps(base, head, &r)
	for _, c := range openapischema.Compare(base.defs, head.defs) {
		line := "`" + c.Definition
		if c.Property != "" {
			line += "." + c.Property
		}
		line += "`: " + c.Kind
		if c.Before != "" || c.After != "" {
			line += fmt.Sprintf(" (`%s` → `%s`)", orDash(c.Before), orDash(c.After))
		}
		switch {
		case c.Breaking():
			r.Breaking = append(r.Breaking, line)
		case c.Kind == openapischema.DefinitionAdded || c.Kind == openapischema.PropertyAdded:
			r.Additions = append(r.Additions, line)
		default:
			r.Other = append(r.Other, line)
		}
	}
	for route, before := range base.permissions {
		if after, ok := head.permissions[route]; !ok {
			r.Gates = append(r.Gates, gateChange{route, before, ""})
		} else if after != before {
			r.Gates = append(r.Gates, gateChange{route, before, after})
		}
	}
	for route, after := range head.permissions {
		if _, ok := base.permissions[route]; !ok {
			r.Gates = append(r.Gates, gateChange{route, "", after})
		}
	}
	sort.Slice(r.Gates, func(i, j int) bool { return r.Gates[i].Route < r.Gates[j].Route })
	for route := range head.routes {
		if !base.routes[route] {
			r.RoutesAdd = append(r.RoutesAdd, route)
		}
	}
	for route := range base.routes {
		if !head.routes[route] {
			r.RoutesDel = append(r.RoutesDel, route)
		}
	}
	sort.Strings(r.RoutesAdd)
	sort.Strings(r.RoutesDel)
	sort.Strings(r.Breaking)
	sort.Strings(r.Additions)
	sort.Strings(r.Other)
	return r
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func compareOps(base, head *bundle, r *report) {
	for key, bop := range base.ops {
		hop, ok := head.ops[key]
		if !ok {
			r.Breaking = append(r.Breaking, "`"+key+"`: operation removed")
			continue
		}
		compareParams(key, bop, hop, r)
		for code, bresp := range bop.Responses {
			if !strings.HasPrefix(code, "2") {
				continue
			}
			hresp, ok := hop.Responses[code]
			switch {
			case !ok:
				r.Breaking = append(r.Breaking, fmt.Sprintf("`%s`: response %s removed", key, code))
			case canonicalSchema(bresp.Schema) != canonicalSchema(hresp.Schema):
				r.Breaking = append(r.Breaking, fmt.Sprintf("`%s`: response %s schema changed (`%s` → `%s`)",
					key, code, orDash(canonicalSchema(bresp.Schema)), orDash(canonicalSchema(hresp.Schema))))
			}
		}
	}
	for key := range head.ops {
		if _, ok := base.ops[key]; !ok {
			r.Additions = append(r.Additions, "`"+key+"`: operation added")
		}
	}
}

func compareParams(key string, bop, hop operation, r *report) {
	index := func(ps []param) map[string]param {
		m := make(map[string]param, len(ps))
		for _, p := range ps {
			m[p.In+":"+p.Name] = p
		}
		return m
	}
	bp, hp := index(bop.Parameters), index(hop.Parameters)
	for id, b := range bp {
		h, ok := hp[id]
		switch {
		case !ok:
			r.Other = append(r.Other, fmt.Sprintf("`%s`: %s parameter `%s` removed", key, b.In, b.Name))
		case !b.Required && h.Required:
			r.Breaking = append(r.Breaking, fmt.Sprintf("`%s`: %s parameter `%s` is now required", key, b.In, b.Name))
		case b.Required && !h.Required:
			r.Other = append(r.Other, fmt.Sprintf("`%s`: %s parameter `%s` is no longer required", key, b.In, b.Name))
		}
		if ok && (b.Type != h.Type || canonicalSchema(b.Schema) != canonicalSchema(h.Schema)) {
			r.Breaking = append(r.Breaking, fmt.Sprintf("`%s`: %s parameter `%s` changed type (`%s` → `%s`)",
				key, b.In, b.Name, orDash(b.Type+canonicalSchema(b.Schema)), orDash(h.Type+canonicalSchema(h.Schema))))
		}
	}
	for id, h := range hp {
		if _, ok := bp[id]; ok {
			continue
		}
		if h.Required {
			r.Breaking = append(r.Breaking, fmt.Sprintf("`%s`: new required %s parameter `%s`", key, h.In, h.Name))
		} else {
			r.Additions = append(r.Additions, fmt.Sprintf("`%s`: new optional %s parameter `%s`", key, h.In, h.Name))
		}
	}
}

func render(r report, baseLabel, headLabel string) string {
	var b strings.Builder
	b.WriteString(Marker + "\n## API contract changes\n\n")
	fmt.Fprintf(&b, "Generated from the Go source for `%s` and `%s` (the contract files are not committed; `make generate` produces them).\n\n", baseLabel, headLabel)
	if r.empty() {
		b.WriteString("No change to operations, request/response shapes, route gates or registered routes.\n")
		return b.String()
	}
	fmt.Fprintf(&b, "**%d potentially breaking** · %d added · %d other · %d route gate change(s) · %d route(s) added, %d removed\n",
		len(r.Breaking), len(r.Additions), len(r.Other), len(r.Gates), len(r.RoutesAdd), len(r.RoutesDel))
	list(&b, "Potentially breaking", "An existing client may depend on what changed. Intended? Say so in the pull request.", r.Breaking, true)
	if len(r.Gates) > 0 {
		b.WriteString("\n### Route gates (web console permission map)\n\nWhat a caller needs for a mutating route, as the web console reads it from the route table. Review these as authorization changes.\n\n")
		b.WriteString("| Route | Before | After |\n|---|---|---|\n")
		for i, g := range r.Gates {
			if i == maxLines {
				fmt.Fprintf(&b, "| … %d more | | |\n", len(r.Gates)-maxLines)
				break
			}
			fmt.Fprintf(&b, "| `%s` | %s | %s |\n", g.Route, cell(g.Before, "(no route)"), cell(g.After, "(removed)"))
		}
	}
	list(&b, "Added", "", r.Additions, false)
	list(&b, "Other changes", "", r.Other, false)
	routes := make([]string, 0, len(r.RoutesAdd)+len(r.RoutesDel))
	for _, x := range r.RoutesAdd {
		routes = append(routes, "+ `"+x+"`")
	}
	for _, x := range r.RoutesDel {
		routes = append(routes, "− `"+x+"`")
	}
	list(&b, "Registered routes", "Documented or not (api/openapi/routes.txt).", routes, false)
	return b.String()
}

func cell(s, empty string) string {
	if s == "" {
		return empty
	}
	return "`" + strings.ReplaceAll(s, "|", "\\|") + "`"
}

func list(b *strings.Builder, title, note string, items []string, open bool) {
	if len(items) == 0 {
		return
	}
	if open {
		fmt.Fprintf(b, "\n### %s (%d)\n\n", title, len(items))
		if note != "" {
			b.WriteString(note + "\n\n")
		}
	} else {
		fmt.Fprintf(b, "\n<details><summary><b>%s (%d)</b></summary>\n\n", title, len(items))
		if note != "" {
			b.WriteString(note + "\n\n")
		}
	}
	for i, it := range items {
		if i == maxLines {
			fmt.Fprintf(b, "- … %d more\n", len(items)-maxLines)
			break
		}
		b.WriteString("- " + it + "\n")
	}
	if !open {
		b.WriteString("\n</details>\n")
	}
}
