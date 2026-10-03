package ingest

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/ctis"
)

// TestCTISSchemaParity proves the Go structs the strict v2 decoder uses and
// the published JSON Schema (schemas/v1 in the ctis module) describe the same
// documents (RFC-026 WP-A3). The strict decoder rejects unknown fields, so a
// field the schema has and the structs lack would refuse a schema-valid
// report, and a field only the structs have is an undocumented contract.
//
// It walks ctis.Report and the schema together, following $ref, and compares
// member names, required members and the enums the Go side also enumerates.
// Known, reviewed differences are listed in schemaParityExceptions with the
// reason; anything else fails.
func TestCTISSchemaParity(t *testing.T) {
	dir := ctisSchemaDir(t)
	w := &parityWalker{t: t, dir: dir, docs: map[string]map[string]any{}, seen: map[string]bool{}}
	root := w.load("report.json")
	w.compare("Report", reflect.TypeOf(ctis.Report{}), root, "report.json")

	enums := []struct {
		pointer string
		values  []string
	}{
		{"finding.json#/properties/severity", stringsOf(ctis.AllSeverities())},
		{"finding.json#/properties/type", stringsOf(ctis.AllFindingTypes())},
		{"asset.json#/properties/type", stringsOf(ctis.AllAssetTypes())},
		{"asset.json#/properties/criticality", stringsOf(ctis.AllCriticalities())},
		{"finding.json#/properties/status", stringsOf(ctis.AllFindingStatuses())},
	}
	for _, e := range enums {
		file, ptr, _ := strings.Cut(e.pointer, "#")
		node, _ := w.deref(w.resolvePointer(w.load(file), ptr), file)
		schemaVals := enumOf(node)
		if schemaVals == nil {
			t.Errorf("%s: schema has no enum", e.pointer)
			continue
		}
		if d := diff(schemaVals, e.values); d != "" {
			if !w.excepted("enum " + e.pointer) {
				t.Errorf("enum %s differs between schema and Go: %s", e.pointer, d)
			}
		}
	}

	for k := range schemaParityExceptions {
		if !w.used[k] {
			t.Errorf("stale parity exception %q: the difference no longer exists, remove it", k)
		}
	}
}

// schemaParityExceptions are reviewed differences between the ctis Go structs
// and the published schema. Each must still exist (the test fails on a stale
// entry), and nothing may be added without a reason. Empty since ctis v1.3.0,
// whose own test makes the schema and the Go types agree field by field and
// enum by enum; the 32 entries recorded against v1.1.0 were all fixed there.
var schemaParityExceptions = map[string]string{}

func stringsOf[T ~string](in []T) []string {
	out := make([]string, len(in))
	for i, v := range in {
		out[i] = string(v)
	}
	return out
}

func enumOf(node map[string]any) []string {
	raw, ok := node["enum"].([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func diff(schema, goVals []string) string {
	s := map[string]bool{}
	for _, v := range schema {
		s[v] = true
	}
	g := map[string]bool{}
	for _, v := range goVals {
		g[v] = true
	}
	var onlyS, onlyG []string
	for v := range s {
		if !g[v] {
			onlyS = append(onlyS, v)
		}
	}
	for v := range g {
		if !s[v] {
			onlyG = append(onlyG, v)
		}
	}
	sort.Strings(onlyS)
	sort.Strings(onlyG)
	if len(onlyS) == 0 && len(onlyG) == 0 {
		return ""
	}
	return "schema only " + strings.Join(onlyS, ",") + "; Go only " + strings.Join(onlyG, ",")
}

func ctisSchemaDir(t *testing.T) string {
	t.Helper()
	cmd := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "github.com/openctemio/ctis")
	cmd.Env = append(os.Environ(), "GOWORK=off", "GOFLAGS=-mod=mod")
	out, err := cmd.Output()
	if err != nil {
		t.Skipf("cannot locate the ctis module: %v", err)
	}
	dir := filepath.Join(strings.TrimSpace(string(out)), "schemas", "v1")
	if _, err := os.Stat(filepath.Join(dir, "report.json")); err != nil {
		t.Fatalf("ctis module has no schemas/v1: %v", err)
	}
	return dir
}

type parityWalker struct {
	t    *testing.T
	dir  string
	docs map[string]map[string]any
	seen map[string]bool
	used map[string]bool
}

func (w *parityWalker) excepted(key string) bool {
	if _, ok := schemaParityExceptions[key]; ok {
		if w.used == nil {
			w.used = map[string]bool{}
		}
		w.used[key] = true
		return true
	}
	return false
}

func (w *parityWalker) load(file string) map[string]any {
	if d, ok := w.docs[file]; ok {
		return d
	}
	b, err := os.ReadFile(filepath.Join(w.dir, file)) //nolint:gosec // module cache path
	if err != nil {
		w.t.Fatalf("read %s: %v", file, err)
	}
	var d map[string]any
	if err := json.Unmarshal(b, &d); err != nil {
		w.t.Fatalf("parse %s: %v", file, err)
	}
	w.docs[file] = d
	return d
}

func (w *parityWalker) resolvePointer(doc map[string]any, ptr string) map[string]any {
	node := doc
	for _, part := range strings.Split(strings.TrimPrefix(ptr, "/"), "/") {
		if part == "" {
			continue
		}
		next, ok := node[part].(map[string]any)
		if !ok {
			return nil
		}
		node = next
	}
	return node
}

// deref follows a $ref (local "#/..." or "file.json[#/...]") from file.
func (w *parityWalker) deref(node map[string]any, file string) (map[string]any, string) {
	for i := 0; i < 8; i++ {
		ref, ok := node["$ref"].(string)
		if !ok {
			return node, file
		}
		target, ptr, _ := strings.Cut(ref, "#")
		if target != "" {
			file = target
		}
		node = w.resolvePointer(w.load(file), ptr)
		if node == nil {
			w.t.Fatalf("unresolvable $ref %q in %s", ref, file)
		}
	}
	return node, file
}

var timeType = reflect.TypeOf(time.Time{})

func (w *parityWalker) compare(name string, gt reflect.Type, schema map[string]any, file string) {
	schema, file = w.deref(schema, file)
	for gt.Kind() == reflect.Pointer {
		gt = gt.Elem()
	}
	if gt.Kind() != reflect.Struct || gt == timeType {
		return
	}
	key := gt.String() + "@" + file
	if w.seen[key] {
		return
	}
	w.seen[key] = true

	props, _ := schema["properties"].(map[string]any)
	if props == nil {
		return // free-form object in the schema
	}
	// Exceptions are keyed by the Go type, which is stable; name is the
	// path it was first reached by, for the message.
	tn := gt.Name() + "@" + file
	goFields := map[string]reflect.StructField{}
	for i := 0; i < gt.NumField(); i++ {
		f := gt.Field(i)
		tag := strings.Split(f.Tag.Get("json"), ",")[0]
		if tag == "-" || !f.IsExported() {
			continue
		}
		if tag == "" {
			tag = f.Name
		}
		goFields[tag] = f
	}
	for p := range props {
		if _, ok := goFields[p]; !ok && !w.excepted("schema-only "+tn+"."+p) {
			w.t.Errorf("%s: schema member %q has no Go field (%s); exception key %q", name, p, file, "schema-only "+tn+"."+p)
		}
	}
	for g := range goFields {
		if _, ok := props[g]; !ok && !w.excepted("go-only "+tn+"."+g) {
			w.t.Errorf("%s: Go field %q is not in the schema (%s); exception key %q", name, g, file, "go-only "+tn+"."+g)
		}
	}
	if req, ok := schema["required"].([]any); ok {
		for _, r := range req {
			rs, _ := r.(string)
			if _, ok := goFields[rs]; !ok && !w.excepted("required "+tn+"."+rs) {
				w.t.Errorf("%s: required schema member %q has no Go field", name, rs)
			}
		}
	}
	for p, sub := range props {
		f, ok := goFields[p]
		subMap, isMap := sub.(map[string]any)
		if !ok || !isMap {
			continue
		}
		ft := f.Type
		for ft.Kind() == reflect.Pointer || ft.Kind() == reflect.Slice {
			ft = ft.Elem()
			if items, ok := subMap["items"].(map[string]any); ok {
				subMap = items
			}
		}
		w.compare(name+"."+p, ft, subMap, file)
	}
}
