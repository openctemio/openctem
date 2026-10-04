package filterspec

import (
	"net/url"
	"strings"
	"testing"
	"time"
)

// Fuzz targets for the two decoders (run nightly by .github/workflows/api-fuzz.yml).
// Invariants: no panic; a failure is always *Error; a success is within the
// limits and compiles, for an admin and a restricted member, to SQL with one
// bound argument per placeholder and no request value in its text.

func FuzzParseValues(f *testing.F) {
	for _, s := range []string{
		"severity=critical,high&status_not=resolved&epss_score_gte=0.1&q=log4j&sort=-severity",
		"severities=high&exclude_statuses=resolved&search=x&assigned_to_me=true",
		"last_seen_at_gte=-P30D&network_port=443&asset_id=44444444-4444-4444-4444-444444444444",
		"file_path_contains=%27%3B--&asset_tag=prod,dev&assigned_to_null=true",
		"severity=" + strings.Repeat("high,", 120),
		"q=%00&sort=%E2%80%AEseverity&page=99999999999999999999",
		"page=101&per_page=100",
	} {
		f.Add(s)
	}
	reg := testRegistry(f)
	admin, member := adminActor(f), memberActor(f)
	f.Fuzz(func(t *testing.T, raw string) {
		q, err := url.ParseQuery(raw)
		if err != nil {
			return
		}
		for _, mode := range []UnknownMode{UnknownWarn, UnknownStrict} {
			spec, err := ParseValues(q, reg, Options{Unknown: mode, Now: func() time.Time { return fixedNow }})
			checkFuzzResult(t, reg, spec, err, admin, member, false)
		}
	})
}

func FuzzParseDocument(f *testing.F) {
	for _, s := range []string{
		`{"v":1,"filter":{"all":[{"field":"severity","op":"in","value":["critical","high"]},{"any":[{"field":"is_in_kev","op":"eq","value":true},{"field":"epss_score","op":"gte","value":0.1}]},{"not":{"field":"asset_tag","op":"in","value":["sandbox"]}}]},"q":"log4j","sort":["-severity"],"page":{"per_page":100}}`,
		`{"filter":{"severity":["critical"],"epss_score_gte":0.1,"status_not":"resolved"}}`,
		`{"filter":{"all":[{"any":[{"not":{"all":[{"field":"severity","op":"in","value":["high"]}]}}]}]}}`,
		`{"filter":{"field":"asset_id","op":"in","value":["44444444-4444-4444-4444-444444444444"]}}`,
		`{"filter":{"field":"file_path","op":"contains","value":"%_\\"}}`,
		`{"q":"\u0000","sort":"x"}`,
		`[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[`,
	} {
		f.Add([]byte(s))
	}
	reg := testRegistry(f)
	admin, member := adminActor(f), memberActor(f)
	f.Fuzz(func(t *testing.T, body []byte) {
		spec, err := ParseDocument(body, reg, Options{Now: func() time.Time { return fixedNow }})
		checkFuzzResult(t, reg, spec, err, admin, member, true)
	})
}

func checkFuzzResult(t *testing.T, reg *Registry, spec *Spec, err error, admin, member Actor, doc bool) {
	t.Helper()
	if err != nil {
		if _, ok := AsError(err); !ok {
			t.Fatalf("error is not *Error: %v", err)
		}
		if spec != nil {
			t.Fatal("spec returned with an error")
		}
		return
	}
	leaves := spec.Leaves()
	if len(leaves) > MaxLeaves {
		t.Fatalf("%d leaves", len(leaves))
	}
	if depth(spec.Root) > MaxDepth+1 {
		t.Fatalf("depth %d", depth(spec.Root))
	}
	for _, l := range leaves {
		f, ok := reg.Field(l.Field)
		if !ok || !f.allows(l.Op) {
			t.Fatalf("leaf on unknown field/op %s %s", l.Field, l.Op)
		}
		limit := f.MaxValues
		if doc {
			limit = f.MaxValuesDocument
		}
		if len(l.Values) == 0 || len(l.Values) > limit {
			t.Fatalf("%s: %d values", l.Field, len(l.Values))
		}
	}
	if len(spec.Q) > MaxQLen*4 {
		t.Fatalf("q length %d", len(spec.Q))
	}
	for _, a := range []Actor{admin, member} {
		w, cerr := Compile(spec, reg, a)
		if cerr != nil {
			if _, ok := AsError(cerr); !ok {
				t.Fatalf("compile error is not *Error: %v", cerr)
			}
			continue
		}
		if !strings.HasPrefix(w.SQL, reg.TenantSQL+" = $1") {
			t.Fatalf("tenant predicate missing: %s", w.SQL)
		}
		if a.Restricted() && !strings.Contains(w.SQL, "user_accessible_assets") {
			t.Fatalf("scope predicate missing: %s", w.SQL)
		}
		assertPlaceholders(t, w, 1)
		assertValueIndependent(t, reg, spec, a, w)
	}
}

// assertValueIndependent is the injection invariant: the SQL text depends
// only on the filter's structure. Replacing every request value with a
// constant must yield byte-identical SQL, so no value can be in the text.
func assertValueIndependent(t *testing.T, reg *Registry, spec *Spec, a Actor, w *Where) {
	t.Helper()
	cp := *spec
	cp.Root = blankValues(spec.Root)
	if cp.Q != "" {
		cp.Q = "q"
	}
	w2, err := Compile(&cp, reg, a)
	if err != nil {
		t.Fatalf("blanked spec failed to compile: %v", err)
	}
	if w2.SQL != w.SQL || len(w2.Args) != len(w.Args) {
		t.Fatalf("SQL depends on request values:\n%s\n%s", w.SQL, w2.SQL)
	}
}

func blankValues(n *Node) *Node {
	if n == nil {
		return nil
	}
	out := &Node{Not: blankValues(n.Not)}
	if n.Leaf != nil {
		l := *n.Leaf
		l.Values = make([]any, len(n.Leaf.Values))
		for i, v := range n.Leaf.Values {
			if _, ok := v.(string); ok {
				v = "v"
			}
			l.Values[i] = v
		}
		out.Leaf = &l
	}
	if n.All != nil {
		out.All = make([]*Node, 0, len(n.All))
		for _, c := range n.All {
			out.All = append(out.All, blankValues(c))
		}
	}
	if n.Any != nil {
		out.Any = make([]*Node, 0, len(n.Any))
		for _, c := range n.Any {
			out.Any = append(out.Any, blankValues(c))
		}
	}
	return out
}

func depth(n *Node) int {
	if n == nil || n.Leaf != nil {
		return 0
	}
	d := 0
	if n.Not != nil {
		d = depth(n.Not)
	}
	for _, c := range append(append([]*Node{}, n.All...), n.Any...) {
		d = max(d, depth(c))
	}
	return d + 1
}
