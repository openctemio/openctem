package filterspec

import (
	"encoding/json"
	"net/url"
	"testing"
)

func TestParamsDocument(t *testing.T) {
	reg := testRegistry(t)
	q, _ := url.ParseQuery("severities=critical,high&last_seen_at_gt=-P7D&is_in_kev=true&q=log4j&page=2&file_path=src/main&assigned_to_null=true")
	doc, err := ParamsDocument(q, reg, Options{Unknown: UnknownStrict})
	if err != nil {
		t.Fatal(err)
	}
	got, _ := json.Marshal(doc)
	want := `{"filter":{"all":[{"field":"assigned_to","op":"is_null","value":true},{"field":"file_path","op":"contains","value":"src/main"},{"field":"is_in_kev","op":"eq","value":true},{"field":"last_seen_at","op":"gt","value":"-P7D"},{"field":"severity","op":"in","value":["critical","high"]}]},"q":"log4j","v":1}`
	if string(got) != want {
		t.Fatalf("doc = %s\nwant %s", got, want)
	}
	// The document is a valid filter.
	if _, err := ParseDocument(got, reg, Options{Unknown: UnknownStrict}); err != nil {
		t.Fatalf("document does not parse: %v", err)
	}
	if _, err := ParamsDocument(url.Values{"severity": {"bogus"}}, reg, Options{Unknown: UnknownStrict}); err == nil {
		t.Fatal("bad params accepted")
	}
}

func TestLeafParam(t *testing.T) {
	reg := testRegistry(t)
	cases := []struct {
		field string
		op    Op
		vals  []string
		name  string
		value string
		ok    bool
	}{
		{"severity", OpIn, []string{"critical", "high"}, "severity", "critical,high", true},
		{"severity", OpNotIn, []string{"info"}, "severity_not", "info", true},
		{"last_seen_at", OpGt, []string{"-P7D"}, "last_seen_at_gt", "-P7D", true},
		{"is_in_kev", OpEq, []string{"true"}, "is_in_kev", "true", true},
		{"file_path", OpContains, []string{"a,b"}, "file_path_contains", "a,b", true},
		{"assigned_to", OpIsNull, []string{"true"}, "assigned_to_null", "true", true},
		{"rule_id", OpIn, []string{"a,b"}, "", "", false},
		{"pentest_note", OpGte, []string{"x"}, "", "", false},
		{"nope", OpIn, []string{"x"}, "", "", false},
	}
	for _, c := range cases {
		n, v, ok := reg.LeafParam(c.field, c.op, c.vals)
		if n != c.name || v != c.value || ok != c.ok {
			t.Errorf("%s %s %v = %q %q %v", c.field, c.op, c.vals, n, v, ok)
		}
		if ok {
			// The flat param reads back as the same leaf.
			spec, err := ParseValues(url.Values{n: {v}}, reg, Options{Unknown: UnknownStrict})
			if err != nil || spec.Root.All[0].Leaf.Field != c.field || spec.Root.All[0].Leaf.Op != c.op {
				t.Errorf("%s=%s reads back as %+v, %v", n, v, spec, err)
			}
		}
	}
}
