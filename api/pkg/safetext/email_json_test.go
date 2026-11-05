package safetext

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// String values are masked at any depth; keys, numbers and other values stay;
// a document without an address comes back as given; a second pass is a
// no-op.
func TestMaskEmailsJSON(t *testing.T) {
	in := `{"jane@example.com": "key stays", "n": 12345678901234567890, "f": 1.5, "b": true, "z": null,
		"nested": {"list": ["Ops@Example.org", "lib@1.2.3", {"q": "u=jane%40example.com"}], "html": "<a>bob@example.net</a>"}}`
	out, changed, err := MaskEmailsJSON([]byte(in))
	if err != nil || !changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"jane@example.com": "key stays", "f": 1.5, "b": true, "z": nil,
		"nested": map[string]any{"list": []any{"***@Example.org", "lib@1.2.3", map[string]any{"q": "u=***%40example.com"}}, "html": "<a>***@example.net</a>"}}
	delete(got, "n")
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %s", out)
	}
	if !strings.Contains(string(out), `"n":12345678901234567890`) {
		t.Errorf("number not kept exactly: %s", out)
	}
	again, changed, err := MaskEmailsJSON(out)
	if err != nil || changed || string(again) != string(out) {
		t.Errorf("second pass changed=%v err=%v", changed, err)
	}
	for _, doc := range []string{`{"a": "lib@1.2.3"}`, `"plain"`, `[1, 2]`, `{"jane@example.com": 1}`} {
		got, changed, err := MaskEmailsJSON([]byte(doc))
		if err != nil || changed || string(got) != doc {
			t.Errorf("%s: changed=%v err=%v got %s", doc, changed, err, got)
		}
	}
	if _, _, err := MaskEmailsJSON([]byte(`{"a": "x@example.com"`)); err == nil {
		t.Error("broken JSON accepted")
	}
}
