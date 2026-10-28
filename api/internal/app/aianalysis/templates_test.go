package aianalysis

import (
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/sensorproto/analyze"
)

// Every single-shot kind has a built-in template whose digest is stable and
// names the placeholder and untrusted-data rules.
func TestTemplatesForEveryKind(t *testing.T) {
	for _, k := range analyze.Kinds() {
		a, err := TemplateFor(k.Name)
		if err != nil {
			t.Fatalf("%s: %v", k.Name, err)
		}
		b, _ := TemplateFor(k.Name)
		if a.Digest != b.Digest || !strings.HasPrefix(a.Digest, "sha256:") || a.ID != k.Name {
			t.Fatalf("%s: unstable or malformed template %+v", k.Name, a)
		}
		for _, must := range []string{"untrusted", "Placeholders are opaque", "one JSON object"} {
			if !strings.Contains(a.Text, must) {
				t.Fatalf("%s: template lacks %q", k.Name, must)
			}
		}
	}
	if _, err := TemplateFor("../common"); err == nil {
		t.Fatal("a path must not resolve to a template")
	}
}
