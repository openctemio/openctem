package sensor

import (
	"errors"
	"strings"
	"testing"
)

func TestNormalizeCustomProduct(t *testing.T) {
	p, err := NormalizeCustomProduct("  Acme-Scanner ", "1.4.0", "v1.0.0")
	if err != nil || p.Product != "acme-scanner" || p.Latest != "v1.4.0" || p.Min != "v1.0.0" {
		t.Fatalf("p = %+v, err = %v", p, err)
	}
	if p, err := NormalizeCustomProduct("acme", "", ""); err != nil || p.Latest != "" || p.Min != "" {
		t.Fatalf("no versions: %+v %v", p, err)
	}
	if l := (CustomProduct{Latest: "v2.0.0", Min: "v1.0.0"}).Line(); l.Latest != "v2.0.0" || l.Min != "v1.0.0" {
		t.Fatalf("line = %+v", l)
	}
}

// SECURITY: an organization cannot record a first-party product (it would
// change verdicts of a product it does not publish), nor smuggle anything
// that is not a plain token or a release version.
func TestNormalizeCustomProduct_Refusals(t *testing.T) {
	for name, c := range map[string][3]string{
		"first-party name":   {"openctemio-sensor", "v1.0.0", ""},
		"first-party prefix": {"OpenCTEMio-anything", "", ""},
		"empty":              {"", "", ""},
		"space":              {"acme scanner", "", ""},
		"shell":              {"acme;rm -rf", "", ""},
		"too long":           {strings.Repeat("a", 65), "", ""},
		"latest not version": {"acme", "latest", ""},
		"pre-release":        {"acme", "v1.0.0-rc.1", ""},
		"min not version":    {"acme", "", "1.x"},
		"min above latest":   {"acme", "v1.0.0", "v2.0.0"},
		"leading zero":       {"acme", "v01.0.0", ""},
	} {
		if _, err := NormalizeCustomProduct(c[0], c[1], c[2]); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := NormalizeCustomProduct("openctemio-x", "", ""); !errors.Is(err, ErrCustomProductReserved) {
		t.Errorf("reserved: %v", err)
	}
}
