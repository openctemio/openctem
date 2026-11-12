package compliance

import "testing"

func TestParseImpactType(t *testing.T) {
	valid := []string{"direct", "indirect", "informational"}
	for _, v := range valid {
		if got, err := ParseImpactType(v); err != nil || string(got) != v {
			t.Errorf("ParseImpactType(%q) = (%q,%v), want (%q,nil)", v, got, err, v)
		}
	}
	for _, bad := range []string{"", "critical", "DIRECT", "x"} {
		if _, err := ParseImpactType(bad); err == nil {
			t.Errorf("ParseImpactType(%q) = nil err, want error", bad)
		}
	}
}
