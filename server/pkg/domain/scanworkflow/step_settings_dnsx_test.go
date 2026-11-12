package scanworkflow

import (
	"errors"
	"slices"
	"testing"
)

// dnsx's settings are checked when a step is saved, as the sensor checks
// them: known record types, a boolean wildcard filter.
func TestNormalizeStepConfig_DNSX(t *testing.T) {
	got, err := NormalizeStepConfig("dnsx", map[string]any{"record_types": "A, aaaa,a", "wildcard_filter": true})
	if err != nil {
		t.Fatal(err)
	}
	if rt, _ := got["record_types"].([]string); !slices.Equal(rt, []string{"a", "aaaa"}) || got["wildcard_filter"] != true {
		t.Fatalf("config = %v", got)
	}
	for _, bad := range []map[string]any{
		{"record_types": "axfr"},
		{"record_types": ""},
		{"wildcard_filter": "yes"},
	} {
		if _, err := NormalizeStepConfig("dnsx", bad); !errors.Is(err, ErrInvalidStepSetting) {
			t.Errorf("%v: err = %v", bad, err)
		}
	}
}
