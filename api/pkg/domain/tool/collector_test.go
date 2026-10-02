package tool

import "testing"

func TestToolIsCollector(t *testing.T) {
	cases := []struct {
		name     string
		metadata map[string]any
		want     bool
	}{
		{"scanner without metadata", nil, false},
		{"scanner", map[string]any{"replaces": "gitleaks"}, false},
		{"collector", map[string]any{"kind": "collector"}, true},
		{"other kind", map[string]any{"kind": "scanner"}, false},
		{"non-string kind", map[string]any{"kind": 1}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tl := &Tool{Name: "x", Metadata: tc.metadata}
			if got := tl.IsCollector(); got != tc.want {
				t.Errorf("IsCollector() = %v, want %v", got, tc.want)
			}
		})
	}
}
