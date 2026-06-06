package ingest

import (
	"sort"
	"testing"
)

func TestPartitionByBaseline(t *testing.T) {
	tests := []struct {
		name       string
		fps        []string
		openOnBase []string
		wantNew    []string
		wantPre    []string
	}{
		{
			name: "all new when base empty",
			fps:  []string{"a", "b", "c"}, openOnBase: nil,
			wantNew: []string{"a", "b", "c"}, wantPre: []string{},
		},
		{
			name: "pre-existing on base are suppressed",
			fps:  []string{"a", "b", "c"}, openOnBase: []string{"b"},
			wantNew: []string{"a", "c"}, wantPre: []string{"b"},
		},
		{
			name: "all pre-existing",
			fps:  []string{"a", "b"}, openOnBase: []string{"a", "b", "z"},
			wantNew: []string{}, wantPre: []string{"a", "b"},
		},
		{
			name: "empty input",
			fps:  nil, openOnBase: []string{"a"},
			wantNew: []string{}, wantPre: []string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotNew, gotPre := partitionByBaseline(tt.fps, tt.openOnBase)
			sort.Strings(gotNew)
			sort.Strings(gotPre)
			if !equalStrings(gotNew, tt.wantNew) {
				t.Errorf("new = %v, want %v", gotNew, tt.wantNew)
			}
			if !equalStrings(gotPre, tt.wantPre) {
				t.Errorf("pre-existing = %v, want %v", gotPre, tt.wantPre)
			}
		})
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
