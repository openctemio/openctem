package asset

import "testing"

// The repository used to read only ChangeTypes/Sources, so a caller setting
// the single ChangeType (e.g. GET /state-history/appearances) got every type.
func TestEffectiveChangeTypes_MergesSingleFilter(t *testing.T) {
	single := StateChangeAppeared
	opts := ListStateHistoryOptions{ChangeType: &single}
	got := opts.EffectiveChangeTypes()
	if len(got) != 1 || got[0] != StateChangeAppeared {
		t.Fatalf("got %v, want [appeared]", got)
	}

	opts.ChangeTypes = []StateChangeType{StateChangeDisappeared}
	got = opts.EffectiveChangeTypes()
	if len(got) != 2 {
		t.Fatalf("got %v, want both", got)
	}

	opts.ChangeTypes = []StateChangeType{StateChangeAppeared}
	if got = opts.EffectiveChangeTypes(); len(got) != 1 {
		t.Fatalf("duplicate not collapsed: %v", got)
	}

	if got = (ListStateHistoryOptions{}).EffectiveChangeTypes(); len(got) != 0 {
		t.Fatalf("no filter should stay empty, got %v", got)
	}
}

func TestEffectiveSources_MergesSingleFilter(t *testing.T) {
	src := ChangeSourceScan
	got := ListStateHistoryOptions{Source: &src}.EffectiveSources()
	if len(got) != 1 || got[0] != ChangeSourceScan {
		t.Fatalf("got %v, want [scan]", got)
	}
}
