package scan

import (
	"slices"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/scanzone"
)

// Every skipped target lands in exactly one group, named by its reason,
// largest group first; names that do not resolve and scope exclusions are
// expected outcomes (info), a zone without sensors asks for a fix.
func TestSkipGroups(t *testing.T) {
	r := &resolvedTargets{
		Excluded:      2,
		ExcludedNames: []string{"x1.example.com", "x2.example.com"},
		OutOfScope:    1,
		SkippedNames:  map[string][]string{SkipOutOfScope: {"other.example.org"}},
		Archived:      4,
	}
	plan := &zonePlan{Uncovered: []scanzone.Uncovered{
		{Target: "gone1.example.com", Kind: scanzone.KindUnresolved},
		{Target: "gone2.example.com", Kind: scanzone.KindUnresolved},
		{Target: "gone3.example.com", Kind: scanzone.KindUnresolved},
		{Target: "10.9.0.1", Kind: scanzone.KindZoneNoSensor},
	}}
	rejected := []rejectedTarget{{Target: "bad target", Reason: "invalid"}, {Target: "not-mine.example.net", ActScope: true}}
	got := skipGroups(maxSkipSamples, rejected, r, []string{"stale.example.com"}, plan)

	want := []struct {
		reason, tone  string
		count, listed int
	}{
		{SkipArchived, SkipToneInfo, 4, 0},
		{scanzone.KindUnresolved, SkipToneInfo, 3, 3},
		{SkipExcluded, SkipToneInfo, 2, 2},
		{SkipOutOfScope, SkipToneWarning, 2, 2},
		{SkipInvalid, SkipToneWarning, 1, 1},
		{SkipNotResolving, SkipToneInfo, 1, 1},
		{scanzone.KindZoneNoSensor, SkipToneWarning, 1, 1},
	}
	if len(got) != len(want) {
		t.Fatalf("groups = %+v", got)
	}
	for i, w := range want {
		g := got[i]
		if g.Reason != w.reason || g.Tone != w.tone || g.Count != w.count || len(g.Targets) != w.listed {
			t.Errorf("group %d = %+v, want %+v", i, g, w)
		}
	}
	if skipTotal(got) != 14 {
		t.Errorf("total = %d, want 14", skipTotal(got))
	}
}

// The names listed per reason are bounded; the count is not. A run record
// keeps fewer names than a preview.
func TestSkipGroups_Bounded(t *testing.T) {
	var uncovered []scanzone.Uncovered
	for i := range 300 {
		uncovered = append(uncovered, scanzone.Uncovered{Target: string(rune('a'+i%26)) + ".example.com", Kind: scanzone.KindUnresolved})
	}
	got := skipGroups(maxSkipSamples, nil, nil, nil, &zonePlan{Uncovered: uncovered})
	if len(got) != 1 || got[0].Count != 300 || len(got[0].Targets) != maxSkipSamples {
		t.Fatalf("groups = %d, count %d, listed %d", len(got), got[0].Count, len(got[0].Targets))
	}
	rc := map[string]any{}
	recordSkipGroups(rc, got)
	stored, _ := rc[RunContextKeySkipped].([]SkipGroup)
	if len(stored) != 1 || stored[0].Count != 300 || len(stored[0].Targets) != maxRunSkipSamples {
		t.Fatalf("stored = %+v", stored)
	}
	if len(got[0].Targets) != maxSkipSamples {
		t.Fatal("recording trimmed the caller's groups")
	}
	recordSkipGroups(rc, nil)
	if g, ok := rc[RunContextKeySkipped].([]SkipGroup); !ok || len(g) != 0 {
		t.Fatalf("nothing skipped = %v, want an empty list", rc[RunContextKeySkipped])
	}
}

// A route without a kind (an older router answer) is still counted, as
// outside the zones; nothing is dropped.
func TestSkipGroups_UnknownKind(t *testing.T) {
	got := skipGroups(maxSkipSamples, nil, nil, nil, &zonePlan{Uncovered: []scanzone.Uncovered{{Target: "10.0.0.1"}}})
	if len(got) != 1 || got[0].Reason != scanzone.KindOutsideZones || !slices.Equal(got[0].Targets, []string{"10.0.0.1"}) {
		t.Fatalf("groups = %+v", got)
	}
}
