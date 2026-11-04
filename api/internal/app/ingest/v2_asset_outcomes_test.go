package ingest

import (
	"testing"

	"github.com/openctemio/ctis/v2"

	"github.com/openctemio/openctem/api/pkg/domain/ingestreport"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
)

// An asset a scope exclusion kept out is neither accepted nor rejected, and
// a complete collector report that carries one still counts as complete:
// otherwise one excluded asset stops the source's not-seen sweep for good.
func TestAssetOutcomes_ExcludedIsNotRejected(t *testing.T) {
	stored, other := shared.NewID(), shared.NewID()
	assets := []ctis.Asset{{ID: "a"}, {ID: "excl"}, {ID: "bad"}, {ID: "dup"}}
	o := &ingestreport.SegmentOutcome{}
	touched := assetOutcomes(o, assets, []int{0, 1, 2, 3},
		map[string]shared.ID{"a": stored, "dup": stored, "bad": {}, "unused": other},
		map[string]bool{"excl": true})

	if o.AcceptedAssets != 2 || o.RejectedAssets != 1 {
		t.Fatalf("accepted=%d rejected=%d, want 2 and 1 (the excluded asset is neither)", o.AcceptedAssets, o.RejectedAssets)
	}
	if len(touched) != 1 || touched[0] != stored {
		t.Fatalf("touched = %v, want the one stored asset once", touched)
	}
	codes := map[string]string{}
	for _, e := range o.Errors {
		codes[e.Pointer] = e.Code
	}
	if codes["/assets/1"] != protov2.CodeAssetExcluded || codes["/assets/2"] != protov2.CodeAssetInvalid {
		t.Fatalf("item errors = %v, want asset_excluded for the excluded one and asset_invalid for the unusable one", codes)
	}

	// Only the excluded asset was not stored: the report did not lose any.
	clean := &ingestreport.SegmentOutcome{}
	assetOutcomes(clean, assets[:2], []int{0, 1}, map[string]shared.ID{"a": stored}, map[string]bool{"excl": true})
	rep := &ingestreport.Report{SegmentsReceived: 1, Outcomes: map[int]ingestreport.SegmentOutcome{0: *clean}}
	if reportLostAssets(rep) {
		t.Fatal("a report whose only unstored asset was excluded counts as having lost assets")
	}
}

// Without the exclusion, the same unstored asset is rejected and the sweep
// stays off: the guard against a source that lost part of its listing.
func TestAssetOutcomes_UnstoredWithoutExclusionIsRejected(t *testing.T) {
	o := &ingestreport.SegmentOutcome{}
	assetOutcomes(o, []ctis.Asset{{ID: "a"}, {ID: "b"}}, []int{0, 1}, map[string]shared.ID{"a": shared.NewID()}, nil)
	rep := &ingestreport.Report{SegmentsReceived: 1, Outcomes: map[int]ingestreport.SegmentOutcome{0: *o}}
	if o.RejectedAssets != 1 || !reportLostAssets(rep) {
		t.Fatalf("rejected=%d lost=%v, want 1 and true", o.RejectedAssets, reportLostAssets(rep))
	}
}
