package ingest

import (
	"context"
	"strings"
	"testing"

	"github.com/openctemio/ctis/v2"

	"github.com/openctemio/openctem/api/pkg/domain/ingestreport"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/sensorresult"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
)

// An unstored asset names its reason. Held for review is quarantined, not
// rejected; outside the targets, outside the addresses and outside the
// actor's scope are rejected with their own codes; only an asset with no
// recorded reason is asset_invalid.
func TestAssetOutcomes_EveryUnstoredAssetSaysWhy(t *testing.T) {
	stored := shared.NewID()
	assets := []ctis.Asset{{ID: "ok"}, {ID: "held"}, {ID: "job"}, {ID: "chunk"}, {ID: "scope"}, {ID: "excl"}, {ID: "bad"}}
	why := notStoredReasons{
		held:         map[string]bool{"held": true},
		outsideJob:   map[string]bool{"job": true},
		outsideChunk: map[string]bool{"chunk": true},
		outOfScope:   map[string]bool{"chunk": true, "scope": true},
		excluded:     map[string]bool{"excl": true},
	}
	o := &ingestreport.SegmentOutcome{}
	assetOutcomesWhy(o, assets, []int{0, 1, 2, 3, 4, 5, 6}, map[string]shared.ID{"ok": stored}, why)
	if o.AcceptedAssets != 1 || o.QuarantinedAssets != 1 || o.RejectedAssets != 4 {
		t.Fatalf("accepted=%d quarantined=%d rejected=%d, want 1, 1, 4", o.AcceptedAssets, o.QuarantinedAssets, o.RejectedAssets)
	}
	want := map[string]string{
		"/assets/1": protov2.CodeHeldForReview,
		"/assets/2": protov2.CodeOutsideTargets,
		"/assets/3": protov2.CodeOutsideTargets,
		"/assets/4": protov2.CodeOutOfScope,
		"/assets/5": protov2.CodeAssetExcluded,
		"/assets/6": protov2.CodeAssetInvalid,
	}
	for _, e := range o.Errors {
		if want[e.Pointer] != e.Code {
			t.Errorf("%s: code %s, want %s", e.Pointer, e.Code, want[e.Pointer])
		}
		delete(want, e.Pointer)
	}
	if len(want) != 0 {
		t.Fatalf("missing item errors: %v", want)
	}

	// A quarantine that could not keep the held asset rejects it.
	lost := &ingestreport.SegmentOutcome{}
	why.holdLost = true
	assetOutcomesWhy(lost, assets[1:2], []int{0}, nil, why)
	if lost.RejectedAssets != 1 || lost.QuarantinedAssets != 0 || lost.Errors[0].Code != protov2.CodeQuarantineFull {
		t.Fatalf("lost hold: %+v", lost)
	}
}

// Findings: held ones (by their asset or by their own type) are quarantined
// with held_for_review; one on an asset outside the targets says so; one on
// an unstored asset without a reason stays asset_unresolved.
func TestFindingOutcomes_HeldAndOutsideAreNamed(t *testing.T) {
	stored := shared.NewID()
	kept := []ctis.Finding{
		{AssetRef: "ok"},    // applied
		{AssetRef: "held"},  // its asset was held
		{AssetRef: "ok"},    // held by its own type (index 2)
		{AssetRef: "job"},   // asset outside the job
		{AssetRef: "gone"},  // asset not stored, no reason
		{AssetRef: "scope"}, // asset outside the actor's scope
	}
	out := &Output{AssetMap: map[string]shared.ID{"ok": stored}}
	why := notStoredReasons{
		held: map[string]bool{"held": true}, heldFindings: map[int]bool{2: true},
		outsideJob: map[string]bool{"job": true}, outOfScope: map[string]bool{"scope": true},
	}
	o := &ingestreport.SegmentOutcome{}
	findingOutcomes(o, kept, []int{0, 1, 2, 3, 4, 5}, out, why)
	if o.AcceptedFindings != 1 || o.QuarantinedFindings != 2 || o.RejectedFindings != 3 {
		t.Fatalf("accepted=%d quarantined=%d rejected=%d, want 1, 2, 3", o.AcceptedFindings, o.QuarantinedFindings, o.RejectedFindings)
	}
	codes := map[string]string{}
	for _, e := range o.Errors {
		codes[strings.TrimSuffix(e.Pointer, "/asset_ref")] = e.Code
	}
	want := map[string]string{
		"/findings/1": protov2.CodeHeldForReview, "/findings/2": protov2.CodeHeldForReview,
		"/findings/3": protov2.CodeOutsideTargets, "/findings/4": protov2.CodeAssetUnresolved,
		"/findings/5": protov2.CodeOutOfScope,
	}
	for p, c := range want {
		if codes[p] != c {
			t.Errorf("%s: code %q, want %q", p, codes[p], c)
		}
	}
	if _, has := codes["/findings/0"]; has {
		t.Error("the applied finding has an item error")
	}
}

// The output-type binding names what it held: the out-of-contract asset,
// the findings on it and a finding of an undeclared type, by their index in
// the report, and whether the quarantine kept them.
func TestBindOutputTypesHolds_NamesTheHeldItems(t *testing.T) {
	s := &Service{logger: logger.NewNop(), results: &policyResults{mode: sensorresult.ModeQuarantine}}
	in := dnsxReport()
	_, held, lost, holds := s.bindOutputTypesHolds(context.Background(), &sensor.Sensor{ID: shared.NewID()}, shared.NewID(), boundCommand("dnsx"), in, Options{Route: "ctis"})
	if holds == nil || holds.lost || lost != 0 {
		t.Fatalf("holds %+v lost %d, want named holds kept by the quarantine", holds, lost)
	}
	if len(holds.findings) != held {
		t.Fatalf("held %d findings, named %d", held, len(holds.findings))
	}
	for i := range in.Findings {
		f := in.Findings[i]
		if f.AssetRef != "" && holds.assetRefs[f.AssetRef] && !holds.findings[i] {
			t.Errorf("finding %d on held asset %q is not named", i, f.AssetRef)
		}
	}
	if !holds.assetRefs["a3"] || holds.assetRefs["a1"] || !holds.findings[1] || holds.findings[0] {
		t.Fatalf("holds %+v, want the planted repository and its finding only", holds)
	}

	full := &Service{logger: logger.NewNop(), results: &fullResults{policyResults{mode: sensorresult.ModeQuarantine}}}
	if _, _, _, h := full.bindOutputTypesHolds(context.Background(), &sensor.Sensor{ID: shared.NewID()}, shared.NewID(), boundCommand("dnsx"), dnsxReport(), Options{}); h == nil || !h.lost {
		t.Fatalf("a full quarantine: holds %+v, want lost", h)
	}
	// Nothing out of contract: nothing named.
	if _, _, _, h := s.bindOutputTypesHolds(context.Background(), &sensor.Sensor{ID: shared.NewID()}, shared.NewID(), Binding{}, dnsxReport(), Options{}); h != nil {
		t.Fatalf("unbound report named holds %+v", h)
	}
}
