package ingest

import (
	"context"
	"strconv"
	"strings"
	"testing"

	"github.com/openctemio/ctis/v2"

	"github.com/openctemio/openctem/server/pkg/domain/ingestreceipt"
	"github.com/openctemio/openctem/server/pkg/domain/sensor"
	"github.com/openctemio/openctem/server/pkg/domain/sensorresult"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// Findings the binding held are booked on the receipt item log as
// quarantined (held_for_review), or rejected (quarantine_full) when the
// quarantine could not keep them; findings refused before ingest come first.
func TestAddRefusedItems_HeldAndRefusedAreBooked(t *testing.T) {
	s := &Service{logger: logger.NewNop(), results: &policyResults{mode: sensorresult.ModeQuarantine}}
	sent := dnsxReport()
	_, held, _, holds := s.bindOutputTypesHolds(context.Background(), &sensor.Sensor{ID: shared.NewID()}, shared.NewID(),
		boundCommand("dnsx"), sent, Options{Route: "ctis"})
	if held == 0 || holds == nil {
		t.Fatalf("fixture holds nothing: held %d", held)
	}
	refused := []ingestreceipt.Item{{Key: "k-refused", Disposition: ingestreceipt.DispositionRejected, ReasonCode: ingestreceipt.ReasonUnresolvedRef}}
	out := &Output{}
	addRefusedItems(out, sent, holds, refused)
	if len(out.Items) != 1+held {
		t.Fatalf("items %d, want %d", len(out.Items), 1+held)
	}
	if out.Items[0].Key != "k-refused" {
		t.Fatalf("refused item not first: %+v", out.Items[0])
	}
	for _, it := range out.Items[1:] {
		if it.Disposition != ingestreceipt.DispositionQuarantined || it.ReasonCode != ingestreceipt.ReasonHeldForReview ||
			it.Policy != ingestreceipt.PolicyBinding || it.Key == "" || it.Tool != "dnsx" {
			t.Fatalf("held item %+v", it)
		}
	}

	lost := *holds
	lost.lost = true
	out = &Output{}
	addRefusedItems(out, sent, &lost, nil)
	if len(out.Items) != held || out.Items[0].Disposition != ingestreceipt.DispositionRejected ||
		out.Items[0].ReasonCode != ingestreceipt.ReasonQuarantineFull {
		t.Fatalf("lost hold items %+v", out.Items)
	}

	// Nothing held, nothing refused: nothing booked.
	out = &Output{}
	addRefusedItems(out, sent, nil, nil)
	if len(out.Items) != 0 {
		t.Fatalf("items %+v", out.Items)
	}
}

// A protocol v2 finding that names no asset of its segment becomes a
// rejected item (unresolved_ref); the kept ones do not.
func TestRefusedV2Items_UnresolvedRefs(t *testing.T) {
	r := &ctis.Report{Tool: &ctis.Tool{Name: "nuclei"}, Assets: []ctis.Asset{{ID: "a"}, {ID: "b"}},
		Findings: []ctis.Finding{{AssetRef: "a", RuleID: "ok"}, {AssetRef: "elsewhere", RuleID: "gone", Title: "t"}, {RuleID: "ambiguous"}}}
	kept, keptIdx, _, _ := resolveV2Assets(r)
	if len(kept) != 1 {
		t.Fatalf("kept %d", len(kept))
	}
	items := refusedV2Items(r, keptIdx)
	if len(items) != 2 {
		t.Fatalf("items %+v", items)
	}
	for _, it := range items {
		if it.Disposition != ingestreceipt.DispositionRejected || it.ReasonCode != ingestreceipt.ReasonUnresolvedRef ||
			it.Tool != "nuclei" || it.Key == "" {
			t.Fatalf("item %+v", it)
		}
	}
	if refusedV2Items(r, []int{0, 1, 2}) != nil {
		t.Fatal("all kept: items booked")
	}
}

// A refused finding never reaches Ingest, where reports are masked. Its
// receipt item is read with findings:read alone (no reveal gate), so the
// title must not carry a secret scanner's raw match or a full e-mail address,
// and the item key must not be a hash of the raw text.
func TestRefusedV2Items_TitlesAreMasked(t *testing.T) {
	secret := "AKIA" + "QX7RZT4MWV8NP3YB"
	const address = "jane@example.com"
	report := func() *ctis.Report {
		return &ctis.Report{Tool: &ctis.Tool{Name: "betterleaks"}, Assets: []ctis.Asset{{ID: "a"}, {ID: "b"}},
			Findings: []ctis.Finding{
				// No asset_ref in a segment of two assets: ambiguous, refused.
				{Type: ctis.FindingTypeSecret, RuleID: "aws-access-key", Title: "AWS key " + secret + " of " + address,
					Location: &ctis.FindingLocation{Path: "deploy/.env", StartLine: 3, Snippet: "AWS_ACCESS_KEY_ID=" + secret}},
				// Typed generically by a converter: a secret by its tool. Dangling asset_ref.
				{Type: ctis.FindingTypeVulnerability, AssetRef: "elsewhere", RuleID: "generic", Title: "found " + secret,
					Location: &ctis.FindingLocation{Snippet: secret}},
				// An address alone, in a finding that carries no secret.
				{Type: ctis.FindingTypeSecret, AssetRef: "elsewhere", RuleID: "contact", Title: "contact " + address},
				{AssetRef: "a", RuleID: "kept", Title: "kept"},
			}}
	}
	r := report()
	_, keptIdx, _, _ := resolveV2Assets(r)
	items := refusedV2Items(r, keptIdx)
	if len(items) != 3 {
		t.Fatalf("items %+v", items)
	}
	raw := report()
	for i, it := range items {
		if strings.Contains(it.Title, secret) || strings.Contains(it.Title, address) || strings.Contains(it.Title, "jane") {
			t.Errorf("item %d title %q holds the raw secret or the address", i, it.Title)
		}
		if it.Title == "" || it.Disposition != ingestreceipt.DispositionRejected || it.ReasonCode != ingestreceipt.ReasonUnresolvedRef {
			t.Errorf("item %d %+v", i, it)
		}
		f := raw.Findings[i]
		path, line := "", 0
		if f.Location != nil {
			path, line = f.Location.Path, f.Location.StartLine
		}
		if it.Key == ingestreceipt.ItemKey("betterleaks", f.RuleID, f.Title, f.AssetRef, "", path, strconv.Itoa(line)) {
			t.Errorf("item %d key is the hash of the raw title", i)
		}
	}
	if !strings.Contains(items[2].Title, "@example.com") {
		t.Errorf("the address keeps its domain: %q", items[2].Title)
	}
}
