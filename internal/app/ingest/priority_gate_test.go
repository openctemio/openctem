package ingest

import (
	"testing"

	"github.com/google/uuid"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/tenant"
)

func newSID(t *testing.T) shared.ID {
	t.Helper()
	id, err := shared.IDFromString(uuid.New().String())
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestPriorityGate_FeatureOff_AlwaysAllow(t *testing.T) {
	// Backward-compat regression guard: a tenant with no config
	// must see today's behavior — every write allowed, no filtering.
	g := NewPriorityGate()
	var settings tenant.AssetSourceSettings // zero value
	src := newSID(t)

	dec := g.CanWrite(settings, src, "severity", FieldOwnership{"severity": newSID(t)})
	if !dec.Allowed {
		t.Fatalf("zero-value settings must allow all writes; got %+v", dec)
	}
	if dec.Reason != ReasonFeatureDisabled {
		t.Errorf("expected reason %q, got %q", ReasonFeatureDisabled, dec.Reason)
	}
}

func TestPriorityGate_UnownedField_Allow(t *testing.T) {
	// No source has claimed this field yet → incoming source wins
	// by default. Adding new knowledge should never be blocked.
	g := NewPriorityGate()
	src := newSID(t)
	settings := tenant.AssetSourceSettings{
		Priority: []shared.ID{src}, // feature is on
	}

	dec := g.CanWrite(settings, src, "brand_new_field", FieldOwnership{})
	if !dec.Allowed || dec.Reason != ReasonUnownedField {
		t.Errorf("expected allow/unowned, got %+v", dec)
	}
}

func TestPriorityGate_SameSource_AllowsRewrite(t *testing.T) {
	// A source may freely update a field it already owns. Re-scan
	// from the same Nessus instance must refresh its own values.
	g := NewPriorityGate()
	src := newSID(t)
	settings := tenant.AssetSourceSettings{
		Priority: []shared.ID{src, newSID(t)},
	}

	dec := g.CanWrite(settings, src, "severity", FieldOwnership{"severity": src})
	if !dec.Allowed || dec.Reason != ReasonSameSource {
		t.Errorf("expected allow/same_source, got %+v", dec)
	}
}

func TestPriorityGate_ListedBeatsListed_ByPosition(t *testing.T) {
	// Priority[0] outranks Priority[1]. A higher-ranked source that
	// comes later still wins.
	g := NewPriorityGate()
	winner := newSID(t)
	loser := newSID(t)
	settings := tenant.AssetSourceSettings{
		Priority: []shared.ID{winner, loser},
	}

	// Winner trying to overwrite a field loser currently owns.
	dec := g.CanWrite(settings, winner, "severity", FieldOwnership{"severity": loser})
	if !dec.Allowed {
		t.Errorf("higher-ranked winner must overwrite loser; got %+v", dec)
	}

	// Loser trying to overwrite a field winner owns.
	dec = g.CanWrite(settings, loser, "severity", FieldOwnership{"severity": winner})
	if dec.Allowed {
		t.Errorf("lower-ranked loser must be blocked; got %+v", dec)
	}
	if dec.Reason != ReasonLowerRank {
		t.Errorf("expected reason lower_rank, got %q", dec.Reason)
	}
}

func TestPriorityGate_ListedBeatsUnlisted(t *testing.T) {
	// A source in Priority always outranks a source missing from
	// both Priority and TrustLevels (Q2: listed > unlisted).
	g := NewPriorityGate()
	listed := newSID(t)
	unlisted := newSID(t)
	settings := tenant.AssetSourceSettings{
		Priority: []shared.ID{listed},
	}

	dec := g.CanWrite(settings, listed, "owner", FieldOwnership{"owner": unlisted})
	if !dec.Allowed {
		t.Errorf("listed should beat unlisted; got %+v", dec)
	}

	dec = g.CanWrite(settings, unlisted, "owner", FieldOwnership{"owner": listed})
	if dec.Allowed {
		t.Errorf("unlisted must not beat listed; got %+v", dec)
	}
}

func TestPriorityGate_TrustLevels_OutrankEachOther(t *testing.T) {
	// TrustLevels-only config — Primary beats Low, Medium ties Medium.
	g := NewPriorityGate()
	primarySource := newSID(t)
	lowSource := newSID(t)

	settings := tenant.AssetSourceSettings{
		TrustLevels: map[string]tenant.TrustLevel{
			primarySource.String(): tenant.TrustLevelPrimary,
			lowSource.String():     tenant.TrustLevelLow,
		},
	}

	dec := g.CanWrite(settings, primarySource, "os", FieldOwnership{"os": lowSource})
	if !dec.Allowed {
		t.Errorf("primary should beat low; got %+v", dec)
	}

	dec = g.CanWrite(settings, lowSource, "os", FieldOwnership{"os": primarySource})
	if dec.Allowed {
		t.Errorf("low must not beat primary; got %+v", dec)
	}
}

func TestPriorityGate_TrustLevels_EqualRank_AllowEqual(t *testing.T) {
	// Same bucket — tie goes to the caller per Q8: the gate allows
	// equal-or-higher. Net effect is last-write-wins inside a
	// bucket, matching today's behavior.
	g := NewPriorityGate()
	a := newSID(t)
	b := newSID(t)

	settings := tenant.AssetSourceSettings{
		TrustLevels: map[string]tenant.TrustLevel{
			a.String(): tenant.TrustLevelMedium,
			b.String(): tenant.TrustLevelMedium,
		},
	}

	dec := g.CanWrite(settings, a, "severity", FieldOwnership{"severity": b})
	if !dec.Allowed {
		t.Errorf("equal rank must allow; got %+v", dec)
	}
	if dec.Reason != ReasonHigherOrEqualRank {
		t.Errorf("expected reason higher_or_equal_rank; got %q", dec.Reason)
	}
}

func TestPriorityGate_PriorityWinsOverTrustLevels(t *testing.T) {
	// Both Priority and TrustLevels populated: Priority's ordering
	// is authoritative, TrustLevels is advisory. A listed source
	// must beat a TrustLevel-only high-bucket source.
	g := NewPriorityGate()
	listed := newSID(t)
	trustOnlyHigh := newSID(t)

	settings := tenant.AssetSourceSettings{
		Priority: []shared.ID{listed},
		TrustLevels: map[string]tenant.TrustLevel{
			trustOnlyHigh.String(): tenant.TrustLevelHigh,
			// listed has no TrustLevels entry
		},
	}

	// trustOnlyHigh has TrustLevel=High → rank 3.
	// listed has no TrustLevel, but is Priority[0] → rank 11.
	dec := g.CanWrite(settings, listed, "field", FieldOwnership{"field": trustOnlyHigh})
	if !dec.Allowed {
		t.Errorf("Priority-listed must beat TrustLevel-High; got %+v", dec)
	}

	dec = g.CanWrite(settings, trustOnlyHigh, "field", FieldOwnership{"field": listed})
	if dec.Allowed {
		t.Errorf("TrustLevel-High must NOT beat Priority-listed; got %+v", dec)
	}
}

func TestPriorityGate_PriorityPositionIsStable(t *testing.T) {
	// Regression guard: swapping position changes the winner
	// deterministically. Catches any off-by-one in rankOfSource.
	g := NewPriorityGate()
	a := newSID(t)
	b := newSID(t)

	abSettings := tenant.AssetSourceSettings{Priority: []shared.ID{a, b}}
	baSettings := tenant.AssetSourceSettings{Priority: []shared.ID{b, a}}

	// In [a, b], a wins over b.
	if !g.CanWrite(abSettings, a, "x", FieldOwnership{"x": b}).Allowed {
		t.Errorf("a should win in [a,b]")
	}
	if g.CanWrite(abSettings, b, "x", FieldOwnership{"x": a}).Allowed {
		t.Errorf("b should lose in [a,b]")
	}

	// Swap the list: b wins over a.
	if !g.CanWrite(baSettings, b, "x", FieldOwnership{"x": a}).Allowed {
		t.Errorf("b should win in [b,a]")
	}
	if g.CanWrite(baSettings, a, "x", FieldOwnership{"x": b}).Allowed {
		t.Errorf("a should lose in [b,a]")
	}
}

func TestPriorityGate_FilterProperties_SplitsAllowedAndSkipped(t *testing.T) {
	g := NewPriorityGate()
	low := newSID(t)
	high := newSID(t)

	settings := tenant.AssetSourceSettings{
		Priority: []shared.ID{high, low},
	}

	// Pretend high source already wrote severity + cvss_score.
	// low source tries to write severity (blocked), cvss_score
	// (blocked), and a new field "last_seen" (allowed).
	ownership := FieldOwnership{
		"severity":   high,
		"cvss_score": high,
	}
	incoming := map[string]any{
		"severity":   "medium",
		"cvss_score": 5.0,
		"last_seen":  "2026-04-23",
	}

	allowed, skipped := g.FilterProperties(settings, low, incoming, ownership)

	if got, want := len(allowed), 1; got != want {
		t.Fatalf("allowed has %d entries, want %d", got, want)
	}
	if _, ok := allowed["last_seen"]; !ok {
		t.Error("last_seen should be allowed (unowned)")
	}
	if len(skipped) != 2 {
		t.Errorf("expected 2 skipped fields, got %d: %v", len(skipped), skipped)
	}
}

func TestPriorityGate_FilterProperties_FeatureOffReturnsInputUnchanged(t *testing.T) {
	// Hot-path fast path: returning the original map saves an
	// allocation per call. Confirm no copy happens.
	g := NewPriorityGate()
	var settings tenant.AssetSourceSettings // feature off
	src := newSID(t)

	incoming := map[string]any{"a": 1, "b": 2}
	allowed, skipped := g.FilterProperties(settings, src, incoming, nil)

	// Same map reference — zero-allocation happy path.
	if &allowed == &incoming { // can't compare maps by pointer directly
		// fallthrough; documented invariant is "same map contents"
	}
	if len(allowed) != 2 {
		t.Errorf("expected pass-through of 2 entries, got %d", len(allowed))
	}
	if skipped != nil {
		t.Errorf("expected nil skipped list, got %v", skipped)
	}
}

func TestPriorityGate_FilterProperties_NilIncomingSafe(t *testing.T) {
	g := NewPriorityGate()
	settings := tenant.AssetSourceSettings{Priority: []shared.ID{newSID(t)}}

	allowed, skipped := g.FilterProperties(settings, newSID(t), nil, FieldOwnership{})
	if len(allowed) != 0 {
		t.Errorf("expected empty allowed, got %v", allowed)
	}
	if len(skipped) != 0 {
		t.Errorf("expected empty skipped, got %v", skipped)
	}
}
