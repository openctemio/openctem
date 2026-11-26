package threatalert

import (
	"math"
	"testing"
	"time"

	"github.com/openctemio/openctem/server/pkg/domain/advisory"
)

// Every score Score produces is explained by its own parts: the parts,
// times the confidence, rounded and capped at 100, give the total.
func TestScoreTotalIsWhatItsPartsGive(t *testing.T) {
	now := time.Date(2026, 11, 26, 8, 0, 0, 0, time.UTC)
	fresh, old := now.Add(-time.Hour), now.Add(-10*24*time.Hour)
	epssLow, epssHigh := 0.2, 0.9
	vulns := []Vuln{
		{},
		{Severity: "critical", InKEV: true, KEVRansomware: true, CVSSVector: "AV:N/AC:L/PR:N/UI:N", LastEventAt: &fresh},
		{Severity: "high", EPSS: &epssLow, LastEventAt: &old},
		{Severity: "medium", EPSS: &epssHigh},
		{Severity: "low", Exploitation: advisory.ExploitWeaponised, LastEventAt: &fresh},
	}
	kinds := []MatchKind{MatchConfirmed, MatchLikely, MatchPossible}
	for vi, v := range vulns {
		for _, kind := range kinds {
			for _, inet := range []bool{false, true} {
				for _, crit := range []string{"", "high", "critical"} {
					assets := []Asset{{Kind: kind, InternetFacing: inet, Criticality: crit}}
					b, _ := Score(v, assets, now)
					want := min(100, int(math.Round(float64(b.Exploitation+b.Severity+b.Exposure+b.Freshness)*b.Confidence)))
					if b.Total != want || !b.Explains(b.Total) {
						t.Fatalf("vuln %d %s inet=%v crit=%q: total %d, parts give %d (%+v)", vi, kind, inet, crit, b.Total, want, b)
					}
				}
			}
		}
	}
}

func TestBreakdownExplains(t *testing.T) {
	good := Breakdown{Exploitation: 40, Severity: 20, Exposure: 20, Freshness: 10, Confidence: 1, Total: 90}
	if !good.Explains(90) {
		t.Fatal("a breakdown whose parts give the score must explain it")
	}
	scaled := Breakdown{Exploitation: 40, Severity: 20, Exposure: 20, Freshness: 10, Confidence: 0.5, Total: 45}
	if !scaled.Explains(45) {
		t.Fatal("the confidence multiplier is part of the explanation")
	}
	capped := Breakdown{Exploitation: 45, Severity: 25, Exposure: 30, Freshness: 10, Confidence: 1, Total: 100}
	if !capped.Explains(100) {
		t.Fatal("110 points cap at 100")
	}
	cases := map[string]struct {
		b   Breakdown
		ets int
	}{
		// The case the UI showed: score 87, every part 0 (a row written
		// with the score but no parts).
		"never recorded":       {Breakdown{}, 87},
		"total is not the ets": {good, 87},
		"parts do not add up":  {Breakdown{Exploitation: 10, Confidence: 1, Total: 87}, 87},
		"confidence above one": {Breakdown{Exploitation: 40, Severity: 20, Exposure: 20, Freshness: 10, Confidence: 2, Total: 100}, 100},
		"negative part":        {Breakdown{Exploitation: 97, Severity: -10, Confidence: 1, Total: 87}, 87},
		"zero score, no parts": {Breakdown{}, 0},
	}
	for name, c := range cases {
		if c.b.Explains(c.ets) {
			t.Fatalf("%s: %+v must not explain %d", name, c.b, c.ets)
		}
	}
}

func TestScorePartsAndActionFor(t *testing.T) {
	a := Alert{ETS: 87, Tier: TierConfirmed}
	if _, ok := a.ScoreParts(); ok {
		t.Fatal("an empty breakdown is not the parts of 87")
	}
	// The advice follows the evidence even without recorded parts: a KEV
	// vulnerability on a confirmed asset is patch now.
	if got := ActionFor(&a, Vuln{InKEV: true}); got != ActionPatchNow {
		t.Fatalf("no parts, KEV: %s", got)
	}
	if got := ActionFor(&a, Vuln{}); got != ActionPatchWithinSLA {
		t.Fatalf("no parts, no exploit: %s", got)
	}
	a.ETS = 90
	a.Breakdown = Breakdown{Exploitation: 40, Severity: 20, Exposure: 20, Freshness: 10, Confidence: 1, Total: 90}
	if b, ok := a.ScoreParts(); !ok || b.Total != a.ETS {
		t.Fatalf("recorded parts: %+v %v", b, ok)
	}
	if got := ActionFor(&a, Vuln{}); got != ActionPatchNow {
		t.Fatalf("recorded parts decide: %s", got)
	}
}
