package threatalert

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

func f64(v float64) *float64 { return &v }

func TestScoreAndLevel(t *testing.T) {
	now := time.Date(2026, 10, 19, 8, 0, 0, 0, time.UTC)
	fresh := now.Add(-time.Hour)
	old := now.Add(-10 * 24 * time.Hour)
	var defaults tenant.EmergingThreatSettings
	edge := Asset{Kind: MatchConfirmed, InternetFacing: true, Criticality: "high"}
	internal := Asset{Kind: MatchConfirmed, Criticality: "medium"}
	banner := Asset{Kind: MatchPossible, InternetFacing: true}

	cases := []struct {
		name      string
		v         Vuln
		assets    []Asset
		minSev    bool
		wantTotal int
		wantTier  Tier
		wantLevel Level
	}{
		// The RFC's examples.
		{"KEV on internet-facing, confirmed", Vuln{Severity: "critical", InKEV: true, LastEventAt: &fresh},
			[]Asset{edge, edge}, false, 90, TierConfirmed, LevelImmediate},
		{"same CVE, version unknown", Vuln{Severity: "critical", InKEV: true, LastEventAt: &fresh},
			[]Asset{banner}, false, 45, TierPossible, LevelDigest},
		{"critical, no exploit, internal", Vuln{Severity: "critical", LastEventAt: &fresh},
			[]Asset{internal}, false, 30, TierConfirmed, LevelListed},
		{"critical internal, min severity covers it", Vuln{Severity: "critical", LastEventAt: &fresh},
			[]Asset{internal}, true, 30, TierConfirmed, LevelDigest},
		// Never immediate on severity alone.
		{"critical + crown jewel + fresh, no exploitation", Vuln{Severity: "critical", CVSSVector: "AV:N/AC:L/PR:N/UI:N", LastEventAt: &fresh},
			[]Asset{{Kind: MatchConfirmed, InternetFacing: true, Criticality: "critical"}}, false, 65, TierConfirmed, LevelDigest},
		{"EPSS 0.6, internet-facing, old event", Vuln{Severity: "high", EPSS: f64(0.6), LastEventAt: &old},
			[]Asset{edge}, false, 52, TierConfirmed, LevelDigest},
		{"likely only scales by 0.8", Vuln{Severity: "critical", InKEV: true, LastEventAt: &fresh},
			[]Asset{{Kind: MatchLikely, InternetFacing: true}}, false, 72, TierConfirmed, LevelImmediate},
		{"ransomware adds 5", Vuln{Severity: "critical", InKEV: true, KEVRansomware: true, LastEventAt: &fresh},
			[]Asset{edge}, false, 95, TierConfirmed, LevelImmediate},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b, tier := Score(c.v, c.assets, now)
			if b.Total != c.wantTotal || tier != c.wantTier {
				t.Fatalf("score = %+v tier %s, want %d %s", b, tier, c.wantTotal, c.wantTier)
			}
			if got := LevelFor(b, tier, c.v, c.assets, defaults, c.minSev); got != c.wantLevel {
				t.Fatalf("level = %s, want %s", got, c.wantLevel)
			}
		})
	}
}

func TestPossibleOnlyPagesWhenKEVAndInternetFacingOrOptIn(t *testing.T) {
	now := time.Now()
	fresh := now.Add(-time.Hour)
	v := Vuln{Severity: "critical", CVSSVector: "AV:N/PR:N/UI:N", InKEV: true, KEVRansomware: true, LastEventAt: &fresh}
	internalBanner := []Asset{{Kind: MatchPossible, Criticality: "critical"}}
	b := Breakdown{Exploitation: 45, Total: 80}
	if got := LevelFor(b, TierPossible, v, internalBanner, tenant.EmergingThreatSettings{}, false); got != LevelDigest {
		t.Fatalf("internal possibly affected paged: %s", got)
	}
	if got := LevelFor(b, TierPossible, v, internalBanner, tenant.EmergingThreatSettings{IncludePossibleInImmediate: true}, false); got != LevelImmediate {
		t.Fatalf("opt-in did not page: %s", got)
	}
	if got := LevelFor(b, TierPossible, v, []Asset{{Kind: MatchPossible, InternetFacing: true}}, tenant.EmergingThreatSettings{}, false); got != LevelImmediate {
		t.Fatalf("KEV + internet-facing possibly affected did not page: %s", got)
	}
	noKEV := v
	noKEV.InKEV = false
	if got := LevelFor(Breakdown{Exploitation: 20, Total: 80}, TierPossible, noKEV, []Asset{{Kind: MatchPossible, InternetFacing: true}}, tenant.EmergingThreatSettings{}, false); got != LevelDigest {
		t.Fatalf("possibly affected without KEV paged: %s", got)
	}
}

func TestThresholdsAreTunable(t *testing.T) {
	b := Breakdown{Exploitation: 40, Total: 65}
	if got := LevelFor(b, TierConfirmed, Vuln{}, nil, tenant.EmergingThreatSettings{}, false); got != LevelDigest {
		t.Fatalf("65 with the default 70: %s", got)
	}
	if got := LevelFor(b, TierConfirmed, Vuln{}, nil, tenant.EmergingThreatSettings{ImmediateThreshold: 60}, false); got != LevelImmediate {
		t.Fatalf("65 with 60: %s", got)
	}
	if got := LevelFor(Breakdown{Total: 25}, TierConfirmed, Vuln{}, nil, tenant.EmergingThreatSettings{DigestThreshold: 20}, false); got != LevelDigest {
		t.Fatalf("25 with digest 20: %s", got)
	}
}

func TestReopenedBy(t *testing.T) {
	if !ReopenedBy(ReasonVersionNotAffected, TierPossible, TierConfirmed, false) {
		t.Fatal("a stronger match must reopen")
	}
	if !ReopenedBy(ReasonCompensatingControl, TierConfirmed, TierConfirmed, true) {
		t.Fatal("KEV must reopen a compensating-control suppression")
	}
	for _, r := range []string{ReasonVersionNotAffected, ReasonWrongProduct} {
		if ReopenedBy(r, TierConfirmed, TierConfirmed, true) {
			t.Fatalf("KEV reopened %s", r)
		}
	}
	if ReopenedBy(ReasonFeatureNotUsed, TierConfirmed, TierConfirmed, false) {
		t.Fatal("nothing new reopened")
	}
}

func TestValidateTransition(t *testing.T) {
	if err := ValidateTransition(StateNotAffected, "", ""); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("not affected without reason: %v", err)
	}
	if err := ValidateTransition(StateNotAffected, ReasonFeatureNotUsed, ""); err != nil {
		t.Fatal(err)
	}
	if err := ValidateTransition(StateResolved, "", ""); !errors.Is(err, shared.ErrValidation) {
		t.Fatal("resolved is the planner's, not a person's")
	}
	if err := ValidateTransition(StateAcknowledged, "", strings.Repeat("x", MaxNoteLength+1)); !errors.Is(err, shared.ErrValidation) {
		t.Fatal("long note accepted")
	}
	if err := ValidateTransition(State("closed"), "", ""); !errors.Is(err, shared.ErrValidation) {
		t.Fatal("unknown state accepted")
	}
}

func TestPlainTextStripsChannelMarkup(t *testing.T) {
	got := PlainText("<!channel> @here *Forti*OS\n`x` [link](https://evil.example)\u0007 ok", 200)
	for _, bad := range []string{"<", ">", "@", "*", "`", "[", "]", "\n", "\u0007"} {
		if strings.Contains(got, bad) {
			t.Fatalf("%q kept %q", got, bad)
		}
	}
	if !strings.Contains(got, "Forti OS") && !strings.Contains(got, "Forti") {
		t.Fatalf("text lost: %q", got)
	}
	if n := len([]rune(PlainText(strings.Repeat("é", 500), 120))); n > 120 {
		t.Fatalf("not capped: %d", n)
	}
	if got := Title("CVE-2026-1", "Fortinet <FortiOS>"); got != "CVE-2026-1 · Fortinet FortiOS" {
		t.Fatalf("title %q", got)
	}
	if got := Title("CVE-2026-1", ""); got != "CVE-2026-1" {
		t.Fatalf("title %q", got)
	}
}

func TestRecommendedAction(t *testing.T) {
	if RecommendedAction(TierPossible, Breakdown{Exploitation: 40}) != ActionConfirm {
		t.Fatal("possible must confirm first")
	}
	if RecommendedAction(TierConfirmed, Breakdown{Exploitation: 20}) != ActionPatchNow {
		t.Fatal("exploited and confirmed: patch now")
	}
	if RecommendedAction(TierConfirmed, Breakdown{}) != ActionPatchWithinSLA {
		t.Fatal("not exploited: within SLA")
	}
}

func TestSettings(t *testing.T) {
	h := func(v int) *int { return &v }
	bad := []tenant.EmergingThreatSettings{
		{ImmediateThreshold: 50}, {ImmediateThreshold: 95}, {DigestThreshold: 10}, {DigestThreshold: 70},
		{DigestHour: h(24)}, {DigestHour: h(-1)}, {QuietOverride: 60}, {QuietOverride: 101},
		{QuietHours: tenant.QuietHours{Enabled: true, StartHour: 5, EndHour: 5}}, {QuietHours: tenant.QuietHours{StartHour: 25}},
	}
	for _, s := range bad {
		if err := s.Validate(); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("%+v accepted", s)
		}
	}
	e := tenant.EmergingThreatSettings{}.Effective()
	if e.ImmediateThreshold != 70 || e.DigestThreshold != 35 || *e.DigestHour != 8 || e.QuietOverride != 90 || e.Disabled || e.AssetNamesInMessages {
		t.Fatalf("defaults: %+v", e)
	}
	wrap := tenant.EmergingThreatSettings{QuietHours: tenant.QuietHours{Enabled: true, StartHour: 22, EndHour: 7}}
	for hour, want := range map[int]bool{21: false, 22: true, 3: true, 6: true, 7: false, 12: false} {
		if wrap.InQuietHours(hour) != want {
			t.Errorf("22-7 at %d: want %v", hour, want)
		}
	}
	if (tenant.EmergingThreatSettings{}).InQuietHours(3) {
		t.Error("quiet hours are off by default")
	}
}
