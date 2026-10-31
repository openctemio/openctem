package posture

import (
	"math"
	"testing"
)

func TestWeightsAddUpTo100(t *testing.T) {
	var sum float64
	for _, c := range Categories() {
		sum += WeightOf(c).Max
	}
	if sum != 100 {
		t.Fatalf("weights add up to %v, want 100", sum)
	}
}

func TestComputeNoSurfaceIsNotMeasured(t *testing.T) {
	s := Compute(Sums{})
	if s.Measured || s.Grade != "" || s.Value != 0 {
		t.Fatalf("empty surface: got %+v", s)
	}
}

func TestComputeCleanSurfaceIsA100(t *testing.T) {
	s := Compute(Sums{Assets: 50})
	if !s.Measured || s.Value != 100 || s.Grade != "A" {
		t.Fatalf("clean surface: got value %d grade %q", s.Value, s.Grade)
	}
}

func TestComputeWorkedExamples(t *testing.T) {
	cases := []struct {
		name  string
		sums  Sums
		value int
		grade string
	}{
		// 100 assets, one confirmed takeover (critical, 10 points):
		// 15 * 10 / (10 + 0.2*100) = 5 -> 95.
		{"one takeover on 100 assets", Sums{Assets: 100, Points: [6]float64{0, 10}}, 95, "A"},
		// 10 assets, one critical vulnerability: 35 * 10 / (10 + 2*10) = 11.67 -> 88.
		{"one critical vuln on 10 assets", Sums{Assets: 10, Points: [6]float64{10}}, 88, "B"},
		// 5 assets scale as 10 (MinSurface).
		{"tiny surface scales as ten", Sums{Assets: 5, Points: [6]float64{10}}, 88, "B"},
		// Every category saturated far beyond its half points: close to 0.
		{"everything broken", Sums{Assets: 10, Points: [6]float64{1e6, 1e6, 1e6, 1e6, 1e6, 1e6}}, 0, "F"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := Compute(c.sums)
			if s.Value != c.value || s.Grade != c.grade {
				t.Fatalf("got %d %s (raw %.3f), want %d %s", s.Value, s.Grade, s.Raw, c.value, c.grade)
			}
		})
	}
}

func TestComputeFixingAnyIssueRaisesTheRawScore(t *testing.T) {
	base := Sums{Assets: 40, Points: [6]float64{80, 10, 30, 5, 20, 4}}
	before := Compute(base).Raw
	for i := range base.Points {
		w := base
		w.Points[i] /= 2
		if after := Compute(w).Raw; after <= before {
			t.Fatalf("halving category %d did not raise the score: %.4f -> %.4f", i, before, after)
		}
	}
}

func TestDeductionNeverReachesMax(t *testing.T) {
	if d := deduction(0, 1e9, 10); d >= 35 || d < 34.9 {
		t.Fatalf("deduction %v must approach but not reach 35", d)
	}
}

func TestGrades(t *testing.T) {
	for score, want := range map[int]string{100: "A", 90: "A", 89: "B", 80: "B", 79: "C", 70: "C", 69: "D", 60: "D", 59: "F", 0: "F"} {
		if g := GradeOf(score); g != want {
			t.Errorf("GradeOf(%d) = %s, want %s", score, g, want)
		}
	}
	if g, f, ok := NextGrade("C"); !ok || g != "B" || f != 80 {
		t.Fatalf("NextGrade(C) = %s %d %v", g, f, ok)
	}
	if _, _, ok := NextGrade("A"); ok {
		t.Fatal("A has no next grade")
	}
}

func TestFixPlanReachesNextGradeWithFewestUrgentItems(t *testing.T) {
	// 20 assets: a takeover (10 points) and two vulnerabilities. The
	// takeover is the most urgent per point (15/0.2 vs 35/2).
	s := Sums{Assets: 20, Points: [6]float64{30, 10}, Issues: [6]int64{3, 1}}
	cur := Compute(s)
	items := []Item{
		{AssetID: "b", Category: CatVulnerabilities, Points: 20, Issues: 2},
		{AssetID: "a", Category: CatHijackable, Points: 10, Issues: 1},
		{AssetID: "c", Category: CatVulnerabilities, Points: 10, Issues: 1},
	}
	p := FixPlan(s, items)
	if p.Target == "" {
		t.Fatalf("grade %s should have a target", cur.Grade)
	}
	if len(p.Steps) == 0 || p.Steps[0].Item.AssetID != "a" {
		t.Fatalf("first step should be the takeover, got %+v", p.Steps)
	}
	last := p.Steps[len(p.Steps)-1]
	if p.Reached != (last.ScoreAfter >= p.Floor) {
		t.Fatalf("reached flag inconsistent: %+v", p)
	}
	for i := 1; i < len(p.Steps); i++ {
		if p.Steps[i].ScoreAfter < p.Steps[i-1].ScoreAfter {
			t.Fatal("score must not drop along the plan")
		}
	}
}

func TestFixPlanEmptyAtA(t *testing.T) {
	if p := FixPlan(Sums{Assets: 10}, nil); p.Target != "" || len(p.Steps) != 0 {
		t.Fatalf("an A has no plan: %+v", p)
	}
}

func TestReductionsCoverEveryLevelAndShareAddsUp(t *testing.T) {
	crit := Sums{Assets: 2, Points: [6]float64{20, 10}, Issues: [6]int64{2, 1}}
	med := Sums{Assets: 8, Points: [6]float64{10}, Issues: [6]int64{3}}
	total := crit
	total.Add(med)
	rs := Reductions(total, []LevelSums{{"critical", crit}, {"medium", med}})
	if len(rs) != 4 || rs[0].Criticality != "critical" || rs[3].Criticality != "low" {
		t.Fatalf("levels: %+v", rs)
	}
	var share float64
	for _, r := range rs {
		share += r.Share
	}
	if math.Abs(share-100) > 0.2 {
		t.Fatalf("shares add to %v", share)
	}
	if rs[0].Gain <= rs[2].Gain {
		t.Fatalf("fixing the critical assets (more points) should gain more: %+v", rs)
	}
	if rs[1].Gain != 0 || rs[3].Gain != 0 {
		t.Fatalf("levels without points gain nothing: %+v", rs)
	}
}

func TestExposureCategoryMapping(t *testing.T) {
	for typ, want := range map[string]Category{
		"subdomain_takeover": CatHijackable, "port_open": CatExposedServices, "bucket_public": CatCloudStorage,
		"email_security_weak": CatMisconfiguration, "lookalike_domain": CatSuspicious,
	} {
		if c, ok := ExposureCategory(typ); !ok || c != want {
			t.Errorf("%s -> %s %v, want %s", typ, c, ok, want)
		}
	}
	for _, typ := range []string{"port_closed", "subdomain_discovered", "identity_mfa_gap", "custom"} {
		if _, ok := ExposureCategory(typ); ok {
			t.Errorf("%s must not count", typ)
		}
	}
	n := 0
	for _, ts := range ExposureTypes() {
		n += len(ts)
	}
	if n != 20 {
		t.Fatalf("ExposureTypes lists %d types", n)
	}
}

func TestMultiplier(t *testing.T) {
	if Multiplier("low", true) != 2 || Multiplier("low", false) != 0.5 || Multiplier("weird", false) != 1 {
		t.Fatal("multipliers")
	}
	if EffectiveCriticality("low", true) != "critical" || EffectiveCriticality("", false) != "medium" {
		t.Fatal("effective criticality")
	}
}

func TestSchedules(t *testing.T) {
	if !DefaultSchedule.Valid() || Schedule("5m").Valid() {
		t.Fatal("schedules")
	}
}

func TestRootDomain(t *testing.T) {
	for in, want := range map[string]string{
		"charts-uat.vndirect.com.vn":     "vndirect.com.vn",
		"https://a.b.example.com:8443/x": "example.com",
		"api.example.co.uk:443":          "example.co.uk",
		"*.dev.example.com":              "example.com",
		"Example.COM.":                   "example.com",
		"10.0.0.1":                       "",
		"10.0.0.1:22":                    "",
		"[2001:db8::1]:443":              "",
		"localhost":                      "",
		"":                               "",
	} {
		if got := RootDomain(in); got != want {
			t.Errorf("RootDomain(%q) = %q, want %q", in, got, want)
		}
	}
}
