package scope

import "testing"

func actions(rs []Remedy) []string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		out = append(out, r.Action)
	}
	return out
}

func eq(a, b []string) bool {
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

func TestRankRemedies(t *testing.T) {
	verify := []Fix{{Action: FixVerifyDomain, Domain: "acme.example"}, {Action: FixUseTenantSensor}}
	one := 1
	cases := []struct {
		name string
		in   RemedyInput
		want []string
	}{
		{"own sensor online ranks first for proof", RemedyInput{Code: RefusalProofRequired, Fixes: verify, Preference: "platform", TenantSensor: true},
			[]string{RemedyRunOnTenantSensor, RemedyVerifyDomain, RemedyRemove}},
		{"no own sensor: verify first", RemedyInput{Code: RefusalProofRequired, Fixes: verify, Preference: "auto"},
			[]string{RemedyVerifyDomain, RemedyRemove}},
		{"already on own sensors: no switch", RemedyInput{Code: RefusalProofRequired, Fixes: verify, Preference: "tenant", TenantSensor: true},
			[]string{RemedyVerifyDomain, RemedyRemove}},
		{"caller may not verify (fix filtered out)", RemedyInput{Code: RefusalProofRequired, Fixes: []Fix{{Action: FixUseTenantSensor}}, Preference: "auto"},
			[]string{RemedyRemove}},
		{"program target, own sensor", RemedyInput{Code: RefusalProgramPlatform, Preference: "platform", TenantSensor: true},
			[]string{RemedyRunOnTenantSensor, RemedyRemove}},
		{"own sensor does not help an out-of-scope target", RemedyInput{Code: RefusalNoEntry, Preference: "platform", TenantSensor: true},
			[]string{RemedyRemove}},
		{"lower intensity", RemedyInput{Code: RefusalTierExceeds, LowerTier: &one},
			[]string{RemedyLowerIntensity, RemedyRemove}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := RankRemedies(c.in)
			if !eq(actions(got), c.want) {
				t.Fatalf("got %v, want %v", actions(got), c.want)
			}
		})
	}
	got := RankRemedies(RemedyInput{Code: RefusalProofRequired, Fixes: verify})
	if got[0].Domain != "acme.example" {
		t.Fatalf("verify carries the domain: %+v", got[0])
	}
	low := RankRemedies(RemedyInput{Code: RefusalTierExceeds, LowerTier: &one})
	if low[0].Tier == nil || *low[0].Tier != 1 {
		t.Fatalf("lower intensity carries the tier: %+v", low[0])
	}
}

func TestTierSensitive(t *testing.T) {
	if !TierSensitive(RefusalTierExceeds) || !TierSensitive(RefusalLowImpact) || TierSensitive(RefusalProofRequired) {
		t.Fatal("tier-sensitive codes")
	}
}
