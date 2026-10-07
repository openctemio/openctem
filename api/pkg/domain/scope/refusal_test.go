package scope

import "testing"

// tier_exceeds: raise the covering entry, or (a seed or verified domain
// covers it) an expiring entry at the needed tier; approvers only.
func TestNewTierRefusal(t *testing.T) {
	r := NewTierRefusal("app.example.com", &RuleRef{Kind: RuleScopeTarget, ID: "e1", Pattern: "*.example.com"}, TierIntrusive, 0)
	if r.Code != RefusalTierExceeds || r.Message == "" || len(r.Fixes) != 1 {
		t.Fatalf("refusal = %+v", r)
	}
	if f := r.Fixes[0]; f.Action != FixRaiseTier || f.ID != "e1" || f.Tier != "t2" || f.Requires != permScopeApprove {
		t.Fatalf("fix = %+v", f)
	}
	r = NewTierRefusal("app.example.com", nil, TierIntrusive, 3)
	if f := r.Fixes; len(f) != 1 || f[0].Action != FixAllowTemporarily || f[0].Pattern != "app.example.com" || f[0].Days != 3 || f[0].Tier != "t2" {
		t.Fatalf("seed-covered fixes = %+v", f)
	}
	if got := FilterFixes(r.Fixes, func(string) bool { return false }); len(got) != 0 {
		t.Fatalf("a member was offered %+v", got)
	}
}
