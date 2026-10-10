package unit

import (
	"slices"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/permission"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
)

// Every refusal code has a message, and every fix names a real permission
// (RFC-054 §6.5).
func TestScopeRefusal_CodesAndFixes(t *testing.T) {
	codes := []string{
		scopedom.RefusalInvalidTarget, scopedom.RefusalDenyList, scopedom.RefusalExcluded, scopedom.RefusalRejected,
		scopedom.RefusalNeedsReview, scopedom.RefusalCandidate, scopedom.RefusalDependency, scopedom.RefusalMonitorOnly,
		scopedom.RefusalNoEntry, scopedom.RefusalEntryPending, scopedom.RefusalEntryExpired, scopedom.RefusalEntryInactive,
		scopedom.RefusalTierExceeds, scopedom.RefusalProofRequired, scopedom.RefusalOutOfDataScope, scopedom.RefusalNotAnAsset,
		scopedom.RefusalZoneNone, scopedom.RefusalZoneNoSensor, scopedom.RefusalZoneSensorMismatch,
		scopedom.RefusalProgramPlatform, scopedom.RefusalConstrained,
	}
	all := permission.AllPermissions()
	for _, c := range codes {
		if scopedom.RefusalMessages[c] == "" {
			t.Errorf("%s has no message", c)
		}
		for _, target := range []string{"app.example.co.uk", "https://shop.example.co.uk/x", "203.0.113.7"} {
			for _, f := range scopedom.FixesFor(c, target, &scopedom.RuleRef{ID: "x"}, 7) {
				if f.Requires != "" && !slices.Contains(all, permission.Permission(f.Requires)) {
					t.Errorf("%s fix %s requires unknown permission %q", c, f.Action, f.Requires)
				}
			}
		}
	}
}

func TestScopeRefusal_NoEntryFixes(t *testing.T) {
	fixes := scopedom.FixesFor(scopedom.RefusalNoEntry, "https://app.example.co.uk/login", nil, 7)
	var add *scopedom.Fix
	for i := range fixes {
		if fixes[i].Action == scopedom.FixAddEntry {
			add = &fixes[i]
		}
	}
	if add == nil || add.Pattern != "*.example.co.uk" {
		t.Fatalf("add_entry fix = %+v, want *.example.co.uk (the registrable domain, never the public suffix)", add)
	}
	// An approver allows it; a member requests it; nobody sees both.
	approver := scopedom.FilterFixes(fixes, func(string) bool { return true })
	memberFixes := scopedom.FilterFixes(fixes, func(p string) bool { return p == string(permission.ScopeWrite) })
	has := func(list []scopedom.Fix, action string) bool {
		return slices.ContainsFunc(list, func(f scopedom.Fix) bool { return f.Action == action })
	}
	if !has(approver, scopedom.FixAllowTemporarily) || has(approver, scopedom.FixRequestAccess) {
		t.Errorf("approver fixes: %+v", approver)
	}
	if has(memberFixes, scopedom.FixAllowTemporarily) || has(memberFixes, scopedom.FixAddEntry) || !has(memberFixes, scopedom.FixRequestAccess) {
		t.Errorf("member fixes: %+v", memberFixes)
	}
	if got := scopedom.FixesFor(scopedom.RefusalNoEntry, "203.0.113.7", nil, 3); got[0].Pattern != "203.0.113.7" || got[0].Days != 3 || got[0].TargetType != "ip_address" {
		t.Errorf("address fixes: %+v", got)
	}
	// Platform policy names no detail and offers only support.
	deny := scopedom.NewRefusal("portal.gov.vn", scopedom.RefusalDenyList, &scopedom.RuleRef{Kind: scopedom.RulePlatformPolicy}, 7)
	if len(deny.Fixes) != 1 || deny.Fixes[0].Action != scopedom.FixContactSupport || deny.Rule.Pattern != "" {
		t.Errorf("deny-list refusal: %+v", deny)
	}
}
