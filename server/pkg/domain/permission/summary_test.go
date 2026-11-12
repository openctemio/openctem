package permission_test

import (
	"slices"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/permission"
)

func TestSummarize_RiskTiers(t *testing.T) {
	cases := []struct {
		name       string
		perms      []permission.Permission
		fullData   bool
		admin      bool
		want       permission.Risk
		wantReason string
	}{
		{"read only", []permission.Permission{permission.FindingsRead, permission.AssetsRead}, false, false, permission.RiskLow, ""},
		{"changes findings", []permission.Permission{permission.FindingsRead, permission.FindingsStatus}, false, false, permission.RiskMedium, ""},
		{"runs scans", []permission.Permission{permission.ScansExecute}, false, false, permission.RiskMedium, permission.ReasonRunScans},
		{"approves", []permission.Permission{permission.FindingsApprove}, false, false, permission.RiskMedium, permission.ReasonApprove},
		{"full data reader", []permission.Permission{permission.FindingsRead}, true, false, permission.RiskHigh, permission.ReasonFullData},
		{"invites people", []permission.Permission{permission.MembersInvite}, false, false, permission.RiskHigh, permission.ReasonManagePeople},
		{"reveals secrets", []permission.Permission{permission.CredentialsReveal}, false, false, permission.RiskHigh, permission.ReasonSecrets},
		{"administrator", nil, true, true, permission.RiskCritical, permission.ReasonAdmin},
	}
	for _, c := range cases {
		s := permission.Summarize(permission.ToStrings(c.perms), c.fullData, c.admin)
		if s.Risk != c.want {
			t.Errorf("%s: risk %s, want %s", c.name, s.Risk, c.want)
		}
		if c.wantReason != "" && !slices.Contains(s.Reasons, c.wantReason) {
			t.Errorf("%s: reasons %v miss %s", c.name, s.Reasons, c.wantReason)
		}
	}
}

func TestSummarize_AreasChangeBeforeView(t *testing.T) {
	s := permission.Summarize([]string{"assets:read", "findings:read", "findings:status", "scans:read"}, false, false)
	want := []permission.AreaAccess{{Area: "findings", Level: "change"}, {Area: "assets", Level: "view"}, {Area: "scans", Level: "view"}}
	if !slices.Equal(s.Areas, want) {
		t.Errorf("areas = %v, want %v", s.Areas, want)
	}
}

// Every template is explained: none is critical (no template administers the
// organization) and the full-data ones say so.
func TestSummarize_Templates(t *testing.T) {
	for _, tpl := range permission.RoleTemplates() {
		s := permission.Summarize(permission.ToStrings(tpl.Permissions), tpl.HasFullDataAccess, false)
		if s.Risk == permission.RiskCritical {
			t.Errorf("%s is critical", tpl.ID)
		}
		if tpl.HasFullDataAccess && !slices.Contains(s.Reasons, permission.ReasonFullData) {
			t.Errorf("%s: full data not explained", tpl.ID)
		}
		if len(s.Areas) == 0 {
			t.Errorf("%s: no areas", tpl.ID)
		}
	}
}

func TestDiffAndApplyTemplate(t *testing.T) {
	tpl := permission.RoleTemplate{Permissions: []permission.Permission{permission.FindingsRead, permission.ReportsRead}}
	d := permission.DiffTemplate([]string{"findings:read", "assets:read"}, tpl)
	if !slices.Equal(d.Added, []string{"reports:read"}) || !slices.Equal(d.Removed, []string{"assets:read"}) {
		t.Fatalf("diff = %+v", d)
	}
	got := permission.ApplyTemplateDiff([]string{"findings:read", "assets:read", "dashboard:read"}, d)
	if !slices.Equal(got, []string{"findings:read", "dashboard:read", "reports:read"}) {
		t.Errorf("applied = %v", got)
	}
	if !permission.DiffTemplate(permission.ToStrings(tpl.Permissions), tpl).Empty() {
		t.Error("an unchanged template has a diff")
	}
}
