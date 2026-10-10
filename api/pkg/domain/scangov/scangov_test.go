package scangov

import (
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestEffectiveMode(t *testing.T) {
	cases := []struct {
		tenant Mode
		policy PlatformPolicy
		want   Mode
		src    string
	}{
		{"", PolicyTenantControlled, ModeOff, SourceOrganization},
		{ModeOn, PolicyTenantControlled, ModeOn, SourceOrganization},
		{ModeStrict, PolicyOff, ModeOff, SourcePlatform},
		{ModeOff, PolicyOn, ModeOn, SourcePlatform},
		{ModeStrict, PolicyOn, ModeStrict, SourceOrganization},
		{ModeOff, PolicyStrict, ModeStrict, SourcePlatform},
		{ModeOn, "", ModeOn, SourceOrganization},
	}
	for _, c := range cases {
		got, src := Effective(c.tenant, c.policy)
		if got != c.want || src != c.src {
			t.Errorf("Effective(%q, %q) = %q/%q, want %q/%q", c.tenant, c.policy, got, src, c.want, c.src)
		}
	}
	if TenantMayChoose(ModeOff, PolicyOn) || !TenantMayChoose(ModeStrict, PolicyOn) || TenantMayChoose(ModeOn, PolicyStrict) || TenantMayChoose(ModeOn, PolicyOff) {
		t.Error("TenantMayChoose: a forced policy must refuse the modes it overrides")
	}
	if ScopeEntriesNeedApproval(ModeOn) || ScopeEntriesNeedApproval(ModeOff) || !ScopeEntriesNeedApproval(ModeStrict) {
		t.Error("scope entries keep approvals only in Strict")
	}
}

func TestNormalizeRejectsBadRules(t *testing.T) {
	ok := Rule{Name: "r", Enabled: true, Requirement: Requirement{Approvals: 1}}
	bad := map[string]Rule{
		"no name":         {Requirement: Requirement{Approvals: 1}},
		"zero approvals":  {Name: "r"},
		"three approvals": {Name: "r", Requirement: Requirement{Approvals: 3}},
		"bad intensity":   {Name: "r", Conditions: Conditions{MinIntensity: "loud"}, Requirement: Requirement{Approvals: 1}},
		"bad role":        {Name: "r", Requirement: Requirement{Approvals: 1, ApproverRoles: []string{"member"}}},
		"bad user":        {Name: "r", Requirement: Requirement{Approvals: 1, ApproverUserIDs: []string{"bob"}}},
		"bad pattern":     {Name: "r", Requirement: Requirement{Approvals: 1, TicketPattern: "("}},
		"bad validity":    {Name: "r", Requirement: Requirement{Approvals: 1, Validity: ValidityDays}},
		"bad placement":   {Name: "r", Conditions: Conditions{SensorPlacement: "cloud"}, Requirement: Requirement{Approvals: 1}},
		"bad id":          {ID: "x", Name: "r", Requirement: Requirement{Approvals: 1}},
	}
	for name, r := range bad {
		if _, err := Normalize([]Rule{r}); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("%s: want a validation error, got %v", name, err)
		}
	}
	out, err := Normalize([]Rule{ok, {Name: "t", Requirement: Requirement{Approvals: 2, TicketPattern: `CHG-\d+`}}})
	if err != nil || out[0].ID == "" || out[0].Requirement.Validity != ValidityDefinition || !out[1].Requirement.RequireTicket {
		t.Fatalf("Normalize: %v %+v", err, out)
	}
	if _, err := Normalize([]Rule{out[0], out[0]}); err == nil {
		t.Error("duplicate ids must be refused")
	}
}

func TestEvaluate(t *testing.T) {
	light := Preset(PresetLight)
	if ev := Evaluate(ModeOff, light, Facts{IntensityTier: 2}); ev.Required {
		t.Fatal("Off never requires an approval")
	}
	if ev := Evaluate(ModeOn, light, Facts{IntensityTier: 1}); ev.Required {
		t.Fatal("Light: an active scan needs none")
	}
	ev := Evaluate(ModeOn, light, Facts{IntensityTier: 2})
	if !ev.Required || ev.Approvals != 1 || len(ev.Matched) != 1 || ev.Decisive != light[0].ID {
		t.Fatalf("Light: an intrusive scan needs one approval: %+v", ev)
	}
	if ev := Evaluate(ModeStrict, light, Facts{IntensityTier: 2}); ev.Approvals != 2 || !ev.RequireJustification {
		t.Fatalf("Strict raises approvals to two and asks a justification: %+v", ev)
	}

	std := Preset(PresetStandard)
	prod := Facts{IntensityTier: 1, AssetTags: []string{"Production"}, WidestCIDRPrefix: -1}
	if ev := Evaluate(ModeOn, std, prod); !ev.Required || ev.Matched[0].Name != "Active scans on production assets" {
		t.Fatalf("Standard: an active scan on a production asset: %+v", ev)
	}
	if ev := Evaluate(ModeOn, std, Facts{IntensityTier: 0, AssetTags: []string{"production"}}); ev.Required {
		t.Fatal("Standard: a passive scan on production needs none")
	}
	if ev := Evaluate(ModeOn, std, Facts{IntensityTier: 1, TargetCount: 501}); !ev.Required {
		t.Fatal("Standard: a scan of more than 500 targets")
	}
}

func TestEvaluateMergesRules(t *testing.T) {
	rules, err := Normalize([]Rule{
		{Name: "monitor all", Enabled: true, Monitor: true, Requirement: Requirement{Approvals: 2}},
		{Name: "disabled", Enabled: false, Requirement: Requirement{Approvals: 2}},
		{Name: "ot zone", Enabled: true, Conditions: Conditions{ZoneIDs: []string{"6b1f5d1e-6a8e-4f53-9d5a-1f3e1b2c3d4e"}},
			Requirement: Requirement{Approvals: 1, ApproverUserIDs: []string{"11111111-1111-1111-1111-111111111111"}, Validity: ValidityDays, ValidityDays: 7}},
		{Name: "credentialed", Enabled: true, Conditions: Conditions{Tools: []string{"Hydra"}},
			Requirement: Requirement{Approvals: 2, ApproverRoles: []string{"admin"}, TicketPattern: `CHG-\d+`, Validity: ValidityRun}},
	})
	if err != nil {
		t.Fatal(err)
	}
	f := Facts{ZoneID: "6B1F5D1E-6A8E-4F53-9D5A-1F3E1B2C3D4E", Tools: []string{"hydra"}}
	ev := Evaluate(ModeOn, rules, f)
	if !ev.Required || len(ev.Matched) != 2 || len(ev.Monitored) != 1 {
		t.Fatalf("matched/monitored: %+v", ev)
	}
	if ev.Approvals != 2 || ev.Decisive != rules[3].ID || len(ev.ApproverRoles) != 1 || len(ev.ApproverUserIDs) != 0 {
		t.Fatalf("the rule with the most approvals decides the approvers: %+v", ev)
	}
	if ev.Validity != ValidityRun || !ev.RequireTicket || len(ev.TicketPatterns) != 1 {
		t.Fatalf("the shortest validity and every ticket pattern apply: %+v", ev)
	}
	if ev.CheckEvidence("", "") == "" || ev.CheckEvidence("", "INC-1") == "" || ev.CheckEvidence("", "CHG-42") != "" {
		t.Fatal("ticket evidence check")
	}
	// Monitor rules alone never block.
	if ev := Evaluate(ModeOn, rules[:1], Facts{}); ev.Required || len(ev.Monitored) != 1 {
		t.Fatalf("a monitor rule records without blocking: %+v", ev)
	}
}
