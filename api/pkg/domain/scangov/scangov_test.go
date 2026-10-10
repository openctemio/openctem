package scangov

import (
	"errors"
	"testing"
	"time"

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

func TestDigestAndDiff(t *testing.T) {
	a := Definition{Targets: []string{"b.example.com", "a.example.com"}, ScanType: "single", ScannerName: "nuclei",
		ScannerConfig: map[string]any{"z": 1, "a": "x"}, Intensity: "active", ScheduleType: "manual"}
	b := a
	b.Targets = []string{"a.example.com", "b.example.com", " a.example.com "}
	if a.Digest() != b.Digest() {
		t.Fatal("target order and duplicates must not change the digest")
	}
	if d := Diff(a, b); len(d) != 0 {
		t.Fatalf("no change: %+v", d)
	}
	c := b
	c.Intensity = "intrusive"
	c.Targets = append(c.Targets, "*.example.com")
	if a.Digest() == c.Digest() {
		t.Fatal("intensity and targets change the digest")
	}
	d := Diff(a, c)
	if len(d) != 2 || d[0].Field != "targets" || d[1].Field != "intensity" {
		t.Fatalf("diff: %+v", d)
	}
}

func TestRequestLifecycle(t *testing.T) {
	now := time.Date(2026, 10, 10, 9, 0, 0, 0, time.UTC)
	tid, sid := shared.NewID(), shared.NewID()
	def := Definition{Targets: []string{"x.example.com"}, ScanType: "single", ScannerName: "nuclei", Intensity: "intrusive"}
	ev := Evaluation{Mode: ModeStrict, Required: true, Approvals: 2, Validity: ValidityDefinition}
	r := NewRequest(tid, sid, def, ev, "req", "pentest", "", true, 0, now)
	if !r.IsPending(now) || r.ExpiresAt.Sub(now) != DefaultPendingDays*24*time.Hour {
		t.Fatalf("new request: %+v", r)
	}
	if err := r.Approve("req", "", now); !errors.Is(err, ErrOwnRequest) {
		t.Fatalf("the requester never approves: %v", err)
	}
	if err := r.Approve("a1", "ok", now); err != nil || r.Status != StatusPending || r.Remaining() != 1 {
		t.Fatalf("first approval: %v %+v", err, r)
	}
	if err := r.Approve("a1", "", now); !errors.Is(err, ErrAlreadyApproved) {
		t.Fatalf("the same person counts once: %v", err)
	}
	if r.Authorizes(def.Digest(), now) {
		t.Fatal("a pending request authorizes nothing")
	}
	if err := r.Approve("a2", "", now); err != nil || r.Status != StatusApproved {
		t.Fatalf("second approval: %v %+v", err, r)
	}
	if !r.Authorizes(def.Digest(), now.Add(365*24*time.Hour)) {
		t.Fatal("until the definition changes")
	}
	changed := def
	changed.Targets = []string{"y.example.com"}
	if r.Authorizes(changed.Digest(), now) {
		t.Fatal("a changed definition is not authorized")
	}
	if err := r.Reject("a3", "", now); !errors.Is(err, ErrNotPending) {
		t.Fatalf("an approved request cannot be rejected: %v", err)
	}

	// Expiry, rejection, cancel.
	p := NewRequest(tid, sid, def, ev, "req", "", "", false, 2, now)
	if p.IsPending(now.Add(49*time.Hour)) || p.Approve("a1", "", now.Add(49*time.Hour)) == nil {
		t.Fatal("an expired request takes no approvals")
	}
	if err := p.Reject("req", "", now); !errors.Is(err, ErrOwnRequest) {
		t.Fatalf("the requester cancels, not rejects: %v", err)
	}
	if err := p.Cancel("other", now); err == nil {
		t.Fatal("only the requester cancels")
	}
	if err := p.Reject("a1", "too wide", now); err != nil || p.Status != StatusRejected {
		t.Fatalf("reject: %v", err)
	}

	// Validity: run-only and days.
	runOnly := NewRequest(tid, sid, def, Evaluation{Approvals: 1, Validity: ValidityRun}, "req", "", "", false, 0, now)
	_ = runOnly.Approve("a1", "", now)
	if !runOnly.Authorizes(def.Digest(), now) {
		t.Fatal("run-only before use")
	}
	runOnly.ConsumedAt = &now
	if runOnly.Authorizes(def.Digest(), now) {
		t.Fatal("run-only after use")
	}
	days := NewRequest(tid, sid, def, Evaluation{Approvals: 1, Validity: ValidityDays, ValidityDays: 3}, "req", "", "", false, 0, now)
	_ = days.Approve("a1", "", now)
	if !days.Authorizes(def.Digest(), now.Add(71*time.Hour)) || days.Authorizes(def.Digest(), now.Add(73*time.Hour)) {
		t.Fatal("days validity")
	}
}

func TestEligibilityAndSelfApproval(t *testing.T) {
	now := time.Now()
	all := []Approver{{UserID: "owner", Role: RoleOwner}, {UserID: "adm", Role: RoleAdmin}, {UserID: "lead", Role: "member"}}
	r := NewRequest(shared.NewID(), shared.NewID(), Definition{}, Evaluation{Approvals: 1, ApproverRoles: []string{"admin"}}, "owner", "", "", false, 0, now)
	if got := r.Eligible(all); len(got) != 1 || got[0].UserID != "adm" {
		t.Fatalf("rule names admins: %+v", got)
	}
	if r.SelfApprovalAllowed("owner", all, now) {
		t.Fatal("no self-approval while another approver can approve")
	}
	r.Evaluation.ApproverUserIDs = []string{"lead"}
	if got := r.Eligible(all); len(got) != 2 {
		t.Fatalf("role or named person: %+v", got)
	}

	solo := []Approver{{UserID: "owner", Role: RoleOwner}}
	s := NewRequest(shared.NewID(), shared.NewID(), Definition{}, Evaluation{Approvals: 1}, "owner", "", "", false, 0, now)
	if !s.SelfApprovalAllowed("owner", solo, now) {
		t.Fatal("the sole owner may self-approve")
	}
	if s.SelfApprovalAllowed("other", solo, now) {
		t.Fatal("only the requester self-approves")
	}
	if err := s.SelfApprove("owner", "only owner", now); err != nil || s.Status != StatusApproved || !s.Approvals[0].Self {
		t.Fatalf("self-approve: %v %+v", err, s)
	}
	m := NewRequest(shared.NewID(), shared.NewID(), Definition{}, Evaluation{Approvals: 1}, "adm", "", "", false, 0, now)
	if m.SelfApprovalAllowed("adm", []Approver{{UserID: "adm", Role: RoleAdmin}}, now) {
		t.Fatal("an administrator who is not an owner never self-approves")
	}
	// Strict with one other approver: the other gives one, the owner the second.
	two := NewRequest(shared.NewID(), shared.NewID(), Definition{}, Evaluation{Approvals: 2}, "owner", "", "", false, 0, now)
	pair := []Approver{{UserID: "owner", Role: RoleOwner}, {UserID: "adm", Role: RoleAdmin}}
	if !two.SelfApprovalAllowed("owner", pair, now) {
		t.Fatal("one other approver cannot give two approvals")
	}
	_ = two.Approve("adm", "", now)
	if two.SelfApprovalAllowed("owner", pair, now) != true || two.Remaining() != 1 {
		t.Fatal("after the other approved, the owner gives the last")
	}
}

func TestEmergency(t *testing.T) {
	now := time.Now()
	def := Definition{Targets: []string{"x"}}
	e := NewEmergency(shared.NewID(), shared.NewID(), def, Evaluation{Approvals: 2}, "adm", "outage", 99, now)
	if !e.Emergency || e.Status != StatusApproved || e.ValidUntil.Sub(now.UTC()) != DefaultEmergencyHours*time.Hour {
		t.Fatalf("emergency: %+v", e)
	}
	if !e.Authorizes(def.Digest(), now.Add(time.Hour)) || e.Authorizes(def.Digest(), now.Add(5*time.Hour)) {
		t.Fatal("an emergency approval is time-boxed")
	}
}
