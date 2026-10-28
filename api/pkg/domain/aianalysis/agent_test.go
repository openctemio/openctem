package aianalysis

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/approvalpolicy"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestDenied_KeepsApprovalsResolvingAndAdministrationWithPeople(t *testing.T) {
	for _, p := range []string{
		"findings:approve", "findings:suppressions:approve", "scans:approve", "findings:verify", "findings:fix_apply",
		"findings:delete", "findings:export", "findings:bulk_update", "findings:credentials:reveal",
		"findings:evidence:reveal", "settings:write", "team:roles:assign", "service_accounts:manage",
		"integrations:write", "audit:read", "sensors:write", "scans:execute",
	} {
		if !Denied(p) {
			t.Errorf("%s must never be effective for an AI agent", p)
		}
	}
	for _, p := range []string{
		"findings:read", "findings:comment", "findings:write", "findings:status", "findings:severity",
		"findings:triage", "findings:assign", "assets:read", "scans:read", "ai_triage:read",
	} {
		if Denied(p) {
			t.Errorf("%s should be allowed by the deny list", p)
		}
	}
}

func TestEffective_RoleWithinCeilingMinusDenyList(t *testing.T) {
	role := []string{"findings:read", "findings:status", "findings:approve", "findings:severity"}
	got := Effective(role, false, []string{"findings:read", "findings:approve"})
	if len(got) != 1 || got[0] != "findings:read" {
		t.Fatalf("effective = %v, want only findings:read (status/severity above the ceiling, approve denied)", got)
	}
	got = Effective(role, true, nil)
	want := []string{"findings:read", "findings:severity", "findings:status"}
	if len(got) != len(want) {
		t.Fatalf("effective under an administrator owner = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("effective = %v, want %v", got, want)
		}
	}
}

func TestAboveCeiling_ListsWhatNoOwnerHolds(t *testing.T) {
	above := AboveCeiling([]string{"findings:read", "findings:status", "findings:approve"}, false, []string{"findings:read"})
	if len(above) != 1 || above[0] != "findings:status" {
		t.Fatalf("above = %v, want [findings:status] (denied permissions are dropped, not refused)", above)
	}
	if AboveCeiling([]string{"findings:status"}, true, nil) != nil {
		t.Fatal("an owner or administrator holds everything")
	}
}

func TestPresets_NeverCarryDeniedPermissions(t *testing.T) {
	for _, p := range []Preset{PresetSuggest, PresetTriage} {
		perms := p.Permissions()
		if len(perms) == 0 {
			t.Fatalf("preset %s has no permissions", p)
		}
		known := map[string]bool{}
		for _, x := range permission.AllPermissions() {
			known[string(x)] = true
		}
		for _, x := range perms {
			if Denied(x) {
				t.Errorf("preset %s carries denied permission %s", p, x)
			}
			if !known[x] {
				t.Errorf("preset %s carries unknown permission %s", p, x)
			}
		}
	}
	if len(PresetTriage.Permissions()) <= len(PresetSuggest.Permissions()) {
		t.Fatal("triage must extend suggest")
	}
	if Preset("custom").Permissions() != nil {
		t.Fatal("an unknown preset has no permissions")
	}
}

func TestHealthReason(t *testing.T) {
	now := time.Now()
	a := &Agent{AttestDueAt: now.Add(time.Hour)}
	if r := a.HealthReason(now, 1); r != "" {
		t.Fatalf("healthy agent paused: %s", r)
	}
	if r := a.HealthReason(now, 0); r != PauseNoActiveOwner {
		t.Fatalf("no owner: got %q", r)
	}
	a.AttestDueAt = now
	if r := a.HealthReason(now, 2); r != PauseAttestationExpired {
		t.Fatalf("attestation due now: got %q", r)
	}
}

func TestStampActor_OnlyTheAgentsOwnRows(t *testing.T) {
	agent, person := shared.NewID(), shared.NewID()
	ctx := WithProvenance(context.Background(), Provenance{AgentID: agent, RunID: shared.NewID()})
	if _, ok := StampActor(ctx, &person); ok {
		t.Fatal("a person's row in the same context must not be labeled AI")
	}
	p, ok := StampActor(ctx, &agent)
	if !ok || p.Map()["run_id"] == "" {
		t.Fatal("the agent's row carries the run")
	}
	if _, ok := StampActor(context.Background(), &agent); ok {
		t.Fatal("no provenance, no stamp")
	}
}

// An AI agent requests as a requester who can never approve (its effective
// permissions never include an approve permission and the executor passes
// CanApprove=false), so every risk-lowering change it asks for needs a
// person, whatever the organization's levels.
func TestAgentRequests_AlwaysNeedAPerson(t *testing.T) {
	agent := shared.NewID()
	for _, kind := range []approvalpolicy.Kind{approvalpolicy.KindFalsePositive, approvalpolicy.KindAccepted} {
		for _, level := range []string{approvalpolicy.FPLevelOff, approvalpolicy.FPLevelAll} {
			res := approvalpolicy.Evaluate(approvalpolicy.Policy{}, approvalpolicy.Request{
				Kind: kind, RequesterID: agent, RequesterCanApprove: false, FPLevel: level, AcceptLevel: level,
				Approvers: []approvalpolicy.Candidate{{UserID: agent}},
			})
			if res.SinglePerson() || res.Required < 1 {
				t.Errorf("%s at level %s: tier %s, %d approvals: an agent's request was decided without a person",
					kind, level, res.Tier, res.Required)
			}
			for _, e := range res.Eligible {
				if e == agent {
					t.Errorf("%s: the requesting agent is an eligible approver", kind)
				}
			}
		}
	}
}

func TestParseRole(t *testing.T) {
	if r, err := ParseRole(""); err != nil || r != RoleAnalyst {
		t.Fatalf("empty role = %q, %v; want the default analyst", r, err)
	}
	for _, s := range []string{"analyst", "remediator", "reporter", "hunter", "router"} {
		if r, err := ParseRole(s); err != nil || string(r) != s {
			t.Errorf("ParseRole(%q) = %q, %v", s, r, err)
		}
	}
	for _, s := range []string{"admin", "Analyst", "ai_agent", " analyst"} {
		if _, err := ParseRole(s); err == nil {
			t.Errorf("ParseRole(%q) accepted an unknown role", s)
		}
	}
}
