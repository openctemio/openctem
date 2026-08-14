package ctemcycle

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/openctemio/api/pkg/domain/shared"
)

// The charter is stored in the ctem_cycles.charter JSONB column and is
// (de)serialized with encoding/json by the handler. These tests exercise
// that exact marshal→JSONB→unmarshal round-trip for the playbook
// scope-charter fields, and prove that charters written before those
// fields existed still load with the new fields left empty.

func fullCharter() Charter {
	return Charter{
		BusinessPriorities: []string{"protect customer data", "keep payments up"},
		RiskAppetite:       "low",
		InScopeServices:    []string{"svc-1", "svc-2"},
		Objectives:         []string{"reduce KEV exposure"},
		ThreatScenarios:    []string{"ransomware via exposed RDP", "supply-chain compromise"},
		Exclusions: []CharterExclusion{
			{Item: "corp WiFi", Reason: "covered by separate network audit"},
			{Item: "legacy VPN", Reason: "decommission in progress"},
		},
		SuccessCriteria: []CharterSuccessCriterion{
			{Name: "KEV remediation", Metric: "open_kev_findings", Target: "0"},
			{Name: "P0 MTTR", Metric: "mttr_hours_p0", Target: "<48"},
		},
		EscalationPath: "CISO -> VP Eng",
		Roles: CharterRoles{
			Sponsor:            "ciso@example.com",
			Operator:           "secops@example.com",
			EngineeringPartner: "platform-team@example.com",
		},
		Timeline: "Q3 2026, 6-week cadence",
	}
}

// TestCharter_RoundTrip proves a fully-populated charter survives the
// marshal→JSONB→unmarshal cycle unchanged (the repo/handler path).
func TestCharter_RoundTrip(t *testing.T) {
	want := fullCharter()

	raw, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var got Charter
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if !reflect.DeepEqual(want, got) {
		t.Fatalf("round-trip mismatch:\n want %+v\n  got %+v", want, got)
	}
}

// TestCharter_OldFormatLoads proves backward compatibility: a charter
// persisted before the playbook fields existed (only the original four
// fields) still unmarshals, with every new field left at its zero value.
func TestCharter_OldFormatLoads(t *testing.T) {
	oldJSON := []byte(`{
		"business_priorities": ["a", "b"],
		"risk_appetite": "medium",
		"in_scope_services": ["svc-legacy"],
		"objectives": ["baseline coverage"]
	}`)

	var c Charter
	if err := json.Unmarshal(oldJSON, &c); err != nil {
		t.Fatalf("unmarshal old-format charter: %v", err)
	}

	// Original fields load as before.
	if len(c.BusinessPriorities) != 2 || c.RiskAppetite != "medium" ||
		len(c.InScopeServices) != 1 || len(c.Objectives) != 1 {
		t.Fatalf("original fields not preserved: %+v", c)
	}

	// Every new playbook field defaults to its zero value.
	if c.ThreatScenarios != nil {
		t.Errorf("ThreatScenarios = %v, want nil", c.ThreatScenarios)
	}
	if c.Exclusions != nil {
		t.Errorf("Exclusions = %v, want nil", c.Exclusions)
	}
	if c.SuccessCriteria != nil {
		t.Errorf("SuccessCriteria = %v, want nil", c.SuccessCriteria)
	}
	if c.EscalationPath != "" {
		t.Errorf("EscalationPath = %q, want empty", c.EscalationPath)
	}
	if (c.Roles != CharterRoles{}) {
		t.Errorf("Roles = %+v, want zero", c.Roles)
	}
	if c.Timeline != "" {
		t.Errorf("Timeline = %q, want empty", c.Timeline)
	}
}

// TestSetCharter_PreservesPlaybookFields proves SetCharter stores the new
// fields verbatim and keeps the planning-only mutation guard: once the
// cycle leaves planning, the charter (including playbook fields) is frozen.
func TestSetCharter_PreservesPlaybookFields(t *testing.T) {
	tid := shared.NewID()
	uid := shared.NewID()

	cycle, err := NewCycle(tid, "playbook cycle", uid)
	if err != nil {
		t.Fatalf("NewCycle: %v", err)
	}

	want := fullCharter()
	if err := cycle.SetCharter(want); err != nil {
		t.Fatalf("SetCharter in planning: %v", err)
	}
	if !reflect.DeepEqual(cycle.Charter(), want) {
		t.Fatalf("charter not stored verbatim:\n want %+v\n  got %+v", want, cycle.Charter())
	}

	// Freeze on activation: the charter can no longer be mutated.
	if err := cycle.Activate(); err != nil {
		t.Fatalf("Activate: %v", err)
	}
	if err := cycle.SetCharter(Charter{EscalationPath: "changed"}); err == nil {
		t.Fatal("SetCharter after activation must be rejected (planning-only guard)")
	}
	// The frozen charter is unchanged.
	if !reflect.DeepEqual(cycle.Charter(), want) {
		t.Fatalf("charter mutated after freeze: %+v", cycle.Charter())
	}
}
