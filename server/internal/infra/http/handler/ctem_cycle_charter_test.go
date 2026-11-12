package handler

import (
	"encoding/json"
	"testing"
)

// The CTEM cycle handler stores the charter as an opaque JSONB object
// (map[string]any) so it is schema-flexible: new charter fields flow
// through create/update/get without a handler change. These tests lock in
// that the playbook scope-charter fields (threat scenarios, exclusions,
// success criteria, escalation path, roles, timeline) survive the exact
// decode → marshal(JSONB) → unmarshal path the handler runs, and that an
// old-format charter still decodes.

const playbookCharterBody = `{
  "name": "2026 Q3 ransomware readiness",
  "charter": {
    "business_priorities": ["protect payments"],
    "risk_appetite": "low",
    "in_scope_services": ["svc-1"],
    "objectives": ["cut KEV exposure"],
    "threat_scenarios": ["ransomware via exposed RDP"],
    "exclusions": [{"item": "corp WiFi", "reason": "separate audit"}],
    "success_criteria": [{"name": "KEV", "metric": "open_kev", "target": "0"}],
    "escalation_path": "CISO -> VP Eng",
    "roles": {"sponsor": "ciso@x", "operator": "secops@x", "engineering_partner": "plat@x"},
    "timeline": "6-week cadence"
  }
}`

// TestCreateCharterRequest_PlaybookFieldsRoundTrip mirrors the handler's
// Create path: decode the request body, marshal the charter to JSONB, then
// unmarshal the stored JSONB back into the response charter map — exactly
// what Create/Update/scanCycle do — and assert every playbook field survives.
func TestCreateCharterRequest_PlaybookFieldsRoundTrip(t *testing.T) {
	var req CreateCTEMCycleRequest
	if err := json.Unmarshal([]byte(playbookCharterBody), &req); err != nil {
		t.Fatalf("decode request: %v", err)
	}
	if req.Name == "" {
		t.Fatal("name not decoded")
	}

	// Create: marshal the charter for the INSERT.
	charterJSON, err := json.Marshal(req.Charter)
	if err != nil {
		t.Fatalf("marshal charter: %v", err)
	}

	// scanCycle: unmarshal the RETURNING'd JSONB into the response map.
	var out map[string]any
	if err := json.Unmarshal(charterJSON, &out); err != nil {
		t.Fatalf("unmarshal charter: %v", err)
	}

	// Original + playbook keys are all present after the round-trip.
	for _, k := range []string{
		"business_priorities", "risk_appetite", "in_scope_services", "objectives",
		"threat_scenarios", "exclusions", "success_criteria", "escalation_path",
		"roles", "timeline",
	} {
		if _, ok := out[k]; !ok {
			t.Errorf("charter key %q dropped in round-trip", k)
		}
	}

	if out["escalation_path"] != "CISO -> VP Eng" {
		t.Errorf("escalation_path = %v", out["escalation_path"])
	}
	roles, ok := out["roles"].(map[string]any)
	if !ok || roles["sponsor"] != "ciso@x" {
		t.Errorf("roles not preserved: %v", out["roles"])
	}
	excl, ok := out["exclusions"].([]any)
	if !ok || len(excl) != 1 {
		t.Fatalf("exclusions not preserved: %v", out["exclusions"])
	}
	if e0 := excl[0].(map[string]any); e0["item"] != "corp WiFi" || e0["reason"] != "separate audit" {
		t.Errorf("exclusion content lost: %v", excl[0])
	}
}

// TestCreateCharterRequest_OldFormatDecodes proves a pre-playbook charter
// (only the original four fields) still decodes through the handler DTO.
func TestCreateCharterRequest_OldFormatDecodes(t *testing.T) {
	body := `{"name":"legacy","charter":{"business_priorities":["a"],"risk_appetite":"medium","in_scope_services":["s"],"objectives":["o"]}}`
	var req CreateCTEMCycleRequest
	if err := json.Unmarshal([]byte(body), &req); err != nil {
		t.Fatalf("decode legacy request: %v", err)
	}
	if req.Charter["risk_appetite"] != "medium" {
		t.Fatalf("legacy charter not decoded: %v", req.Charter)
	}
	if _, ok := req.Charter["threat_scenarios"]; ok {
		t.Fatal("legacy charter unexpectedly has threat_scenarios")
	}
}
