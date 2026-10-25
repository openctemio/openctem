package handler

import (
	"bytes"
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// findingExportExcluded is every FindingResponse field an export leaves out,
// on purpose. Adding a FindingResponse field forces a decision here or in
// FindingExportRow.
var findingExportExcluded = map[string]string{
	// Evidence and code: leave the platform only through the UI.
	"snippet": "evidence", "context_snippet": "evidence", "context_start_line": "evidence",
	"scanner_output": "evidence", "source_data": "evidence", "stacks": "evidence", "attachments": "evidence",
	"related_locations": "evidence", "data_flow": "evidence", "has_data_flow": "evidence",
	"start_column": "evidence", "end_column": "evidence", "location": "evidence",
	"fix_code": "fix code", "fix_regex": "fix code", "remediation": "fix code", "recommendation": "free text",
	"description": "free text", "message": "free text (title falls back to it)", "metadata": "free-form",
	"partial_fingerprints": "internal", "fingerprint": "internal", "correlation_id": "internal",
	"row_version": "internal", "tenant_id": "internal", "hosted_viewer_uri": "internal", "work_item_uris": "internal",
	// Secret details.
	"secret_type": "secret", "secret_service": "secret", "secret_valid": "secret", "secret_revoked": "secret",
	"secret_masked_value": "secret", "secret_fingerprint": "secret", "secret_entropy": "secret",
	"secret_scopes": "secret", "secret_expires_at": "secret", "secret_rotation_due_at": "secret",
	"secret_age_in_days": "secret", "secret_commit_count": "secret", "secret_in_history_only": "secret",
	"secret_verified_at": "secret",
	// Embedded objects and single-finding extras (ids are exported).
	"asset": "embedded (asset_name, asset_type exported)", "component": "embedded", "provenance": "embedded",
	"package_fix": "embedded", "intel": "embedded", "vulnerability": "embedded", "assigned_to_user": "embedded",
	"severity_override": "embedded", "pending_severity_request": "embedded",
	// A bug-bounty report carries the researcher's text and handle: it leaves
	// the platform only through the UI, like other free text.
	"bounty_report":    "embedded free text (researcher report)",
	"vulnerability_id": "id not useful offline", "branch_id": "id not useful offline", "component_id": "id not useful offline",
	"tool_id": "id not useful offline", "sub_status_id": "id not useful offline", "duplicate_of": "id not useful offline",
	"scan_id": "id not useful offline", "resolved_by": "person id", "assigned_by": "person id", "verified_by": "person id",
	// Detail-page attributes not in the export (kept small; add by decision).
	"tool_version": "detail", "vpr_score": "detail", "cvss_version": "detail", "patch_published_at": "detail",
	"cvss_v2_vector": "detail", "cvss_v3_vector": "detail", "owasp_ids": "detail", "tags": "detail",
	"resolution": "detail", "closure_reason": "detail", "verification": "detail", "max_acceptance_days": "detail",
	"is_triaged": "derived", "assigned_at": "detail", "verified_at": "detail",
	"sla_kev_capped": "detail (SLA reason)", "acceptance_expires_at": "detail (My Work)", "kev_ransomware": "detail (KEV catalog lookup per list page)",
	"first_detected_branch": "detail", "first_detected_commit": "detail", "last_seen_branch": "detail",
	"last_seen_commit": "detail", "duplicate_count": "detail", "comments_count": "detail",
	"confidence": "detail", "impact": "detail", "likelihood": "detail", "vulnerability_class": "detail",
	"subcategory": "detail", "baseline_state": "detail", "kind": "detail", "rank": "detail",
	"occurrence_count": "detail", "kev_due_date": "detail", "priority_class_reason": "detail",
	"priority_class_override": "detail", "source_severity": "detail", "reachable_from_count": "detail",
	"exposure_vector": "detail", "is_network_accessible": "detail", "is_internet_accessible": "detail",
	"attack_prerequisites": "detail", "remediation_type": "detail", "estimated_fix_time": "detail",
	"fix_complexity": "detail", "remedy_available": "detail", "data_exposure_risk": "detail",
	"reputational_impact": "detail", "compliance_impact": "detail", "branch_only": "detail",
	"compliance_framework": "detail", "compliance_framework_version": "detail", "compliance_control_id": "detail",
	"compliance_control_name": "detail", "compliance_control_description": "detail", "compliance_result": "detail",
	"compliance_section": "detail", "web3_chain": "detail", "web3_chain_id": "detail",
	"web3_contract_address": "detail", "web3_swc_id": "detail", "web3_function_signature": "detail",
	"web3_tx_hash": "detail", "web3_function_selector": "detail", "web3_bytecode_offset": "detail",
	"misconfig_policy_id": "detail", "misconfig_policy_name": "detail", "misconfig_resource_type": "detail",
	"misconfig_resource_name": "detail", "misconfig_resource_path": "detail", "misconfig_expected": "evidence",
	"misconfig_actual": "evidence", "misconfig_cause": "evidence",
}

// Exported under another name (FindingResponse -> FindingExportRow).
var findingExportRenamed = map[string]string{"asset_name": "asset", "asset_type": "asset"}

func jsonNames(t reflect.Type) []string {
	out := make([]string, 0, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		name := strings.Split(t.Field(i).Tag.Get("json"), ",")[0]
		if name != "" && name != "-" {
			out = append(out, name)
		}
	}
	return out
}

func TestFindingExportRow_EveryResponseFieldDecided(t *testing.T) {
	exported := map[string]bool{}
	for _, n := range findingExportColumns {
		exported[n] = true
	}
	for _, n := range jsonNames(reflect.TypeOf(FindingResponse{})) {
		_, excluded := findingExportExcluded[n]
		switch {
		case exported[n] && excluded:
			t.Errorf("%s is both exported and excluded", n)
		case !exported[n] && !excluded:
			t.Errorf("FindingResponse field %s has no export decision: add it to FindingExportRow or findingExportExcluded", n)
		}
	}
	resp := map[string]bool{}
	for _, n := range jsonNames(reflect.TypeOf(FindingResponse{})) {
		resp[n] = true
	}
	for n := range exported {
		if !resp[n] && findingExportRenamed[n] == "" {
			t.Errorf("export column %s has no FindingResponse source", n)
		}
	}
}

// An NDJSON row has exactly the allowlisted keys, and nothing sensitive gets
// through even when the response carries it.
func TestFindingExportRow_NDJSONKeysAndNoEvidence(t *testing.T) {
	p := "P1"
	f := FindingResponse{
		ID: "f1", Title: "t", Severity: "high", Status: "new", PriorityClass: &p, Source: "secret", FindingType: "secret",
		Snippet: "AKIA-SNIPPET", ContextSnippet: "CTX-SNIPPET", FixCode: "FIX-CODE", Description: "DESC-TEXT",
		Metadata: map[string]any{"k": "META-VALUE"}, SecretMaskedValue: "MASKED", SecretFingerprint: "SECRET-FP",
		Asset: &FindingAssetInfo{Name: "app.example.com", Type: "domain"},
	}
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(toFindingExportRow(f)); err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	keys := make([]string, 0, len(got))
	for k := range got {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	want := append([]string(nil), findingExportColumns...)
	sort.Strings(want)
	if !reflect.DeepEqual(keys, want) {
		t.Fatalf("NDJSON keys = %v, want %v", keys, want)
	}
	for _, leak := range []string{"AKIA-SNIPPET", "CTX-SNIPPET", "FIX-CODE", "DESC-TEXT", "META-VALUE", "MASKED", "SECRET-FP"} {
		if bytes.Contains(buf.Bytes(), []byte(leak)) {
			t.Errorf("NDJSON row leaked %s: %s", leak, buf.String())
		}
	}
	if got["asset_name"] != "app.example.com" || got["priority_class"] != "P1" {
		t.Errorf("row = %v", got)
	}
	cells := toFindingExportRow(f).csvCells()
	if len(cells) != len(findingExportColumns) {
		t.Fatalf("csv row has %d cells, header %d", len(cells), len(findingExportColumns))
	}
	if strings.Contains(strings.Join(cells, ","), "SNIPPET") {
		t.Error("csv row leaked a snippet")
	}
}
