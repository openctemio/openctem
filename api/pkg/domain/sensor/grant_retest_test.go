package sensor

// Retest admission (RFC-052 §5.2, §5.3): a retest re-runs one finding's own
// rule with the tool that found it and is rated at that detection's tier.

import (
	"encoding/json"
	"slices"
	"testing"
)

func retestPayload(t *testing.T, tool, target string) json.RawMessage {
	t.Helper()
	return payload(t, map[string]any{
		"scanner": tool, "retest_id": "r1", "timeout_seconds": 120,
		"targets": []string{target},
		"items": []map[string]any{{
			"ref": "f1", "target": target, "kind": "finding", "rule_id": "CVE-2021-41773",
		}},
		"required_capabilities": []string{"retest:" + tool},
	})
}

var builtinT1 = &ToolContract{Origin: ToolOriginBuiltin, Class: "target-scan", Tier: "T1"}

// Every profile that may scan may also validate and retest, and no other
// dimension changes with it.
func TestProfiles_ScanProfilesRetest(t *testing.T) {
	for _, p := range SelectableProfiles() {
		g := mustProfile(t, p)
		if !slices.Contains(g.JobTypes, "scan") {
			if slices.Contains(g.JobTypes, "retest") {
				t.Errorf("%s retests without scanning", p)
			}
			continue
		}
		for _, jt := range []string{"validate", "retest"} {
			if !slices.Contains(g.JobTypes, jt) {
				t.Errorf("%s may scan but not %s: %v", p, jt, g.JobTypes)
			}
		}
	}
}

// A default (internal-network-scanner) sensor, once trusted, gets the retest
// of a finding a T1 tool raised: the retest is T1, as the detection was.
func TestAdmit_DefaultProfileRetestsT1Finding(t *testing.T) {
	g := trusted(mustProfile(t, DefaultProfile))
	p := retestPayload(t, "nuclei", "https://app.example.com")
	if tier := CommandTierFor("retest", JobOf("retest", p), builtinT1); tier != TierActive {
		t.Fatalf("nuclei retest tier = T%d, want T1 (the detection's)", tier)
	}
	if r := g.AdmitContract("retest", p, nil, builtinT1); r != nil {
		t.Fatalf("default trusted sensor refused a T1 retest: %v", r)
	}
	// The same grant, other profiles that scan at T1.
	for _, prof := range []string{ProfileEASMExternal, ProfileAuthenticatedScanner} {
		if r := trusted(mustProfile(t, prof)).AdmitContract("retest", p, nil, builtinT1); r != nil {
			t.Errorf("%s refused a T1 retest: %v", prof, r)
		}
	}
}

// A retest is never rated below the detection it repeats: a finding from a
// T2 detection (an intrusive tool, an operator-installed tool, a declared side
// effect) retests at T2 and a T1 ceiling refuses it.
func TestAdmit_T2OriginRetestRefusedUnderT1(t *testing.T) {
	g := trusted(mustProfile(t, DefaultProfile))
	cases := map[string]struct {
		tool     string
		contract *ToolContract
	}{
		"intrusive tool (DAST)":   {"zap", nil},
		"operator-installed tool": {"nuclei", &ToolContract{Origin: "adapter", Class: "target-scan", Tier: "T1"}},
		"declared side effect":    {"nuclei", &ToolContract{Origin: ToolOriginBuiltin, Class: "target-scan", Tier: "T1", Descriptor: json.RawMessage(`{"safety":{"side_effects":["writes"]}}`)}},
		"tool declares T2":        {"nuclei", &ToolContract{Origin: ToolOriginBuiltin, Class: "target-scan", Tier: "T2"}},
		"tool the catalog lacks":  {"mystery-tool", nil},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			p := retestPayload(t, tc.tool, "https://app.example.com")
			scan := CommandTierFor("scan", Job{Type: "scan", Tool: tc.tool}, tc.contract)
			retest := CommandTierFor("retest", JobOf("retest", p), tc.contract)
			if scan != TierIntrusive || retest != scan {
				t.Fatalf("detection T%d, retest T%d; want both T2", scan, retest)
			}
			r := g.AdmitContract("retest", p, nil, tc.contract)
			if r == nil || r.Dimension != DimTier {
				t.Fatalf("T2-origin retest under a T1 ceiling: %v, want a tier refusal", r)
			}
			// A T2 grant runs it.
			wide := g
			wide.TierCeiling = TierIntrusive
			if r := wide.AdmitContract("retest", p, nil, tc.contract); r != nil {
				t.Fatalf("T2 grant refused a T2 retest: %v", r)
			}
		})
	}
}

// A retest takes the detection's tier for every tool: never lower, never
// higher than the scan that raised the finding.
func TestCommandTier_RetestEqualsDetection(t *testing.T) {
	for _, tool := range []string{"nuclei", "subfinder", "naabu", "httpx", "katana", "semgrep", "trivy", "gitleaks", "zap"} {
		scan := CommandTierFor("scan", Job{Type: "scan", Tool: tool}, nil)
		retest := CommandTierFor("retest", JobOf("retest", retestPayload(t, tool, "https://app.example.com")), nil)
		if retest != scan {
			t.Errorf("%s: retest T%d, detection T%d", tool, retest, scan)
		}
	}
}

// A New sensor stays at T0 (RFC-052 §5.1): it refuses the retest of a T1
// finding; only a T0 detection's retest reaches it.
func TestAdmit_NewSensorRefusesT1Retest(t *testing.T) {
	g := mustProfile(t, DefaultProfile)
	if g.TrustLevel != TrustNew {
		t.Fatalf("profile default trust %s", g.TrustLevel)
	}
	r := g.AdmitContract("retest", retestPayload(t, "nuclei", "https://app.example.com"), nil, builtinT1)
	if r == nil || r.Dimension != DimTier {
		t.Fatalf("New sensor admitted a T1 retest: %v", r)
	}
	if r := g.Admit("retest", retestPayload(t, "subfinder", "example.com"), nil); r != nil {
		t.Fatalf("New sensor refused a T0 retest: %v", r)
	}
}

// A grant without retest in its job types refuses it (a custom grant an
// administrator narrowed, a collector).
func TestAdmit_RetestNeedsTheJobType(t *testing.T) {
	g := trusted(mustProfile(t, DefaultProfile))
	g.JobTypes = []string{"scan", "validate"}
	if r := g.AdmitContract("retest", retestPayload(t, "nuclei", "https://app.example.com"), nil, builtinT1); r == nil || r.Dimension != DimJobTypes {
		t.Fatalf("grant without retest admitted it: %v", r)
	}
	if r := trusted(mustProfile(t, "collector:tenable-sc")).Admit("retest", retestPayload(t, "nuclei", "https://app.example.com"), nil); r == nil || r.Dimension != DimJobTypes {
		t.Fatalf("collector admitted a retest: %v", r)
	}
}
