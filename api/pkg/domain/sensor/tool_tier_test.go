package sensor

import (
	"encoding/json"
	"testing"
)

func builtinContract(tier string, implements ...string) *ToolContract {
	return &ToolContract{APIVersion: ToolContractAPIVersion, Tier: tier, Class: "target-scan",
		Origin: ToolOriginBuiltin, Implements: implements}
}

// The platform assigns a job's tier; a tool's contract only ever raises it.
func TestCommandTierFor(t *testing.T) {
	adapter := builtinContract("T1", "scan.ports@1")
	adapter.Origin = ToolOriginAdapter
	sideEffects := builtinContract("T2", "vuln.templates@1")
	sideEffects.Descriptor = json.RawMessage(`{"safety":{"side_effects":["state_change"]}}`)
	unreadable := builtinContract("T1", "vuln.templates@1")
	unreadable.Descriptor = json.RawMessage(`{`)

	cases := []struct {
		name string
		job  Job
		c    *ToolContract
		want int
	}{
		// Unchanged without a contract: the catalog rule (TC12 fallback).
		{"catalog tool, no contract", Job{Tool: "naabu"}, nil, TierActive},
		{"catalog passive tool", Job{Tool: "subfinder"}, nil, TierPassive},
		{"unknown tool, no contract", Job{Tool: "acme-scan"}, nil, TierIntrusive},
		// The capability floor applies; a capability nobody knows fails closed.
		{"capability floor", Job{Tool: "trivy", Capability: "sca.deps@1"}, nil, TierPassive},
		{"unknown capability", Job{Tool: "naabu", Capability: "scan.everything@1"}, nil, TierIntrusive},
		// SECURITY: a declared tier raises; it never lowers the floor.
		{"declared higher tier", Job{Tool: "subfinder"}, builtinContract("T2", "discover.subdomains@1"), TierIntrusive},
		{"declared lower tier ignored", Job{Tool: "naabu"}, builtinContract("T0", "scan.ports@1"), TierActive},
		// SECURITY: an operator-installed tool is unverified: T2.
		{"adapter origin", Job{Tool: "naabu"}, adapter, TierIntrusive},
		// SECURITY: a declared side effect is intrusive (TC16).
		{"side effects", Job{Tool: "nuclei"}, sideEffects, TierIntrusive},
		{"unreadable descriptor", Job{Tool: "nuclei"}, unreadable, TierIntrusive},
		// A built-in tool the catalog does not route: its capabilities' floors.
		{"built-in outside the catalog", Job{Tool: "file-import"}, builtinContract("T0", "sast.code@1"), TierPassive},
		{"built-in without capabilities", Job{Tool: "file-import"}, builtinContract("T0"), TierIntrusive},
		// SECURITY: "builtin" is a sensor claim, honored only for a tool a
		// released sensor compiles in; any other tool claiming it is
		// unverified (T2), catalog-routed name or not.
		{"unknown tool claims builtin", Job{Tool: "acme-builtin"}, builtinContract("T0", "sast.code@1"), TierIntrusive},
		{"catalog tool the sensor does not ship claims builtin", Job{Tool: "zap"}, builtinContract("T0", "dast.web@1"), TierIntrusive},
		// Out-of-band callbacks stay intrusive whatever the contract says.
		{"interactsh", Job{Tool: "nuclei", Interactsh: true}, builtinContract("T1", "vuln.templates@1"), TierIntrusive},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := CommandTierFor("scan", tc.job, tc.c); got != tc.want {
				t.Fatalf("tier T%d, want T%d", got, tc.want)
			}
		})
	}
	if CommandTier("scan", Job{Tool: "naabu"}) != CommandTierFor("scan", Job{Tool: "naabu"}, nil) {
		t.Fatal("CommandTier must equal CommandTierFor without a contract")
	}
}

func TestToolTrust(t *testing.T) {
	if ToolTrust("naabu", nil) != "" || ToolTrust("naabu", builtinContract("T1")) != ToolTrustBuiltin {
		t.Fatal("trust")
	}
	if ToolTrust("Gitleaks", builtinContract("T0")) != ToolTrustBuiltin {
		t.Fatal("a retired name of a built-in tool is the built-in tool")
	}
	// SECURITY: a sensor cannot make its own tool builtin by claiming it.
	if ToolTrust("acme-scan", builtinContract("T1")) != ToolTrustUnverified {
		t.Fatal("an unknown tool claiming builtin is unverified")
	}
	c := builtinContract("T1")
	c.Origin = ToolOriginAdapter
	if ToolTrust("naabu", c) != ToolTrustUnverified {
		t.Fatal("an adapter is unverified")
	}
	c.Origin = ""
	if ToolTrust("naabu", c) != ToolTrustUnverified {
		t.Fatal("an unknown origin is unverified")
	}
}

// The grant refuses a job above its ceiling once the contract raises it.
func TestGrantAdmitContract(t *testing.T) {
	g := Grant{TrustLevel: TrustTrusted, TierCeiling: TierActive}
	payload := json.RawMessage(`{"scanner":"naabu","target":"192.0.2.1","capability":"scan.ports@1"}`)
	if r := g.AdmitContract("scan", payload, nil, builtinContract("T1", "scan.ports@1")); r != nil && r.Dimension == DimTier {
		t.Fatalf("a T1 built-in under a T1 ceiling: %+v", r)
	}
	adapter := builtinContract("T1", "scan.ports@1")
	adapter.Origin = ToolOriginAdapter
	r := g.AdmitContract("scan", payload, nil, adapter)
	if r == nil || r.Dimension != DimTier {
		t.Fatalf("an unverified tool under a T1 ceiling: %+v", r)
	}
	if j := JobOf("scan", payload); j.Capability != "scan.ports@1" || j.Tool != "naabu" {
		t.Fatalf("job %+v", j)
	}
}
