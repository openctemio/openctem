package remediation

import "testing"

func TestDeriveKey_ComplianceControl(t *testing.T) {
	in := KeyInput{Source: "va", FindingType: "compliance", BenchmarkKey: "cis-example-linux", BenchmarkName: "CIS Example Linux",
		ControlID: "1.1.1", ControlName: "Ensure x is disabled", SolutionText: "Upgrade openssl to 3.0.8 (CVE-2023-0001)",
		PackageName: "openssl", FixedVersions: []string{"3.0.8"}, InstalledVersion: "3.0.1"}
	key, title, ok := DeriveKey(in)
	if !ok || key != "control:cis-example-linux:1.1.1" {
		t.Fatalf("key = %q, %v", key, ok)
	}
	if title != "CIS Example Linux, 1.1.1 Ensure x is disabled" {
		t.Fatalf("title = %q", title)
	}
	if KeyKind(key) != KindControl || KeyConfidence(key) != 1.0 {
		t.Fatalf("kind %q confidence %v", KeyKind(key), KeyConfidence(key))
	}
	spec := FixSpecForKey("control:cis-example-linux:a~b:c")
	if spec["benchmark"] != "cis-example-linux" || spec["control"] != "a/b:c" {
		t.Fatalf("fix spec = %v", spec)
	}
}

// A compliance finding never joins a package or solution group, even with
// package data or a specific solution text, and without a control it has no
// key at all.
func TestDeriveKey_ComplianceNeverMixes(t *testing.T) {
	in := KeyInput{Source: "va", FindingType: "compliance", SolutionText: "Upgrade openssl to 3.0.8 (CVE-2023-0001)",
		PackageName: "openssl", FixedVersions: []string{"3.0.8"}, InstalledVersion: "3.0.1"}
	if key, _, ok := DeriveKey(in); ok {
		t.Fatalf("compliance finding without a control got %q", key)
	}
	// A vulnerability with the same data keeps its package key.
	in.FindingType = "vulnerability"
	if key, _, ok := DeriveKey(in); !ok || KeyKind(key) != KindUpgrade {
		t.Fatalf("vulnerability key = %q, %v", key, ok)
	}
	// Control data on a vulnerability is ignored.
	in.BenchmarkKey, in.ControlID = "cis-x", "1"
	if key, _, _ := DeriveKey(in); KeyKind(key) == KindControl {
		t.Fatalf("vulnerability got a control key %q", key)
	}
}
