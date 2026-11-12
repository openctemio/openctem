package ingest

import (
	"testing"
	"time"

	"github.com/openctemio/ctis/v2"

	"github.com/openctemio/openctem/server/pkg/domain/compliancecheck"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/vulnerability"
)

func nessusCheck(kind, native string) ctis.Finding {
	return ctis.Finding{
		Type: ctis.FindingTypeCompliance, Kind: kind, Severity: ctis.SeverityHigh, Title: "1.1.1 Ensure x",
		RuleID: "21157:1.1.1 Ensure x", Message: "check message",
		Compliance: &ctis.ComplianceDetails{Framework: ctis.FrameworkCIS, FrameworkVersion: "2.0.0", ControlID: "1.1.1", ControlName: "1.1.1 Ensure x"},
		SourceExtra: map[string]string{
			"compliance-benchmark-name": "CIS Example Linux", "compliance-benchmark-version": "1.0.0",
			"compliance-benchmark-profile": "Level 2 - Server", "compliance-result": native,
			"compliance-policy-value": "1", "compliance-audit-file": "CIS_Example_L2.audit",
		},
		EvidenceItems: []ctis.EvidenceItem{{Kind: "raw_text", Label: "compliance-actual-value", Text: "0"}},
	}
}

func TestComplianceResultOf(t *testing.T) {
	cases := []struct {
		name string
		f    ctis.Finding
		want compliancecheck.Result
		ok   bool
	}{
		{"pass", nessusCheck("pass", "PASSED"), compliancecheck.ResultPass, true},
		{"fail", nessusCheck("fail", "FAILED"), compliancecheck.ResultFail, true},
		{"warning", nessusCheck("review", "WARNING"), compliancecheck.ResultManual, true},
		{"skipped", nessusCheck("not_applicable", "SKIPPED"), compliancecheck.ResultNotApplicable, true},
		// The importer folded ERROR into not_applicable: the native word keeps it.
		{"error, native word", nessusCheck("not_applicable", "ERROR"), compliancecheck.ResultError, true},
		{"vulnerability", ctis.Finding{Type: ctis.FindingTypeVulnerability, Kind: "pass"}, "", false},
	}
	withOutcome := nessusCheck("not_applicable", "")
	withOutcome.Extensions.Set(ctis.OpenCTEMNamespace, complianceOutcomeKey, "error")
	cases = append(cases, struct {
		name string
		f    ctis.Finding
		want compliancecheck.Result
		ok   bool
	}{"error, importer outcome", withOutcome, compliancecheck.ResultError, true})
	for _, c := range cases {
		got, ok := complianceResultOf(&c.f)
		if got != c.want || ok != c.ok {
			t.Errorf("%s: %q, %v; want %q, %v", c.name, got, ok, c.want, c.ok)
		}
	}
}

func TestComplianceObservation_NessusCheck(t *testing.T) {
	f := nessusCheck("fail", "FAILED")
	asset := shared.NewID()
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	o, ok := complianceObservation(&f, asset, "fp-1", "nessus", at)
	if !ok || !o.Valid() {
		t.Fatalf("observation = %+v, %v", o, ok)
	}
	if o.BenchmarkKey != "cis-example-linux" || o.BenchmarkName != "CIS Example Linux" || o.BenchmarkVersion != "1.0.0" {
		t.Errorf("benchmark = %q %q %q", o.BenchmarkKey, o.BenchmarkName, o.BenchmarkVersion)
	}
	if o.ControlID != "1.1.1" || o.Level != vulnerability.ComplianceLevel2 || o.Framework != "cis" {
		t.Errorf("control = %q level = %d framework = %q", o.ControlID, o.Level, o.Framework)
	}
	if o.Evidence.Actual != "0" || o.Evidence.Expected != "1" || o.Evidence.AuditFile != "CIS_Example_L2.audit" || o.Evidence.Message != "check message" {
		t.Errorf("evidence = %+v", o.Evidence)
	}
	if o.ScannerSeverity != "high" || o.ToolName != "nessus" || o.Fingerprint != "fp-1" || !o.ObservedAt.Equal(at) {
		t.Errorf("observation = %+v", o)
	}
}

func TestComplianceObservation_GenericProducer(t *testing.T) {
	// No source extra: the framework names the benchmark, the rule the control.
	f := ctis.Finding{Type: ctis.FindingTypeCompliance, Kind: "pass", RuleID: "kube-1.2", Title: "API server flag",
		Compliance: &ctis.ComplianceDetails{Framework: ctis.FrameworkCIS, FrameworkVersion: "1.9"}}
	o, ok := complianceObservation(&f, shared.NewID(), "fp", "kube-bench", time.Now())
	if !ok || o.BenchmarkKey != "cis" || o.BenchmarkVersion != "1.9" || o.ControlID != "kube-1.2" || o.ControlName != "API server flag" {
		t.Fatalf("observation = %+v", o)
	}
	if o.Level != vulnerability.ComplianceLevelUnknown {
		t.Fatalf("level = %d", o.Level)
	}
}
