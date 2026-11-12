package ingest

// Compliance check state at ingest (docs/architecture/compliance-checks.md).
//
// Every compliance result of a report (finding type compliance) is recorded
// as the latest state of its control on its asset, with its evidence, and
// every change is kept as history. Only a failed result and a warning keep a
// finding: a pass, a not-applicable and an error are states only. A pass
// still resolves the open failure of the same check through the closing
// paths (an upload in findingimport, a bound scan in Service).

import (
	"context"
	"strings"
	"time"

	"github.com/openctemio/ctis/v2"

	"github.com/openctemio/openctem/server/pkg/domain/compliancecheck"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/vulnerability"
)

// ComplianceCheckRecorder stores compliance check states
// (postgres.ComplianceCheckRepository).
type ComplianceCheckRecorder = compliancecheck.Recorder

// SetComplianceCheckRecorder wires the compliance check state store. Without
// it no state is kept (the findings are unchanged).
func (p *FindingProcessor) SetComplianceCheckRecorder(r ComplianceCheckRecorder) {
	p.complianceChecks = r
}

// SetComplianceCheckRecorder wires the compliance check state store.
func (s *Service) SetComplianceCheckRecorder(r ComplianceCheckRecorder) {
	s.findingProcessor.SetComplianceCheckRecorder(r)
}

// complianceOutcomeKey is the io.openctem extension member in which an
// importer says why a not_applicable result was not evaluated (error,
// skipped).
const complianceOutcomeKey = "compliance_outcome"

// Source-extra keys a benchmark's identity and level are read from (the
// Nessus importer's; other producers use the compliance block).
var (
	benchmarkNameKeys    = []string{"compliance-benchmark-name", "benchmark_name", "benchmark"}
	benchmarkVersionKeys = []string{"compliance-benchmark-version", "benchmark_version"}
	benchmarkLevelKeys   = []string{"compliance-benchmark-profile", "benchmark_profile", "profile", "level"}
)

func firstExtra(f *ctis.Finding, keys []string) string {
	for _, k := range keys {
		if v := strings.TrimSpace(f.SourceExtra[k]); v != "" {
			return v
		}
	}
	return ""
}

// complianceResultOf is the result of a compliance finding; ok is false for
// a finding that is no compliance result.
func complianceResultOf(f *ctis.Finding) (compliancecheck.Result, bool) {
	if !isComplianceResult(f) {
		return "", false
	}
	outcome := ""
	if v, ok := f.Extensions.Get(ctis.OpenCTEMNamespace, complianceOutcomeKey); ok {
		outcome, _ = v.(string)
	}
	return compliancecheck.ResultOf(f.Kind, outcome, f.SourceExtra["compliance-result"])
}

// isComplianceResult reports whether f is a benchmark check result: its
// type says so, or it has no type and names a framework (inferFindingType).
func isComplianceResult(f *ctis.Finding) bool {
	if f == nil {
		return false
	}
	return f.Type == ctis.FindingTypeCompliance ||
		(f.Type == "" && f.Compliance != nil && f.Compliance.Framework != "")
}

// complianceLevelOf reads the benchmark level of a compliance finding.
func complianceLevelOf(f *ctis.Finding) vulnerability.ComplianceLevel {
	return vulnerability.ParseComplianceLevel(firstExtra(f, benchmarkLevelKeys))
}

// complianceEvidenceOf is what the check saw: the actual value (the raw text
// item the importer keeps, else the misconfiguration block), the expected
// value, the scanner's message and the audit file.
func complianceEvidenceOf(f *ctis.Finding) compliancecheck.Evidence {
	var e compliancecheck.Evidence
	for _, it := range f.EvidenceItems {
		if it.Text != "" && (it.Label == "compliance-actual-value" || it.Kind == "raw_text") {
			e.Actual = it.Text
			break
		}
	}
	if m := f.Misconfiguration; m != nil {
		if e.Actual == "" {
			e.Actual = m.Actual
		}
		e.Expected = m.Expected
	}
	if v := f.SourceExtra["compliance-policy-value"]; v != "" {
		e.Expected = v
	}
	e.Message = firstNonEmptyString(f.SourceExtra["compliance-error"], f.Message)
	e.AuditFile = f.SourceExtra["compliance-audit-file"]
	return e
}

func firstNonEmptyString(v ...string) string {
	for _, s := range v {
		if strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}

// complianceObservation builds the state observation of a compliance
// finding on its asset. ok is false when it is no compliance result.
func complianceObservation(f *ctis.Finding, assetID shared.ID, fingerprint, tool string, observedAt time.Time) (compliancecheck.Observation, bool) {
	result, ok := complianceResultOf(f)
	if !ok {
		return compliancecheck.Observation{}, false
	}
	o := compliancecheck.Observation{
		AssetID: assetID, Fingerprint: fingerprint, Result: result, Level: complianceLevelOf(f),
		ScannerSeverity: string(f.Severity), Evidence: complianceEvidenceOf(f), ToolName: tool, ObservedAt: observedAt,
		BenchmarkName: firstExtra(f, benchmarkNameKeys), BenchmarkVersion: firstExtra(f, benchmarkVersionKeys),
	}
	if c := f.Compliance; c != nil {
		o.Framework = string(c.Framework)
		o.ControlID = strings.TrimSpace(c.ControlID)
		o.ControlName = strings.TrimSpace(c.ControlName)
		if o.BenchmarkVersion == "" {
			o.BenchmarkVersion = c.FrameworkVersion
		}
	}
	if o.BenchmarkName == "" {
		o.BenchmarkName = firstNonEmptyString(o.Framework, tool)
	}
	o.BenchmarkKey = compliancecheck.BenchmarkKey(o.BenchmarkName)
	if o.ControlID == "" {
		o.ControlID = strings.TrimSpace(f.RuleID)
	}
	if o.ControlName == "" {
		o.ControlName = f.Title
	}
	return o, true
}

// recordComplianceChecks stores the batch's compliance states. Best effort:
// a failure is logged and never fails the ingest (the findings are kept).
func (p *FindingProcessor) recordComplianceChecks(ctx context.Context, tenantID shared.ID, obs []compliancecheck.Observation) {
	if p.complianceChecks == nil || len(obs) == 0 {
		return
	}
	st, err := p.complianceChecks.Record(ctx, tenantID, compliancecheck.SourceIngest, obs)
	if err != nil {
		p.logger.Warn("failed to record compliance check states", "error", err, "count", len(obs))
		return
	}
	if st.Invalid > 0 {
		p.logger.Debug("compliance check results without an asset, benchmark or control", "count", st.Invalid)
	}
}

// toolNameOf is the tool that reported f: its own tool, else the report's.
func toolNameOf(report *ctis.Report, f *ctis.Finding) string {
	if f != nil && f.Tool != nil && strings.TrimSpace(f.Tool.Name) != "" {
		return strings.TrimSpace(f.Tool.Name)
	}
	if report != nil && report.Tool != nil {
		return strings.TrimSpace(report.Tool.Name)
	}
	return ""
}
