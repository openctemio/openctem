package ingest

import (
	"testing"

	"github.com/openctemio/ctis"
	"github.com/stretchr/testify/require"
)

// ctis.FromSARIF does not read a result's kind or baselineState, so a SARIF
// upload never stored them, even though the CTIS ingest path (and the
// findings columns) support both. applySARIFResultFields copies them onto the
// converted findings, which FromSARIF emits one per runs[0].results[i] as
// "finding-<i+1>".
func TestApplySARIFResultFields_CopiesKindAndBaselineState(t *testing.T) {
	sarif := []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"semgrep"}},"results":[
		{"ruleId":"a","message":{"text":"one"}},
		{"ruleId":"b","kind":"notApplicable","baselineState":"unchanged","message":{"text":"two"}},
		{"ruleId":"c","kind":"review","message":{"text":"three"}}
	]}]}`)
	report, err := ctis.FromSARIF(sarif, nil)
	require.NoError(t, err)
	require.Len(t, report.Findings, 3)

	applySARIFResultFields(report, sarif)

	require.Empty(t, report.Findings[0].Kind)
	require.Equal(t, "notApplicable", report.Findings[1].Kind) // normalized to not_applicable at buildFinding
	require.Equal(t, "unchanged", report.Findings[1].BaselineState)
	require.Equal(t, "review", report.Findings[2].Kind)
}

// A malformed or mismatched document must leave the report untouched.
func TestApplySARIFResultFields_IgnoresMismatch(t *testing.T) {
	report := &ctis.Report{Findings: []ctis.Finding{{ID: "finding-1"}}}
	applySARIFResultFields(report, []byte(`not json`))
	require.Empty(t, report.Findings[0].Kind)

	applySARIFResultFields(report, []byte(`{"runs":[{"results":[{"kind":"fail"},{"kind":"pass"}]}]}`))
	require.Empty(t, report.Findings[0].Kind, "result count differs from finding count: do not guess the mapping")
}
