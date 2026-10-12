package ingest

import (
	"testing"

	"github.com/openctemio/ctis"
	"github.com/stretchr/testify/require"
)

// SARIF uploads rely on ctis.FromSARIF carrying result.kind and baselineState
// (openctemio/ctis#10, released in ctis v1.3.0). The API used to patch them in
// itself after conversion; this pins the behavior it now depends on.
func TestFromSARIF_CarriesKindAndBaselineState(t *testing.T) {
	sarif := []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"semgrep"}},"results":[
		{"ruleId":"a","message":{"text":"one"}},
		{"ruleId":"b","kind":"notApplicable","baselineState":"unchanged","message":{"text":"two"}},
		{"ruleId":"c","kind":"review","message":{"text":"three"}}
	]}]}`)
	report, err := ctis.FromSARIF(sarif, nil)
	require.NoError(t, err)
	require.Len(t, report.Findings, 3)
	require.Empty(t, report.Findings[0].Kind)
	require.Equal(t, "not_applicable", report.Findings[1].Kind)
	require.Equal(t, "unchanged", report.Findings[1].BaselineState)
	require.Equal(t, "review", report.Findings[2].Kind)
}
