package ingest

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/ctis"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openctemio/openctem/api/pkg/domain/branch"
	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// sourceResolveRepo records source-asserted resolve calls.
type sourceResolveRepo struct {
	stubFindingRepository
	calls   int
	dryRuns []bool
	tool    string
	items   []vulnerability.SourceMitigation
	tenant  shared.ID
	match   []shared.ID
}

func (r *sourceResolveRepo) ResolveSourceMitigated(_ context.Context, tenantID shared.ID, tool string,
	items []vulnerability.SourceMitigation, dryRun bool) ([]shared.ID, error) {
	r.calls++
	r.tenant, r.tool, r.items = tenantID, tool, items
	r.dryRuns = append(r.dryRuns, dryRun)
	return r.match, nil
}

func tenableReport(mitigated bool) *ctis.Report {
	open := ctis.Finding{Type: ctis.FindingTypeVulnerability, Title: "OpenSSH", Severity: ctis.SeverityHigh,
		RuleID: "187201", AssetRef: "host-10.0.0.5",
		Vulnerability: &ctis.VulnerabilityDetails{CVEID: "CVE-2024-6387", CVEIDs: []string{"CVE-2024-6387"}},
		Network:       &ctis.NetworkLocation{Host: "10.0.0.5", Port: 22, Protocol: "tcp"},
		Properties:    ctis.Properties{"tenable_state": "open"}}
	findings := []ctis.Finding{open}
	if mitigated {
		m := open
		m.RuleID = "11111"
		m.Vulnerability = &ctis.VulnerabilityDetails{CVEID: "CVE-2023-0001", CVEIDs: []string{"CVE-2023-0001"}}
		m.Status = ctis.FindingStatusResolved
		m.Properties = ctis.Properties{"tenable_state": "mitigated", "tenable_last_mitigated": "2026-10-01T08:00:00Z"}
		findings = append(findings, m)
	}
	return &ctis.Report{Version: "1.0", Tool: &ctis.Tool{Name: "tenable_sc"}, Findings: findings}
}

func runTenable(t *testing.T, mode SourceResolveMode, scope *alterScope, report *ctis.Report, repo *sourceResolveRepo) *Output {
	t.Helper()
	tenantID := shared.NewID()
	p := NewFindingProcessor(repo, nil, nil, logger.NewNop())
	p.sourceResolveMode = mode
	out := &Output{}
	err := p.processBatch(context.Background(), newTestSensor(t, tenantID), tenantID, report,
		map[string]shared.ID{"host-10.0.0.5": shared.NewID()}, branch.BranchTypeRules{}, out, map[string]shared.ID{}, false, scope)
	require.NoError(t, err)
	return out
}

// boundScope is the scope of a report bound to the tenant's Tenable sync.
func boundScope() *alterScope {
	return newAlterScope(Binding{Kind: BindingCommand, Tool: "tenable_sc", CommandType: command.CommandTypeConnectorSync})
}

// A report may resolve on its source's say-so only for a connector command
// of the same tool, and a connector scan only on the assets it may change
// (sensor → platform review, M12).
func TestSourceResolve_OnlyTheCommandsConnectorTool(t *testing.T) {
	for name, scope := range map[string]*alterScope{
		"a command naming no tool (validate)": newAlterScope(Binding{Kind: BindingCommand, CommandType: command.CommandTypeValidate}),
		"a scan command of the same tool":     newAlterScope(Binding{Kind: BindingCommand, Tool: "tenable_sc", CommandType: command.CommandTypeScan}),
		"a connector command of another tool": newAlterScope(Binding{Kind: BindingCommand, Tool: "other_connector", CommandType: command.CommandTypeConnectorSync}),
	} {
		t.Run(name, func(t *testing.T) {
			repo := &sourceResolveRepo{match: []shared.ID{shared.NewID()}}
			out := runTenable(t, SourceResolveEnforce, scope, tenableReport(true), repo)
			assert.Equal(t, 0, repo.calls)
			assert.Equal(t, 0, out.FindingsSourceResolved)
		})
	}

	// A connector scan resolves only on assets inside its scope: the asset
	// of this report was neither created by it nor covered by a target.
	repo := &sourceResolveRepo{match: []shared.ID{shared.NewID()}}
	scanScope := newAlterScope(Binding{Kind: BindingCommand, Tool: "tenable_sc", CommandType: command.CommandTypeConnectorScan,
		Targets: []string{"203.0.113.0/24"}})
	runTenable(t, SourceResolveEnforce, scanScope, tenableReport(true), repo)
	assert.Equal(t, 0, repo.calls, "an asset outside the connector scan's scope is not resolved")
}

func TestSourceResolve_MitigatedRowIsNotASighting(t *testing.T) {
	repo := &sourceResolveRepo{match: []shared.ID{shared.NewID()}}
	out := runTenable(t, SourceResolveEnforce, boundScope(), tenableReport(true), repo)
	require.Len(t, repo.created, 1, "only the open row is stored; the mitigated row creates nothing")
	assert.Equal(t, "187201", repo.created[0].RuleID())
	assert.Equal(t, 1, out.FindingsSourceMitigated)
	assert.Equal(t, 1, out.FindingsSourceResolved)
	require.Equal(t, 1, repo.calls)
	assert.Equal(t, []bool{false}, repo.dryRuns)
	assert.Equal(t, "tenable_sc", repo.tool)
	require.Len(t, repo.items, 1)
	assert.Equal(t, time.Date(2026, 10, 1, 8, 0, 0, 0, time.UTC), repo.items[0].MitigatedAt)
	assert.NotEmpty(t, repo.items[0].Fingerprint, "matched by the server identity, not the sensor fingerprint")
}

func TestSourceResolve_DryRunIsTheDefault(t *testing.T) {
	repo := &sourceResolveRepo{match: []shared.ID{shared.NewID()}}
	out := runTenable(t, "", boundScope(), tenableReport(true), repo)
	assert.Equal(t, []bool{true}, repo.dryRuns)
	assert.Equal(t, 0, out.FindingsSourceResolved)
	assert.Equal(t, 1, out.FindingsSourceWouldResolve)
}

func TestSourceResolve_OffAndUnboundResolveNothing(t *testing.T) {
	repo := &sourceResolveRepo{}
	out := runTenable(t, SourceResolveOff, boundScope(), tenableReport(true), repo)
	assert.Equal(t, 0, repo.calls)
	assert.Equal(t, 1, out.FindingsSourceMitigated)
	assert.Len(t, repo.created, 1, "a mitigated row is never a sighting, even when resolve is off")

	repo = &sourceResolveRepo{}
	runTenable(t, SourceResolveEnforce, newAlterScope(Binding{Kind: BindingUnsolicited}), tenableReport(true), repo)
	assert.Equal(t, 0, repo.calls, "an unsolicited report never resolves on a source's say-so")

	repo = &sourceResolveRepo{}
	runTenable(t, SourceResolveEnforce, fullScope(), tenableReport(true), repo)
	assert.Equal(t, 0, repo.calls, "only command-bound reports resolve")
}

func TestSourceResolve_OtherToolsAreUnaffected(t *testing.T) {
	report := tenableReport(true)
	report.Tool.Name = "nuclei"
	repo := &sourceResolveRepo{}
	out := runTenable(t, SourceResolveEnforce, boundScope(), report, repo)
	assert.Equal(t, 0, repo.calls)
	assert.Equal(t, 0, out.FindingsSourceMitigated)
	assert.Len(t, repo.created, 2, "another tool's resolved-status finding is ingested as before")
}

func TestSourceResolve_OnlyMitigatedRows(t *testing.T) {
	repo := &sourceResolveRepo{}
	out := runTenable(t, SourceResolveEnforce, boundScope(), tenableReport(false), repo)
	assert.Equal(t, 0, repo.calls)
	assert.Equal(t, 0, out.FindingsSourceMitigated)
	assert.Len(t, repo.created, 1)
}

func TestParseSourceResolveMode(t *testing.T) {
	assert.Equal(t, SourceResolveOff, ParseSourceResolveMode("OFF"))
	assert.Equal(t, SourceResolveEnforce, ParseSourceResolveMode(" enforce "))
	assert.Equal(t, SourceResolveDryRun, ParseSourceResolveMode("yes please"))
	assert.Equal(t, SourceResolveDryRun, ParseSourceResolveMode(""))
}

func TestMitigatedAt(t *testing.T) {
	now := time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC)
	f := &ctis.Finding{Properties: ctis.Properties{"tenable_last_mitigated": "2027-01-01T00:00:00Z"}}
	assert.Equal(t, now, mitigatedAt(f, now), "never in the future")
	seen := now.Add(-time.Hour)
	assert.Equal(t, seen, mitigatedAt(&ctis.Finding{LastSeenAt: &seen}, now))
	assert.Equal(t, now, mitigatedAt(&ctis.Finding{}, now))
}
