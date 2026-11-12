package ingest

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/openctemio/ctis/v2"

	"github.com/openctemio/openctem/server/pkg/domain/branch"
	"github.com/openctemio/openctem/server/pkg/domain/command"
	"github.com/openctemio/openctem/server/pkg/domain/ingestreport"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/logger"
	protov2 "github.com/openctemio/openctem/server/pkg/sensorproto/v2"
)

// The legacy shape (research/467 F6): an older sensor reports a scanner the
// job budget killed (exit -1) or a tool that gave up (exit 1) as a completed
// command whose report claims full coverage with every target done.
var legacyStoppedResults = map[string]string{
	"exit -1, completed": `{"status":"completed","exit_code":-1,"metadata":{"coverage_type":"full"}}`,
	"exit 1, completed":  `{"status":"completed","exit_code":1}`,
	"partial status":     `{"status":"partial","exit_code":0}`,
	"sensor stopped":     `{"exit_code":0,"stop_reason":"lease_lost"}`,
	"unreadable":         `{"exit_code":`,
}

func branchMD(name string, targets ...ctis.TargetOutcome) ctis.ReportMetadata {
	return ctis.ReportMetadata{CoverageType: ctis.CoverageFull, Branch: &ctis.BranchInfo{Name: name}, Targets: targets}
}

// branchRun is a completed, clean semgrep run with one full report of the
// branch "feature/x" that touched assetID.
func branchRun(t *testing.T, sensorID, assetID shared.ID) *ingestreport.CommandCoverage {
	return &ingestreport.CommandCoverage{
		CommandType: "scan", CommandStatus: "completed", Result: json.RawMessage(`{"status":"completed","exit_code":0}`),
		Reports: []ingestreport.CoverageReport{{Integrity: protov2.IntegritySingle,
			ReportID: "r-1", SensorID: sensorID, State: protov2.StateCompleted, ToolName: "semgrep",
			Header:          coverageHeader(t, "semgrep", branchMD("feature/x")),
			SegmentOutcomes: map[string]ingestreport.SegmentOutcome{"0": {AcceptedFindings: 2}},
			TouchedAssetIDs: []shared.ID{assetID},
		}},
	}
}

func TestRunCleanFor(t *testing.T) {
	if got := runCleanFor("scan", "completed", json.RawMessage(`{"exit_code":0}`)); got != branchSweepEligible {
		t.Fatalf("clean run = %s", got)
	}
	for name, raw := range legacyStoppedResults {
		if got := runCleanFor("scan", "completed", json.RawMessage(raw)); got != branchSweepStopped {
			t.Errorf("%s = %s, want %s", name, got, branchSweepStopped)
		}
	}
	if got := runCleanFor("scan", "completed", json.RawMessage(`{"exit_code":0,"metadata":{"truncated":true}}`)); got != branchSweepTruncated {
		t.Errorf("truncated = %s", got)
	}
	if got := runCleanFor("scan", "failed", nil); got != branchSweepNotCompleted {
		t.Errorf("failed = %s", got)
	}
	if got := runCleanFor("validate", "completed", nil); got != branchSweepNotScan {
		t.Errorf("not a scan = %s", got)
	}
}

func TestDecideRunBranchSweep(t *testing.T) {
	sensorID, assetID := shared.NewID(), shared.NewID()
	second := func(c *ingestreport.CommandCoverage, tool string, md ctis.ReportMetadata) {
		r := c.Reports[0]
		r.ReportID = "r-2"
		r.ToolName = tool
		r.Header = coverageHeader(t, tool, md)
		c.Reports = append(c.Reports, r)
	}
	cases := []struct {
		name    string
		mutate  func(*ingestreport.CommandCoverage)
		why     string
		reports []string
	}{
		{"clean full run sweeps its report", func(*ingestreport.CommandCoverage) {}, branchSweepEligible, []string{"r-1"}},
		{"report failed", func(c *ingestreport.CommandCoverage) { c.Reports[0].State = protov2.StateFailed }, branchSweepReportFailed, nil},
		{"report in flight", func(c *ingestreport.CommandCoverage) { c.Reports[0].State = protov2.StateQueued }, branchSweepReportsPending, nil},
		{"a listed target not done", func(c *ingestreport.CommandCoverage) {
			c.Reports[0].Header = coverageHeader(t, "semgrep", branchMD("feature/x",
				ctis.TargetOutcome{Target: "a", State: ctis.TargetDone}, ctis.TargetOutcome{Target: "b", State: ctis.TargetUnfinished}))
		}, branchSweepEligible, nil},
		{"partial coverage", func(c *ingestreport.CommandCoverage) {
			c.Reports[0].Header = coverageHeader(t, "semgrep", ctis.ReportMetadata{CoverageType: ctis.CoveragePartial, Branch: &ctis.BranchInfo{Name: "feature/x"}})
		}, branchSweepEligible, nil},
		{"integrity unverified", func(c *ingestreport.CommandCoverage) { c.Reports[0].Integrity = "" }, branchSweepEligible, nil},
		{"a segment rejected a finding", func(c *ingestreport.CommandCoverage) {
			c.Reports[0].SegmentOutcomes = map[string]ingestreport.SegmentOutcome{"0": {RejectedFindings: 1}}
		}, branchSweepEligible, nil},
		// The sweep keys on the report id: two reports of one run on the
		// same branch and tool would each mark the other's occurrences gone.
		{"two full reports, same branch and tool, sweep nothing", func(c *ingestreport.CommandCoverage) {
			second(c, "semgrep", branchMD("feature/x"))
		}, branchSweepEligible, nil},
		{"a partial sibling on the same branch and tool also blocks", func(c *ingestreport.CommandCoverage) {
			second(c, "Semgrep", ctis.ReportMetadata{CoverageType: ctis.CoveragePartial, Branch: &ctis.BranchInfo{Name: "feature/x"}})
		}, branchSweepEligible, nil},
		{"another tool on the same branch sweeps on its own", func(c *ingestreport.CommandCoverage) {
			second(c, "gitleaks", branchMD("feature/x"))
		}, branchSweepEligible, []string{"r-1", "r-2"}},
		{"another branch sweeps on its own", func(c *ingestreport.CommandCoverage) {
			second(c, "semgrep", branchMD("main"))
		}, branchSweepEligible, []string{"r-1", "r-2"}},
	}
	for name, raw := range legacyStoppedResults {
		cases = append(cases, struct {
			name    string
			mutate  func(*ingestreport.CommandCoverage)
			why     string
			reports []string
		}{"legacy stopped run, full coverage claimed: " + name, func(c *ingestreport.CommandCoverage) {
			c.Result = json.RawMessage(raw)
		}, branchSweepStopped, nil})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := branchRun(t, sensorID, assetID)
			tc.mutate(c)
			why, got := decideRunBranchSweep(c)
			if why != tc.why {
				t.Fatalf("reason = %s, want %s", why, tc.why)
			}
			ids := make([]string, 0, len(got))
			for _, r := range got {
				ids = append(ids, r.reportID)
			}
			if len(ids) != len(tc.reports) {
				t.Fatalf("reports = %v, want %v", ids, tc.reports)
			}
			for i := range ids {
				if ids[i] != tc.reports[i] {
					t.Fatalf("reports = %v, want %v", ids, tc.reports)
				}
			}
		})
	}
}

// tenantCommands serves commands by id and refuses another tenant's, like
// the tenant-scoped store; leak returns the command whatever the tenant (a
// reader that forgot the tenant filter).
type tenantCommands struct {
	byID map[shared.ID]*command.Command
	leak bool
	err  error
}

func (c tenantCommands) GetByTenantAndID(_ context.Context, tenantID, id shared.ID) (*command.Command, error) {
	if c.err != nil {
		return nil, c.err
	}
	cmd, ok := c.byID[id]
	if !ok || (!c.leak && cmd.TenantID != tenantID) {
		return nil, shared.ErrNotFound
	}
	return cmd, nil
}

// commandRunClean fails closed: a command of another tenant, a lookup
// error, a missing reader or id, and a stopped run are never clean.
func TestCommandRunClean(t *testing.T) {
	tenantA, tenantB := shared.NewID(), shared.NewID()
	clean := &command.Command{ID: shared.NewID(), TenantID: tenantA, Type: command.CommandTypeScan,
		Status: command.CommandStatusCompleted, Result: json.RawMessage(`{"status":"completed","exit_code":0}`)}
	stopped := &command.Command{ID: shared.NewID(), TenantID: tenantA, Type: command.CommandTypeScan,
		Status: command.CommandStatusCompleted, Result: json.RawMessage(`{"status":"completed","exit_code":-1}`)}
	byID := map[shared.ID]*command.Command{clean.ID: clean, stopped.ID: stopped}
	ctx := context.Background()
	svc := &Service{logger: logger.NewNop()}
	if svc.commandRunClean(ctx, tenantA, &clean.ID) {
		t.Fatal("no command reader must not be clean")
	}
	svc.SetCommandReader(tenantCommands{byID: byID})
	if !svc.commandRunClean(ctx, tenantA, &clean.ID) {
		t.Fatal("own clean run must be clean")
	}
	if svc.commandRunClean(ctx, tenantA, nil) {
		t.Fatal("no command id must not be clean")
	}
	if svc.commandRunClean(ctx, tenantA, &stopped.ID) {
		t.Fatal("a run that exited -1 must not be clean")
	}
	if svc.commandRunClean(ctx, tenantB, &clean.ID) {
		t.Fatal("cross-tenant: tenant B named tenant A's clean command and it counted")
	}
	// Even a reader that returns another tenant's row is caught.
	svc.SetCommandReader(tenantCommands{byID: byID, leak: true})
	if svc.commandRunClean(ctx, tenantB, &clean.ID) {
		t.Fatal("cross-tenant: a leaked row of tenant A counted for tenant B")
	}
	svc.SetCommandReader(tenantCommands{err: errors.New("db down")})
	if svc.commandRunClean(ctx, tenantA, &clean.ID) {
		t.Fatal("a lookup error must not be clean")
	}
}

// The v1 per-branch sweep (Ingest): a report bound to a command sweeps only
// when that command already completed by itself, and never when it lists an
// unfinished target.
func TestV1RunMaySweepBranch(t *testing.T) {
	tenantID := shared.NewID()
	ctx := context.Background()
	mk := func(status command.CommandStatus, result string) *command.Command {
		return &command.Command{ID: shared.NewID(), TenantID: tenantID, Type: command.CommandTypeScan, Status: status, Result: json.RawMessage(result)}
	}
	clean := mk(command.CommandStatusCompleted, `{"exit_code":0}`)
	running := mk(command.CommandStatusRunning, ``)
	byID := map[shared.ID]*command.Command{clean.ID: clean, running.ID: running}
	stoppedIDs := map[string]shared.ID{}
	for name, raw := range legacyStoppedResults {
		c := mk(command.CommandStatusCompleted, raw)
		byID[c.ID] = c
		stoppedIDs[name] = c.ID
	}
	svc := &Service{logger: logger.NewNop()}
	svc.SetCommandReader(tenantCommands{byID: byID})
	full := branchMD("feature/x", ctis.TargetOutcome{Target: "a", State: ctis.TargetDone})

	if !svc.v1RunMaySweepBranch(ctx, tenantID, Binding{Kind: BindingCommand, CommandID: &clean.ID}, full) {
		t.Fatal("a report of a clean completed run must sweep")
	}
	if !svc.v1RunMaySweepBranch(ctx, tenantID, Binding{Kind: BindingUnsolicited}, full) {
		t.Fatal("an unbound report is decided by its own metadata")
	}
	for name, id := range stoppedIDs {
		if svc.v1RunMaySweepBranch(ctx, tenantID, Binding{Kind: BindingCommand, CommandID: &id}, full) {
			t.Errorf("legacy stopped run (%s) with full coverage claimed swept", name)
		}
	}
	if svc.v1RunMaySweepBranch(ctx, tenantID, Binding{Kind: BindingCommand, CommandID: &running.ID}, full) {
		t.Error("a report of a run not completed yet swept")
	}
	other := shared.NewID()
	if svc.v1RunMaySweepBranch(ctx, other, Binding{Kind: BindingCommand, CommandID: &clean.ID}, full) {
		t.Error("cross-tenant: a report naming another tenant's clean command swept")
	}
	unfinished := branchMD("feature/x", ctis.TargetOutcome{Target: "a", State: ctis.TargetDone}, ctis.TargetOutcome{Target: "b", State: ctis.TargetUnfinished})
	if svc.v1RunMaySweepBranch(ctx, tenantID, Binding{Kind: BindingUnsolicited}, unfinished) {
		t.Error("a report listing an unfinished target swept")
	}
}

// CommitV2Report sweeps only unbound reports; a bound report waits for its
// run, whatever its own metadata claims.
func TestCommitSweepsBranch(t *testing.T) {
	cmdID := shared.NewID()
	full := branchMD("feature/x")
	if !commitSweepsBranch(Provenance{}, full) {
		t.Fatal("an unbound full report of a branch must sweep at commit")
	}
	if commitSweepsBranch(Provenance{CommandID: &cmdID}, full) {
		t.Fatal("a bound report must not sweep at commit (its run may have been killed)")
	}
	if commitSweepsBranch(Provenance{}, branchMD("feature/x", ctis.TargetOutcome{Target: "a", State: ctis.TargetFailed})) {
		t.Fatal("a report listing a failed target must not sweep")
	}
	if commitSweepsBranch(Provenance{}, ctis.ReportMetadata{CoverageType: ctis.CoverageFull}) {
		t.Fatal("a report without a branch must not sweep")
	}
}

// sweepRecorder records the branch sweeps a coverage evaluation runs.
type sweepRecorder struct {
	*coverageFindingRepo
	swept []string // report ids
}

func (r *sweepRecorder) AutoResolveStaleBranchOccurrences(_ context.Context, _, _ shared.ID, _, scanID string) (int64, error) {
	r.swept = append(r.swept, scanID)
	return 1, nil
}

// branchByName finds every branch it is asked for.
type branchByName struct{ branch.Repository }

func (branchByName) GetByName(_ context.Context, repoID shared.ID, name string) (*branch.Branch, error) {
	return branch.NewBranch(repoID, name, branch.TypeFeature)
}

// The run-level sweep (EvaluateCommandCoverage): a clean run sweeps its
// branch; the legacy shape of a stopped run, full coverage claimed, sweeps
// nothing in any coverage mode.
func TestEvaluateCommandCoverage_BranchSweepOnlyFromACleanRun(t *testing.T) {
	setup := func(t *testing.T, mode CoverageAutoResolveMode, result string) *sweepRecorder {
		t.Helper()
		svc, repo := coverageService(t, mode, []string{"semgrep"})
		repo.cov.Reports[0].ToolName = "semgrep"
		repo.cov.Reports[0].Header = coverageHeader(t, "semgrep", branchMD("feature/x"))
		repo.cov.Result = json.RawMessage(result)
		rec := &sweepRecorder{coverageFindingRepo: repo}
		svc.findingRepo = rec
		svc.branchRepo = branchByName{}
		svc.EvaluateCommandCoverage(context.Background(), shared.NewID(), shared.NewID())
		return rec
	}
	for _, mode := range []CoverageAutoResolveMode{CoverageAutoResolveOff, CoverageAutoResolveDryRun, CoverageAutoResolveEnforce} {
		if rec := setup(t, mode, `{"status":"completed","exit_code":0}`); len(rec.swept) != 1 || rec.swept[0] != "r-1" {
			t.Errorf("%s: clean run swept %v, want [r-1]", mode, rec.swept)
		}
		for name, raw := range legacyStoppedResults {
			if rec := setup(t, mode, raw); len(rec.swept) != 0 {
				t.Errorf("%s: legacy stopped run (%s) with full coverage claimed swept %v", mode, name, rec.swept)
			}
		}
	}
}
