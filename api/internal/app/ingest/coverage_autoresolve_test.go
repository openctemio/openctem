package ingest

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/ingestreport"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
)

func coverageHeader(t *testing.T, tool string, md ctis.ReportMetadata) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(V2Header{Tool: &ctis.Tool{Name: tool}, Metadata: md})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// completedRun is a completed scan command with one completed nuclei report
// that touched one asset.
func completedRun(t *testing.T, sensorID, assetID shared.ID) *ingestreport.CommandCoverage {
	return &ingestreport.CommandCoverage{
		CommandType: "scan", CommandStatus: "completed", Result: json.RawMessage(`{"exit_code":0}`),
		ProfileID: "p-1",
		Reports: []ingestreport.CoverageReport{{
			ReportID: "r-1", SensorID: sensorID, State: protov2.StateCompleted, ToolName: "nuclei",
			Header:          coverageHeader(t, "nuclei", ctis.ReportMetadata{CoverageType: "full"}),
			SegmentOutcomes: map[string]ingestreport.SegmentOutcome{"0": {AcceptedFindings: 3}},
			TouchedAssetIDs: []shared.ID{assetID},
		}},
	}
}

func TestDecideCoverage(t *testing.T) {
	sensorID, assetID := shared.NewID(), shared.NewID()
	five := 5
	cases := []struct {
		name   string
		mutate func(*ingestreport.CommandCoverage)
		want   string
	}{
		{"completed full run", func(*ingestreport.CommandCoverage) {}, coverageEligible},
		{"explicit full coverage, any case", func(c *ingestreport.CommandCoverage) {
			c.Reports[0].Header = coverageHeader(t, "nuclei", ctis.ReportMetadata{CoverageType: " Full "})
		}, coverageEligible},
		// An older sensor sends no coverage_type. Absent is not full (CTIS
		// spec 4.5): such a run closes nothing.
		{"coverage not declared", func(c *ingestreport.CommandCoverage) {
			c.Reports[0].Header = coverageHeader(t, "nuclei", ctis.ReportMetadata{})
		}, coverageUndeclared},
		{"no header at all", func(c *ingestreport.CommandCoverage) {
			c.Reports[0].Header = nil
		}, coverageUndeclared},
		{"one of two reports undeclared", func(c *ingestreport.CommandCoverage) {
			second := c.Reports[0]
			second.ReportID = "r-2"
			second.Header = coverageHeader(t, "nuclei", ctis.ReportMetadata{})
			c.Reports = append(c.Reports, second)
		}, coverageUndeclared},
		{"not a scan command", func(c *ingestreport.CommandCoverage) { c.CommandType = "validate" }, coverageNotScanCommand},
		{"a Tenable.sc scan through the connector", func(c *ingestreport.CommandCoverage) {
			c.CommandType = "connector_scan"
			c.Reports[0].ToolName = "tenable_sc"
			c.Reports[0].Header = coverageHeader(t, "tenable_sc", ctis.ReportMetadata{CoverageType: "full"})
		}, coverageEligible},
		{"a connector pull never resolves by absence", func(c *ingestreport.CommandCoverage) {
			c.CommandType = "connector_sync"
		}, coverageNotScanCommand},
		{"a connector scan that did not finish", func(c *ingestreport.CommandCoverage) {
			c.CommandType = "connector_scan"
			c.Reports[0].Header = coverageHeader(t, "tenable_sc", ctis.ReportMetadata{CoverageType: "partial"})
		}, coveragePartial},
		{"command failed", func(c *ingestreport.CommandCoverage) { c.CommandStatus = "failed" }, coverageCommandNotCompleted},
		{"command canceled", func(c *ingestreport.CommandCoverage) { c.CommandStatus = "canceled" }, coverageCommandNotCompleted},
		{"command expired", func(c *ingestreport.CommandCoverage) { c.CommandStatus = "expired" }, coverageCommandNotCompleted},
		{"command still running", func(c *ingestreport.CommandCoverage) { c.CommandStatus = "running" }, coverageCommandNotCompleted},
		{"scanner exited non-zero", func(c *ingestreport.CommandCoverage) {
			b, _ := json.Marshal(map[string]any{"exit_code": five})
			c.Result = b
		}, coverageNonZeroExit},
		{"no report filed", func(c *ingestreport.CommandCoverage) { c.Reports = nil }, coverageNoReports},
		{"report still processing", func(c *ingestreport.CommandCoverage) { c.Reports[0].State = protov2.StateProcessing }, coverageReportsPending},
		{"report failed", func(c *ingestreport.CommandCoverage) { c.Reports[0].State = protov2.StateFailed }, coverageReportNotCompleted},
		{"report expired", func(c *ingestreport.CommandCoverage) { c.Reports[0].State = protov2.StateExpired }, coverageReportNotCompleted},
		{"rejected findings", func(c *ingestreport.CommandCoverage) {
			c.Reports[0].SegmentOutcomes["1"] = ingestreport.SegmentOutcome{RejectedFindings: 1}
		}, coverageRejectedItems},
		{"quarantined assets", func(c *ingestreport.CommandCoverage) {
			c.Reports[0].SegmentOutcomes["1"] = ingestreport.SegmentOutcome{QuarantinedAssets: 1}
		}, coverageRejectedItems},
		{"partial coverage", func(c *ingestreport.CommandCoverage) {
			c.Reports[0].Header = coverageHeader(t, "nuclei", ctis.ReportMetadata{CoverageType: "partial"})
		}, coveragePartial},
		{"incremental coverage", func(c *ingestreport.CommandCoverage) {
			c.Reports[0].Header = coverageHeader(t, "nuclei", ctis.ReportMetadata{CoverageType: "incremental"})
		}, coveragePartial},
		{"repository scan keeps its own path", func(c *ingestreport.CommandCoverage) {
			c.Reports[0].Header = coverageHeader(t, "nuclei", ctis.ReportMetadata{Branch: &ctis.BranchInfo{Name: "main", IsDefaultBranch: true}})
		}, coverageRepositoryScan},
		{"two tools in one run", func(c *ingestreport.CommandCoverage) {
			second := c.Reports[0]
			second.ReportID, second.ToolName = "r-2", "trivy"
			c.Reports = append(c.Reports, second)
		}, coverageToolMismatch},
		{"reserved tool name", func(c *ingestreport.CommandCoverage) { c.Reports[0].ToolName = "pentest" }, coverageReservedTool},
		{"unreachable target: nothing touched", func(c *ingestreport.CommandCoverage) { c.Reports[0].TouchedAssetIDs = nil }, coverageNoCoveredAssets},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := completedRun(t, sensorID, assetID)
			tc.mutate(c)
			if got := decideCoverage(c).reason; got != tc.want {
				t.Fatalf("reason = %q, want %q", got, tc.want)
			}
		})
	}

	d := decideCoverage(completedRun(t, sensorID, assetID))
	if d.query.ToolName != "nuclei" || d.query.ProfileID != "p-1" || len(d.query.AssetIDs) != 1 ||
		d.query.AssetIDs[0] != assetID || len(d.query.SeenScanIDs) != 1 || d.query.SeenScanIDs[0] != "r-1" {
		t.Fatalf("query = %+v", d.query)
	}
}

func TestParseCoverageAutoResolveMode(t *testing.T) {
	for in, want := range map[string]CoverageAutoResolveMode{
		"": CoverageAutoResolveDryRun, "dry_run": CoverageAutoResolveDryRun, "garbage": CoverageAutoResolveDryRun,
		"off": CoverageAutoResolveOff, " OFF ": CoverageAutoResolveOff, "enforce": CoverageAutoResolveEnforce,
	} {
		if got := ParseCoverageAutoResolveMode(in); got != want {
			t.Errorf("ParseCoverageAutoResolveMode(%q) = %q, want %q", in, got, want)
		}
	}
}

// coverageFindingRepo is a finding repository with only the coverage queries;
// any other call panics via the nil embedded interface.
type coverageFindingRepo struct {
	vulnerability.FindingRepository
	cov      *ingestreport.CommandCoverage
	stale    []shared.ID
	open     int
	query    ingestreport.CoverageQuery
	resolved []shared.ID
}

func (r *coverageFindingRepo) CommandCoverage(context.Context, shared.ID, shared.ID) (*ingestreport.CommandCoverage, error) {
	return r.cov, nil
}

func (r *coverageFindingRepo) CoverageStaleFindings(_ context.Context, _ shared.ID, q ingestreport.CoverageQuery) ([]shared.ID, int, error) {
	r.query = q
	return r.stale, r.open, nil
}

func (r *coverageFindingRepo) ResolveCoverageStale(_ context.Context, _ shared.ID, ids []shared.ID) ([]shared.ID, error) {
	r.resolved = append(r.resolved, ids...)
	return ids, nil
}

// coverageAssetRepo serves GetByID for the assets a coverage test knows.
type coverageAssetRepo struct {
	asset.Repository
	byID map[shared.ID]*asset.Asset
}

func (r *coverageAssetRepo) GetByID(_ context.Context, _ shared.ID, id shared.ID) (*asset.Asset, error) {
	if a, ok := r.byID[id]; ok {
		return a, nil
	}
	return nil, shared.ErrNotFound
}

// coverageCommands serves the one command a coverage test evaluates.
type coverageCommands struct{ cmd *command.Command }

func (c coverageCommands) GetByTenantAndID(context.Context, shared.ID, shared.ID) (*command.Command, error) {
	return c.cmd, nil
}

// coverageService is a service whose one run is a nuclei scan of
// a.example.com that touched the asset a.example.com (covered by the
// command). touched adds more touched assets by name.
func coverageService(t *testing.T, mode CoverageAutoResolveMode, declared []string, touched ...string) (*Service, *coverageFindingRepo) {
	t.Helper()
	tid, sensorID := shared.NewID(), shared.NewID()
	assets := &coverageAssetRepo{byID: map[shared.ID]*asset.Asset{}}
	names := append([]string{"a.example.com"}, touched...)
	ids := make([]shared.ID, 0, len(names))
	for _, name := range names {
		a, err := asset.NewAssetWithTenant(tid, name, asset.AssetTypeDomain, asset.CriticalityMedium)
		if err != nil {
			t.Fatal(err)
		}
		assets.byID[a.ID()] = a
		ids = append(ids, a.ID())
	}
	cov := completedRun(t, sensorID, ids[0])
	cov.Reports[0].TouchedAssetIDs = ids
	repo := &coverageFindingRepo{cov: cov, stale: []shared.ID{shared.NewID()}, open: 4}
	sensors := &sensorRowRepo{rows: map[shared.ID]*sensor.Sensor{
		sensorID: {ID: sensorID, TenantID: &tid, Reported: sensor.ReportOf(declared...)},
	}}
	svc := &Service{logger: logger.NewNop(), findingRepo: repo, sensorRepo: sensors, assetRepo: assets}
	svc.SetCommandReader(coverageCommands{cmd: &command.Command{
		ID: shared.NewID(), TenantID: tid, Type: command.CommandTypeScan,
		Payload: json.RawMessage(`{"scanner":"nuclei","targets":["a.example.com"]}`),
	}})
	svc.SetCoverageAutoResolve(mode, DefaultBlindingGuard())
	return svc, repo
}

// A report may name any existing asset of its tenant; only the assets its
// command was sent to scan count as covered (RFC-040 §5.3). A hostile sensor
// that names another asset must not close that asset's findings.
func TestEvaluateCommandCoverage_OnlyCommandCoveredAssets(t *testing.T) {
	t.Run("an asset outside the command is left out of the candidate query", func(t *testing.T) {
		svc, repo := coverageService(t, CoverageAutoResolveEnforce, []string{"nuclei"}, "victim.example.org")
		out := svc.EvaluateCommandCoverage(context.Background(), shared.NewID(), shared.NewID())
		if out.Reason != coverageEligible {
			t.Fatalf("outcome = %+v", out)
		}
		if len(repo.query.AssetIDs) != 1 || repo.query.AssetIDs[0] != repo.cov.Reports[0].TouchedAssetIDs[0] {
			t.Fatalf("candidate assets = %v, want only the covered one", repo.query.AssetIDs)
		}
	})
	t.Run("a report that touched only uncovered assets closes nothing", func(t *testing.T) {
		svc, repo := coverageService(t, CoverageAutoResolveEnforce, []string{"nuclei"}, "victim.example.org")
		repo.cov.Reports[0].TouchedAssetIDs = repo.cov.Reports[0].TouchedAssetIDs[1:]
		out := svc.EvaluateCommandCoverage(context.Background(), shared.NewID(), shared.NewID())
		if out.Reason != coverageNoCoveredAssets || len(repo.resolved) != 0 || repo.query.ToolName != "" {
			t.Fatalf("outcome = %+v, resolved %v, query %+v", out, repo.resolved, repo.query)
		}
	})
}

// The default is a dry run: the would-be resolution is reported, nothing is
// changed.
func TestEvaluateCommandCoverage_DryRunChangesNothing(t *testing.T) {
	svc, repo := coverageService(t, "", []string{"nuclei"})
	out := svc.EvaluateCommandCoverage(context.Background(), shared.NewID(), shared.NewID())
	if out.Mode != CoverageAutoResolveDryRun || out.Reason != coverageEligible {
		t.Fatalf("outcome = %+v", out)
	}
	if len(out.WouldResolve) != 1 || len(out.Resolved) != 0 || len(repo.resolved) != 0 {
		t.Fatalf("dry run must not resolve: outcome %+v, repo resolved %v", out, repo.resolved)
	}
	if repo.query.ToolName != "nuclei" || repo.query.ProfileID != "p-1" {
		t.Fatalf("candidate query = %+v", repo.query)
	}
}

func TestEvaluateCommandCoverage_EnforceResolves(t *testing.T) {
	svc, repo := coverageService(t, CoverageAutoResolveEnforce, []string{"nuclei"})
	out := svc.EvaluateCommandCoverage(context.Background(), shared.NewID(), shared.NewID())
	if len(out.Resolved) != 1 || len(repo.resolved) != 1 {
		t.Fatalf("enforce must resolve the stale finding: %+v", out)
	}
}

func TestEvaluateCommandCoverage_Refusals(t *testing.T) {
	t.Run("off", func(t *testing.T) {
		svc, repo := coverageService(t, CoverageAutoResolveOff, []string{"nuclei"})
		svc.EvaluateCommandCoverage(context.Background(), shared.NewID(), shared.NewID())
		if repo.query.ToolName != "" || len(repo.resolved) != 0 {
			t.Fatal("off must not even look for candidates")
		}
	})
	t.Run("sensor never declared the tool", func(t *testing.T) {
		svc, repo := coverageService(t, CoverageAutoResolveEnforce, []string{"trivy"})
		out := svc.EvaluateCommandCoverage(context.Background(), shared.NewID(), shared.NewID())
		if out.Reason != coverageToolMismatch || len(repo.resolved) != 0 {
			t.Fatalf("outcome = %+v, resolved %v", out, repo.resolved)
		}
	})
	t.Run("failed command", func(t *testing.T) {
		svc, repo := coverageService(t, CoverageAutoResolveEnforce, []string{"nuclei"})
		repo.cov.CommandStatus = "failed"
		out := svc.EvaluateCommandCoverage(context.Background(), shared.NewID(), shared.NewID())
		if out.Reason != coverageCommandNotCompleted || len(repo.resolved) != 0 {
			t.Fatalf("outcome = %+v, resolved %v", out, repo.resolved)
		}
	})
	t.Run("blinding guard holds a mass close", func(t *testing.T) {
		svc, repo := coverageService(t, CoverageAutoResolveEnforce, []string{"nuclei"})
		repo.stale = make([]shared.ID, 150)
		for i := range repo.stale {
			repo.stale[i] = shared.NewID()
		}
		repo.open = 160
		out := svc.EvaluateCommandCoverage(context.Background(), shared.NewID(), shared.NewID())
		if !out.Held || len(repo.resolved) != 0 {
			t.Fatalf("150 of 160 must be held: %+v", out)
		}
	})
}

// A repository run closes default-branch findings only on proof that it ran
// cleanly and covered the whole default branch (research 18 F3).
func TestDecideRepoCoverage(t *testing.T) {
	sensorID, assetID := shared.NewID(), shared.NewID()
	mainFull := ctis.ReportMetadata{CoverageType: "full", Branch: &ctis.BranchInfo{Name: "main", IsDefaultBranch: true}}
	repoRun := func() *ingestreport.CommandCoverage {
		c := completedRun(t, sensorID, assetID)
		c.Reports[0].ToolName = "semgrep"
		c.Reports[0].Header = coverageHeader(t, "semgrep", mainFull)
		return c
	}
	cases := []struct {
		name   string
		mutate func(*ingestreport.CommandCoverage)
		want   string
	}{
		{"clean full default-branch run", func(*ingestreport.CommandCoverage) {}, coverageEligible},
		{"scanner exited non-zero (semgrep found errors)", func(c *ingestreport.CommandCoverage) {
			c.Result = json.RawMessage(`{"exit_code":2}`)
		}, coverageNonZeroExit},
		{"command still running", func(c *ingestreport.CommandCoverage) { c.CommandStatus = "running" }, coverageCommandNotCompleted},
		{"scanner errors in the report", func(c *ingestreport.CommandCoverage) {
			c.Reports[0].SegmentOutcomes["1"] = ingestreport.SegmentOutcome{Errors: []protov2.ItemError{{Code: "x"}}}
		}, coverageRejectedItems},
		{"coverage type missing is not full", func(c *ingestreport.CommandCoverage) {
			md := mainFull
			md.CoverageType = ""
			c.Reports[0].Header = coverageHeader(t, "semgrep", md)
		}, coverageUndeclared},
		{"incremental", func(c *ingestreport.CommandCoverage) {
			md := mainFull
			md.CoverageType = "incremental"
			c.Reports[0].Header = coverageHeader(t, "semgrep", md)
		}, coveragePartial},
		{"feature branch", func(c *ingestreport.CommandCoverage) {
			md := mainFull
			md.Branch = &ctis.BranchInfo{Name: "feat/x"}
			c.Reports[0].Header = coverageHeader(t, "semgrep", md)
		}, coverageNotDefaultBranch},
		{"no branch: not a repository run", func(c *ingestreport.CommandCoverage) {
			c.Reports[0].Header = coverageHeader(t, "semgrep", ctis.ReportMetadata{CoverageType: "full"})
		}, coverageNotRepositoryScan},
		{"reserved tool", func(c *ingestreport.CommandCoverage) { c.Reports[0].ToolName = "manual" }, coverageReservedTool},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := repoRun()
			tc.mutate(c)
			if got := decideRepoCoverage(c).reason; got != tc.want {
				t.Fatalf("reason = %q, want %q", got, tc.want)
			}
		})
	}
	// The non-repository decision hands such a run over.
	if got := decideCoverage(repoRun()).reason; got != coverageRepositoryScan {
		t.Fatalf("decideCoverage on a repository run = %q, want %q", got, coverageRepositoryScan)
	}
}
