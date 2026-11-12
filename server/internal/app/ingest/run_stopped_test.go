package ingest

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/openctemio/ctis/v2"

	"github.com/openctemio/openctem/server/pkg/domain/asset"
	"github.com/openctemio/openctem/server/pkg/domain/ingestreport"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/logger"
	protov2 "github.com/openctemio/openctem/server/pkg/sensorproto/v2"
)

// Coverage auto-resolve: the legacy shape of a stopped run (exit -1 or 1,
// "completed", full coverage, every target done) closes nothing, also when
// its per-target outcomes would otherwise prove the done targets.
func TestDecideCoverage_StoppedRunProvesNothing(t *testing.T) {
	sensorID, assetID := shared.NewID(), shared.NewID()
	done := `,"target_outcomes":[{"target":"a.example.com","state":"done"}]`
	for name, raw := range legacyStoppedResults {
		for _, outcomes := range []string{"", done} {
			c := completedRun(t, sensorID, assetID)
			c.Reports[0].Header = coverageHeader(t, "nuclei", ctis.ReportMetadata{CoverageType: ctis.CoverageFull,
				Targets: []ctis.TargetOutcome{{Target: "a.example.com", State: ctis.TargetDone}}})
			res := raw
			if outcomes != "" && json.Valid([]byte(raw)) {
				res = raw[:len(raw)-1] + outcomes + "}"
			}
			c.Result = json.RawMessage(res)
			d := decideCoverage(c)
			want := coverageRunStopped
			if name == "exit -1, completed" || name == "exit 1, completed" {
				want = coverageNonZeroExit
			}
			if d.reason != want || d.eligible() {
				t.Errorf("%s (outcomes %v) = %s, want %s", name, outcomes != "", d.reason, want)
			}
		}
	}
	// End to end in enforce mode: nothing is queried or resolved.
	svc, repo := coverageService(t, CoverageAutoResolveEnforce, []string{"nuclei"})
	repo.cov.Result = json.RawMessage(`{"status":"completed","exit_code":-1}`)
	out := svc.EvaluateCommandCoverage(context.Background(), shared.NewID(), shared.NewID())
	if out.Reason != coverageNonZeroExit || len(repo.resolved) != 0 || repo.query.ToolName != "" {
		t.Fatalf("legacy stopped run: outcome %+v, resolved %v", out, repo.resolved)
	}
}

// Wildcard DNS: a filtered resolution that was stopped marks nothing as
// wildcard-only (a name it never reached is not "dropped by the filter").
func TestResolutionOver_StoppedRun(t *testing.T) {
	done := func(result string) *ingestreport.CommandCoverage {
		return &ingestreport.CommandCoverage{CommandStatus: "completed", Result: json.RawMessage(result),
			Reports: []ingestreport.CoverageReport{{Integrity: protov2.IntegritySingle, State: protov2.StateCompleted}}}
	}
	if !resolutionOver(done(`{"exit_code":0}`)) {
		t.Fatal("precondition: a clean resolution is over")
	}
	for name, raw := range legacyStoppedResults {
		if resolutionOver(done(raw)) {
			t.Errorf("%s: a stopped resolution counted as over", name)
		}
	}

	tenant := shared.NewID()
	guess, resolved := wcAsset(t, "guess.example.com"), wcAsset(t, "api.example.com")
	assets := wcAssets{tenant: tenant, byName: map[string]*asset.Asset{"guess.example.com": guess, "api.example.com": resolved}}
	cmd := wcCommand(t, tenant, map[string]any{"scanner": "dnsx", "targets": []string{"guess.example.com", "api.example.com"},
		"config": map[string]any{"wildcard_filter": true}})
	mark := func(result string) []shared.ID {
		cov := done(result)
		cov.Reports[0].TouchedAssetIDs = []shared.ID{resolved.ID()}
		st := &wcStore{}
		s := &Service{commands: wcCommands{tenant: tenant, cmd: cmd}, assetRepo: assets, wildcardDNS: st, logger: logger.NewNop(),
			nameProber: wcProber{"guess.example.com": NameWildcardOnly}}
		s.evaluateWildcardDNS(context.Background(), tenant, cmd.ID, cov)
		return st.marked
	}
	if got := mark(`{"status":"completed","exit_code":0}`); len(got) != 1 {
		t.Fatalf("precondition: a clean resolution marked %v, want the guess", got)
	}
	if got := mark(`{"status":"completed","exit_code":-1}`); len(got) != 0 {
		t.Fatalf("a resolution killed at exit -1 marked %v wildcard-only", got)
	}
}

// Collector reports: full coverage that lists an unfinished or failed
// target is not complete (a crashed collector run never retires assets it
// did not reach).
func TestCompleteCoverage_ListedTargetNotDone(t *testing.T) {
	md := ctis.ReportMetadata{CoverageType: ctis.CoverageFull, Targets: []ctis.TargetOutcome{{Target: "a", State: ctis.TargetDone}}}
	if !completeCoverage(md) {
		t.Fatal("full, every target done: complete")
	}
	for _, st := range []ctis.TargetState{ctis.TargetFailed, ctis.TargetUnfinished, ctis.TargetSkipped} {
		md.Targets = []ctis.TargetOutcome{{Target: "a", State: ctis.TargetDone}, {Target: "b", State: st}}
		if completeCoverage(md) {
			t.Errorf("full with a %s target counted as complete", st)
		}
	}
}
