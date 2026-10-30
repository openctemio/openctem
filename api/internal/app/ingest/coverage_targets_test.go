package ingest

import (
	"context"
	"encoding/json"
	"slices"
	"testing"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestCoveredTargets(t *testing.T) {
	targets := []string{"a.example.com", "https://b.example.com", "c.example.com", "d.example.com"}
	cases := []struct {
		name   string
		result string
		want   []string
	}{
		{"older sensor, full run, no outcomes: every target", `{"exit_code":0}`, targets},
		{"done targets only", `{"target_outcomes":[
			{"target":"a.example.com","state":"done"},
			{"target":"https://b.example.com","state":"failed","class":"unreachable"},
			{"target":"c.example.com","state":"skipped","class":"refused"},
			{"target":"d.example.com","state":"unfinished"}]}`, []string{"a.example.com"}},
		{"a target without an outcome is not covered", `{"target_outcomes":[{"target":"a.example.com","state":"done"}]}`, []string{"a.example.com"}},
		{"done but its host is a coverage gap", `{"target_outcomes":[
			{"target":"a.example.com","state":"done"},{"target":"c.example.com","state":"done"}],
			"metadata":{"coverage_gaps":[{"host":"c.example.com:443","reason":"breaker_open"}],"coverage_gaps_total":1}}`, []string{"a.example.com"}},
		{"done but unreached", `{"target_outcomes":[{"target":"a.example.com","state":"done"}],
			"metadata":{"unreached_targets":[{"target":"a.example.com","class":"timeout"}],"unreached_targets_total":1}}`, []string{}},
		{"a gap list cut short trusts nothing", `{"target_outcomes":[{"target":"a.example.com","state":"done"}],
			"metadata":{"coverage_gaps":[{"host":"x.example.com"}],"coverage_gaps_total":2}}`, nil},
		{"conflicting outcomes for one target: not covered", `{"target_outcomes":[
			{"target":"a.example.com","state":"done"},{"target":"a.example.com","state":"failed","class":"timeout"}]}`, []string{}},
		{"unreadable metadata trusts nothing", `{"target_outcomes":[{"target":"a.example.com","state":"done"}],"metadata":"x"}`, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := coveredTargets(targets, json.RawMessage(tc.result))
			if len(got) != len(tc.want) || !slices.Equal(got, tc.want) && len(tc.want) > 0 {
				t.Fatalf("coveredTargets = %v, want %v", got, tc.want)
			}
		})
	}
}

// perTargetService is coverageService for a partial run over two targets,
// a.example.com (done) and b.example.com (stopped answering), whose report
// touched nothing; extra assets named in more exist in the tenant.
func perTargetService(t *testing.T, result string, more ...string) (*Service, *coverageFindingRepo, map[string]shared.ID) {
	t.Helper()
	svc, repo := coverageService(t, CoverageAutoResolveEnforce, []string{"nuclei"})
	assets := svc.assetRepo.(*coverageAssetRepo)
	ids := map[string]shared.ID{"a.example.com": repo.cov.Reports[0].TouchedAssetIDs[0]}
	tid := assets.byID[ids["a.example.com"]].TenantID()
	for _, name := range more {
		a, err := asset.NewAssetWithTenant(tid, name, asset.AssetTypeDomain, asset.CriticalityMedium)
		if err != nil {
			t.Fatal(err)
		}
		assets.byID[a.ID()] = a
		ids[name] = a.ID()
	}
	repo.cov.Reports[0].Header = coverageHeader(t, "nuclei", ctis.ReportMetadata{CoverageType: "partial"})
	repo.cov.Reports[0].TouchedAssetIDs = nil
	repo.cov.Result = json.RawMessage(result)
	svc.SetCommandReader(coverageCommands{cmd: &command.Command{
		ID: shared.NewID(), TenantID: tid, Type: command.CommandTypeScan,
		Payload: json.RawMessage(`{"scanner":"nuclei","targets":["a.example.com","b.example.com"]}`),
	}})
	return svc, repo, ids
}

const twoTargetResult = `{"exit_code":0,"target_outcomes":[
	{"target":"a.example.com","state":"done"},
	{"target":"b.example.com","state":"failed","class":"unreachable"}],
	"metadata":{"coverage_gaps":[{"host":"b.example.com","reason":"breaker_open"}],"coverage_gaps_total":1}}`

// One host that stops answering no longer keeps every other host of the run
// from closing what the scan no longer finds there.
func TestEvaluateCommandCoverage_PerTarget(t *testing.T) {
	t.Run("a covered target's assets are candidates, the uncovered one's are not", func(t *testing.T) {
		svc, repo, ids := perTargetService(t, twoTargetResult, "b.example.com")
		repo.candidates = []shared.ID{ids["a.example.com"], ids["b.example.com"]}
		out := svc.EvaluateCommandCoverage(context.Background(), shared.NewID(), shared.NewID())
		if out.Reason != coverageEligible {
			t.Fatalf("outcome = %+v", out)
		}
		if !slices.Equal(repo.candidateTargets, []string{"a.example.com"}) || repo.candidateTool != "nuclei" {
			t.Fatalf("candidate lookup = %q %v, want nuclei on the covered target only", repo.candidateTool, repo.candidateTargets)
		}
		if !slices.Equal(repo.query.AssetIDs, []shared.ID{ids["a.example.com"]}) {
			t.Fatalf("candidate assets = %v, want only a.example.com", repo.query.AssetIDs)
		}
		if len(repo.resolved) != 1 {
			t.Fatalf("the stale finding on the covered host must close: %+v", out)
		}
	})
	t.Run("an asset outside every covered target never closes", func(t *testing.T) {
		svc, repo, ids := perTargetService(t, twoTargetResult, "victim.example.org")
		repo.candidates = []shared.ID{ids["victim.example.org"]}
		out := svc.EvaluateCommandCoverage(context.Background(), shared.NewID(), shared.NewID())
		if out.Reason != coverageNoCoveredAssets || len(repo.resolved) != 0 {
			t.Fatalf("outcome = %+v, resolved %v", out, repo.resolved)
		}
	})
	t.Run("no covered target closes nothing", func(t *testing.T) {
		svc, repo, ids := perTargetService(t, `{"exit_code":0,"target_outcomes":[
			{"target":"a.example.com","state":"failed","class":"unreachable"},
			{"target":"b.example.com","state":"failed","class":"timeout"}]}`)
		repo.candidates = []shared.ID{ids["a.example.com"]}
		out := svc.EvaluateCommandCoverage(context.Background(), shared.NewID(), shared.NewID())
		if out.Reason != coverageNoCoveredAssets || len(repo.resolved) != 0 || repo.candidateTool != "" {
			t.Fatalf("outcome = %+v, resolved %v, lookup %q", out, repo.resolved, repo.candidateTool)
		}
	})
	t.Run("an edge block is never coverage", func(t *testing.T) {
		svc, repo, ids := perTargetService(t, `{"exit_code":0,"target_outcomes":[
			{"target":"a.example.com","state":"done"},{"target":"b.example.com","state":"done"}],
			"metadata":{"coverage_gaps":[{"host":"a.example.com","reason":"blocked","edge":"blocked","vendor":"cloudflare"}],"coverage_gaps_total":1}}`)
		repo.candidates = []shared.ID{ids["a.example.com"]}
		out := svc.EvaluateCommandCoverage(context.Background(), shared.NewID(), shared.NewID())
		if len(repo.resolved) != 0 || slices.Contains(repo.query.AssetIDs, ids["a.example.com"]) {
			t.Fatalf("a blocked host must not close: outcome %+v, query %v", out, repo.query.AssetIDs)
		}
	})
	t.Run("a scan that found nothing closes what it no longer sees", func(t *testing.T) {
		svc, repo, ids := perTargetService(t, `{"exit_code":0,"target_outcomes":[
			{"target":"a.example.com","state":"done"},{"target":"b.example.com","state":"done"}]}`)
		repo.cov.Reports[0].Header = coverageHeader(t, "nuclei", ctis.ReportMetadata{CoverageType: "full"})
		repo.candidates = []shared.ID{ids["a.example.com"]}
		out := svc.EvaluateCommandCoverage(context.Background(), shared.NewID(), shared.NewID())
		if out.Reason != coverageEligible || len(repo.resolved) != 1 {
			t.Fatalf("outcome = %+v, resolved %v", out, repo.resolved)
		}
	})
	t.Run("dry run still changes nothing", func(t *testing.T) {
		svc, repo, ids := perTargetService(t, twoTargetResult)
		svc.SetCoverageAutoResolve(CoverageAutoResolveDryRun, DefaultBlindingGuard())
		repo.candidates = []shared.ID{ids["a.example.com"]}
		out := svc.EvaluateCommandCoverage(context.Background(), shared.NewID(), shared.NewID())
		if len(out.WouldResolve) != 1 || len(repo.resolved) != 0 {
			t.Fatalf("outcome = %+v, resolved %v", out, repo.resolved)
		}
	})
}
