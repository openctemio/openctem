package cirun

import (
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestParseCapabilities(t *testing.T) {
	got, err := ParseCapabilities([]string{"IaC", "sast", "sast"})
	if err != nil || len(got) != 2 || got[0] != CapabilitySAST || got[1] != CapabilityIaC {
		t.Fatalf("ParseCapabilities = %v %v", got, err)
	}
	if _, err := ParseCapabilities([]string{"dast"}); err == nil {
		t.Fatal("dast accepted as a repository capability")
	}
}

func TestComputeCoverage(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	day := 24 * time.Hour
	at := func(d time.Duration) time.Time { return now.Add(-d) }
	ptr := func(t time.Time) *time.Time { return &t }
	repoA, repoB, repoC := shared.NewID(), shared.NewID(), shared.NewID()
	fresh := Pipeline{ID: shared.NewID(), RepositoryAssetID: repoA, LastRunAt: ptr(at(day)), RepositoryName: "a"}
	stale := Pipeline{ID: shared.NewID(), RepositoryAssetID: repoB, LastRunAt: ptr(at(20 * day)), RepositoryName: "b"}
	revoked := Pipeline{ID: shared.NewID(), RepositoryAssetID: repoC, LastRunAt: ptr(at(day)), RevokedAt: ptr(at(time.Hour))}
	pipes := map[shared.ID]Pipeline{fresh.ID: fresh, stale.ID: stale, revoked.ID: revoked}
	repos := []RepositoryRef{{ID: repoA, Name: "a", Criticality: "low"}, {ID: repoB, Name: "b", Criticality: "critical"},
		{ID: repoC, Name: "c", Criticality: "high"}}
	obs := []CoverageObservation{
		{RepositoryAssetID: repoA, Capability: CapabilitySAST, At: at(day), SourceKind: SourcePipeline, PipelineID: &fresh.ID},
		{RepositoryAssetID: repoB, Capability: CapabilitySAST, At: at(20 * day), SourceKind: SourcePipeline, PipelineID: &stale.ID},
		// A daemon scan keeps SCA fresh on B for 30 days.
		{RepositoryAssetID: repoB, Capability: CapabilitySCA, At: at(10 * day), SourceKind: SourceScan, SourceName: "trivy"},
		// A revoked pipeline does not keep coverage fresh.
		{RepositoryAssetID: repoC, Capability: CapabilitySecrets, At: at(day), SourceKind: SourcePipeline, PipelineID: &revoked.ID},
		// Older than the window: ignored.
		{RepositoryAssetID: repoC, Capability: CapabilityIaC, At: at(100 * day), SourceKind: SourceScan},
	}
	exps := map[shared.ID]Expectation{repoC: {RepositoryAssetID: repoC, Capabilities: []Capability{CapabilitySecrets}}}
	rows := ComputeCoverage(repos, obs, pipes, exps, now, StatusPolicy{})
	state := func(r RepositoryCoverage, c Capability) CoverageState {
		for _, cc := range r.Capabilities {
			if cc.Capability == c {
				return cc.State
			}
		}
		return ""
	}
	if !rows[0].Covered || state(rows[0], CapabilitySAST) != CoverageFresh || state(rows[0], CapabilitySCA) != CoverageNever {
		t.Fatalf("repo A = %+v", rows[0])
	}
	if state(rows[1], CapabilitySAST) != CoverageStale || state(rows[1], CapabilitySCA) != CoverageFresh || !rows[1].Covered {
		t.Fatalf("repo B = %+v", rows[1])
	}
	if rows[2].Covered || !rows[2].Gap || state(rows[2], CapabilitySecrets) != CoverageStale || state(rows[2], CapabilityIaC) != CoverageNever {
		t.Fatalf("repo C = %+v", rows[2])
	}
	s := Summarize(rows)
	if s.Repositories != 3 || s.Covered != 2 || s.Gaps != 1 || s.UncoveredByCriticality["high"] != 1 || s.FreshByCapability[CapabilitySAST] != 1 {
		t.Fatalf("summary = %+v", s)
	}
	SortCoverage(rows)
	if rows[0].Repository.ID != repoC || rows[1].Repository.Criticality != "critical" {
		t.Fatalf("sort: gap first, then by criticality: %v, %v", rows[0].Repository.Name, rows[1].Repository.Name)
	}
}

func TestComputeTemplateDrift(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	ptr := func(d time.Duration) *time.Time { t := now.Add(-d); return &t }
	tpl := "acme/security/.github/workflows/scan.yml"
	pipes := []Pipeline{
		{ID: shared.NewID(), TemplateRef: tpl + "@refs/tags/v3", LastRunAt: ptr(time.Hour)},
		{ID: shared.NewID(), TemplateRef: tpl + "@refs/tags/v2", LastRunAt: ptr(2 * time.Hour)},
		{ID: shared.NewID(), TemplateRef: tpl + "@refs/tags/v2", LastRunAt: ptr(3 * time.Hour)},
		{ID: shared.NewID(), TemplateRef: tpl + "@refs/tags/v1", LastRunAt: ptr(200 * 24 * time.Hour)}, // archived: ignored
		{ID: shared.NewID(), LastRunAt: ptr(time.Hour)},                                                // own workflow
	}
	d := ComputeTemplateDrift(pipes, now, StatusPolicy{})
	if len(d) != 1 || d[0].Template != tpl || d[0].Current != "refs/tags/v3" || d[0].Drifted != 2 || d[0].Total != 3 {
		t.Fatalf("drift = %+v", d)
	}
}

func TestEvaluateAlerts(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	day := 24 * time.Hour
	ptr := func(d time.Duration) *time.Time { t := now.Add(-d); return &t }
	repo1, repo2 := shared.NewID(), shared.NewID()
	missed := Pipeline{ID: shared.NewID(), RepositoryAssetID: repo1, LastRunAt: ptr(3 * day), ScheduleInterval: day}
	failing := Pipeline{ID: shared.NewID(), RepositoryAssetID: repo2, LastRunAt: ptr(time.Hour), LastDefaultVerdict: VerdictFail,
		SensorVersion: "v0.1.0"}
	archived := Pipeline{ID: shared.NewID(), RepositoryAssetID: shared.NewID(), LastRunAt: ptr(100 * day), LastDefaultVerdict: VerdictFail}
	alerts := EvaluateAlerts([]Pipeline{missed, failing, archived}, now, StatusPolicy{MinVersion: "v0.5.0", LatestVersion: "v0.9.0"})
	kinds := map[AlertKind]shared.ID{}
	for _, a := range alerts {
		kinds[a.Kind] = a.SubjectID
		if a.SubjectID == archived.ID {
			t.Fatal("an archived pipeline raised an alert")
		}
	}
	if kinds[AlertScheduleMissed] != missed.ID || kinds[AlertGateFailing] != failing.ID || kinds[AlertRunnerOutdated] != failing.ID {
		t.Fatalf("alerts = %+v", alerts)
	}
	// repo1's only pipeline is stale: coverage regression on the repository.
	if kinds[AlertCoverageRegression] != repo1 {
		t.Fatalf("coverage regression = %v, want repository %v", kinds[AlertCoverageRegression], repo1)
	}
	if len(alerts) != 4 {
		t.Fatalf("got %d alerts, want 4", len(alerts))
	}
	// A retired pipeline raises nothing.
	retired := failing
	retired.RetiredAt = ptr(time.Minute)
	if got := EvaluateAlerts([]Pipeline{retired}, now, StatusPolicy{MinVersion: "v0.5.0"}); len(got) != 0 {
		t.Fatalf("retired pipeline alerts = %+v", got)
	}
}
