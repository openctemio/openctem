package sensor

// The ai-worker grant profile (docs/rfcs/RFC-131-ai-analysis.md): an AI
// worker runs analysis jobs and nothing else, and no scanning profile takes
// an analysis job.

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

func analyzePayload(t *testing.T) json.RawMessage {
	t.Helper()
	return payload(t, map[string]any{
		"contract": "openctem.analyze/v1", "job_id": "0193a000-0000-7000-8000-000000000001",
		"kind": "triage.v1", "use_case": "triage",
		"subject":               map[string]any{"type": "finding", "id": "0193a000-0000-7000-8000-000000000002"},
		"bundle":                map[string]any{"digest": "sha256:" + strings.Repeat("a", 64), "masked": true, "text": "HOST_1 answers on URL_1"},
		"required_capabilities": []string{"analyze.triage.v1"},
	})
}

func TestAIWorkerProfile_Shape(t *testing.T) {
	if !ValidProfile(ProfileAIWorker) || !slices.Contains(SelectableProfiles(), ProfileAIWorker) {
		t.Fatalf("%s is not selectable", ProfileAIWorker)
	}
	g := mustProfile(t, ProfileAIWorker)
	if !slices.Equal(g.JobTypes, []string{"analyze"}) {
		t.Fatalf("job types = %v, want [analyze]", g.JobTypes)
	}
	if g.TierCeiling != TierPassive || g.TargetNetwork != TargetNetworkNone || g.AllowCredentials || g.AllowPushIngest {
		t.Fatalf("ai-worker grant is wider than passive, network-less, no credentials, no push: %+v", g)
	}
	if !TrustableAtApproval(ProfileAIWorker) {
		t.Fatal("ai-worker should be trustable at approval (no credentials, no push ingest)")
	}
	if ParameterisedProfile(ProfileAIWorker) || ValidProfile(ProfileAIWorker+":x") {
		t.Fatal("ai-worker takes no parameter")
	}
}

func TestAIWorkerProfile_AdmitsOnlyAnalyze(t *testing.T) {
	an := analyzePayload(t)
	for _, g := range []Grant{mustProfile(t, ProfileAIWorker), trusted(mustProfile(t, ProfileAIWorker))} {
		if r := g.Admit("analyze", an, nil); r != nil {
			t.Fatalf("ai-worker (trust %s) refused an analysis job: %v", g.TrustLevel, r)
		}
		scan := payload(t, map[string]any{"scanner": "nuclei", "targets": []string{"https://app.example.com"}})
		for _, typ := range []string{"scan", "collect", "validate", "retest", "config_update", "connector_sync", "connector_scan"} {
			r := g.Admit(typ, scan, nil)
			if r == nil || r.Dimension != DimJobTypes {
				t.Errorf("ai-worker (trust %s) admitted %s: %v", g.TrustLevel, typ, r)
			}
		}
	}
}

func TestScanProfiles_RefuseAnalyze(t *testing.T) {
	an := analyzePayload(t)
	for _, p := range SelectableProfiles() {
		if p == ProfileAIWorker {
			continue
		}
		for _, g := range []Grant{mustProfile(t, p), trusted(mustProfile(t, p))} {
			r := g.Admit("analyze", an, nil)
			if r == nil || r.Dimension != DimJobTypes {
				t.Errorf("%s (trust %s) admitted an analysis job: %v", p, g.TrustLevel, r)
			}
		}
	}
}

func TestAnalyze_TierIsPassive(t *testing.T) {
	if tier := CommandTier("analyze", JobOf("analyze", analyzePayload(t))); tier != TierPassive {
		t.Fatalf("analyze tier = T%d, want T0", tier)
	}
}

// A grant never mixes analysis with other work: an edited (custom) grant
// that adds scan to an AI worker, or analyze to a scanner, is invalid.
func TestGrant_AnalyzeNotCombined(t *testing.T) {
	g := mustProfile(t, ProfileAIWorker)
	g.Profile, g.JobTypes = ProfileCustom, []string{"analyze", "scan"}
	if err := g.Normalize(); !errors.Is(err, ErrGrantInvalid) {
		t.Fatalf("analyze+scan grant normalised: %v", err)
	}
	g.JobTypes = []string{"analyze"}
	if err := g.Normalize(); err != nil {
		t.Fatalf("analyze-only grant refused: %v", err)
	}
}

func TestSuggestGrant_AIWorkerOnlyForAnalysisUsage(t *testing.T) {
	cur := *LegacyBroadGrant(shared.NewID(), shared.NewID())
	an := SuggestGrant(cur, SensorTypeWorker, GrantUsage{Complete: true, JobCount: 1,
		Jobs: []UsageJob{{Type: "analyze", Payload: analyzePayload(t)}}}, nil)
	if an.Profile != ProfileAIWorker {
		t.Fatalf("analysis-only sensor suggested %q (%s), want %s", an.Profile, an.Reason, ProfileAIWorker)
	}
	hc := SuggestGrant(cur, SensorTypeWorker, GrantUsage{Complete: true, JobCount: 1,
		Jobs: []UsageJob{{Type: "health_check", Payload: json.RawMessage(`{}`)}}}, nil)
	if hc.Profile == ProfileAIWorker {
		t.Fatal("a sensor that only ran health checks was suggested the AI worker profile")
	}
}

// Only an explicit AI worker grant takes an analysis job: a sensor on the
// legacy-broad grant (no job type list) that advertises analyze.<kind> is
// refused, at every trust level, and so is a grant edited to list no job
// type.
func TestAnalyze_OnlyAnExplicitAIWorkerGrant(t *testing.T) {
	an := analyzePayload(t)
	legacy := *LegacyBroadGrant(shared.NewID(), shared.NewID())
	for _, g := range []Grant{legacy, func() Grant { g := legacy; g.TrustLevel = TrustNew; return g }()} {
		if g.ServesAnalysis() {
			t.Fatal("legacy-broad serves analysis jobs")
		}
		if r := g.Admit("analyze", an, nil); r == nil || r.Dimension != DimJobTypes {
			t.Fatalf("legacy-broad (trust %s) admitted an analysis job: %v", g.TrustLevel, r)
		}
	}
	// It still takes the work it always took.
	if r := legacy.Admit("collect", payload(t, map[string]any{"collector": "inventory"}), nil); r != nil {
		t.Fatalf("legacy-broad refused a collect: %v", r)
	}
	custom := mustProfile(t, ProfileInternalScanner)
	custom.Profile, custom.JobTypes = ProfileCustom, nil
	if custom.ServesAnalysis() || custom.Admit("analyze", an, nil) == nil {
		t.Fatal("a custom grant without a job type list admitted an analysis job")
	}
	// The ai-worker profile narrowed by an administrator (custom, still
	// analyze only) keeps taking analysis jobs.
	narrowed := mustProfile(t, ProfileAIWorker)
	narrowed.Profile, narrowed.Capabilities = ProfileCustom, []string{"analyze.triage.v1"}
	if err := narrowed.Normalize(); err != nil {
		t.Fatal(err)
	}
	if !narrowed.ServesAnalysis() || narrowed.Admit("analyze", an, nil) != nil {
		t.Fatal("a narrowed AI worker grant refused its analysis job")
	}
}
