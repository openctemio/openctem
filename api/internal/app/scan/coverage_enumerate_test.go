package scan

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openctemio/openctem/api/internal/app/actscope"
	covdom "github.com/openctemio/openctem/api/pkg/domain/coverage"
	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Active subdomain enumeration (research/333 P0-D1/D2): a coverage run of
// enumerate.subdomains is a brute force (method bruteforce) and its job asks
// for the DNS label list; the run is at standard depth (the small pack).
func TestCoverageScannerConfig_EnumerateIsBruteForce(t *testing.T) {
	enum, ok := stage.Lookup(stage.EnumerateSubdomains)
	require.True(t, ok, "enumerate.subdomains is a catalog stage")
	cfg := coverageScannerConfig(enum, []string{"example.com"})
	assert.Equal(t, "bruteforce", cfg["method"])
	assert.Equal(t, []string{"example.com"}, cfg["targets"])

	passive, _ := stage.Lookup(stage.DiscoverSubdomains)
	_, has := coverageScannerConfig(passive, []string{"example.com"})["method"]
	assert.False(t, has, "a passive discovery run names no method")
}

func TestScannerPayload_WordlistRequestAndDepth(t *testing.T) {
	run := &scanrun.Run{ID: shared.NewID(), Context: map[string]any{
		scanrun.RunContextKeyDepth: string(scanworkflow.DepthStandard), "targets": []string{"example.com"},
	}}
	sc := &scan.Scan{ID: shared.NewID(), ScannerName: "dnsx-enum"}
	p := (&Service{}).scannerPayload(sc, run, nil, map[string]any{"method": "bruteforce"}, run.Context, []string{"example.com"}, nil)

	assert.Equal(t, []stage.WordlistRequest{{Slot: "labels", Purpose: "dns-labels"}}, p[PayloadKeyWordlists],
		"the job asks for the DNS label list at the payload's top level")
	ctx, _ := p["context"].(map[string]any)
	assert.Equal(t, "standard", ctx[scanrun.RunContextKeyDepth], "the depth picks the pack's size class")
	cfg, _ := p["config"].(map[string]any)
	assert.Equal(t, "bruteforce", cfg["method"])
	assert.Equal(t, "example.com", p["target"], "one root per job")

	// A tool that reads no list asks for none.
	sc.ScannerName = "subfinder"
	_, has := (&Service{}).scannerPayload(sc, run, nil, nil, run.Context, []string{"example.com"}, nil)[PayloadKeyWordlists]
	assert.False(t, has)
}

func TestStepCommandPayload_WordlistRequest(t *testing.T) {
	run := &scanrun.Run{ID: shared.NewID(), Context: map[string]any{
		scanrun.RunContextKeyDepth: "deep", "targets": []string{"example.com"},
	}}
	step := &scanworkflow.Step{ID: shared.NewID(), StepKey: "enum", Tool: "dnsx-enum", Capabilities: []string{"enumerate.subdomains"}}
	p, err := StepCommandPayload(run, step, "dnsx-enum", "sr", nil)
	require.NoError(t, err)
	assert.Equal(t, []stage.WordlistRequest{{Slot: "labels", Purpose: "dns-labels"}}, p[PayloadKeyWordlists])
	ctx, _ := p["context"].(map[string]any)
	assert.Equal(t, "deep", ctx[scanrun.RunContextKeyDepth])

	step = &scanworkflow.Step{ID: shared.NewID(), StepKey: "subs", Tool: "subfinder", Capabilities: []string{"discover.subdomains"}}
	p, err = StepCommandPayload(run, step, "subfinder", "sr", nil)
	require.NoError(t, err)
	_, has := p[PayloadKeyWordlists]
	assert.False(t, has)
}

// Security: active enumeration goes through the full dispatch gate as the
// coverage policy. An excluded root, a root outside every scope entry and a
// root whose scope entry allows passive work only are refused one by one;
// nothing is started.
func TestStartCoverage_EnumerateRefusedOffScope(t *testing.T) {
	const (
		excluded    = "excluded.example.com"
		notOurs     = "not-ours.example.org"
		passiveOnly = "passive-only.example.net"
	)
	acts := &stubActScope{targets: map[string]string{notOurs: actscope.ReasonOutOfDataScope}}
	gate := &stubGate{ceiling: map[string]scopedom.Tier{passiveOnly: scopedom.TierPassive}}
	svc := &Service{
		scopeExclusions: &stubExclusions{values: map[string]bool{excluded: true}},
		actScope:        acts, attributionGate: gate, logger: logger.NewNop(),
	}
	res, err := svc.StartCoverage(context.Background(), CoverageInput{
		TenantID: shared.NewID(), Capability: string(stage.EnumerateSubdomains),
		Targets: []string{excluded, notOurs, passiveOnly},
	})
	require.NoError(t, err)
	assert.Nil(t, res.RunID, "nothing is started")
	assert.Empty(t, res.Kept)
	refused := map[string]bool{}
	for _, r := range res.Refused {
		refused[r.Target] = true
	}
	for _, target := range []string{excluded, notOurs, passiveOnly} {
		assert.True(t, refused[target], "%s must be refused, got %+v", target, res.Refused)
	}
	require.NotEmpty(t, acts.got)
	assert.True(t, acts.got[0].System, "coverage acts with the system policy, never a member's scope")
	assert.Equal(t, "dnsx-enum", res.Tool)
}

type stubCoverageContent struct {
	ready bool
	// noDeep: the medium pack is missing (deep depth is not ready).
	noDeep bool
	err    error
	asked  [][]stage.WordlistRequest
	depths []scanworkflow.Depth
}

func (c *stubCoverageContent) CoverageContentReady(_ context.Context, depth scanworkflow.Depth, reqs []stage.WordlistRequest) (bool, error) {
	c.asked = append(c.asked, reqs)
	c.depths = append(c.depths, depth)
	if depth == scanworkflow.DepthDeep && c.noDeep {
		return false, c.err
	}
	return c.ready, c.err
}

// Without the platform's wordlist pack, enumeration coverage pauses with
// content_missing instead of starting runs whose jobs are refused at claim;
// capabilities whose tool reads no list are never held by it. An unreadable
// answer counts as ready (the claim-time pin still refuses the job).
func TestCoverageReadiness_ContentMissing(t *testing.T) {
	ctx := context.Background()
	tenant := shared.NewID()
	enumTool := toolOf(t, "enumerate.subdomains")
	caps := []string{"enumerate.subdomains", "discover.subdomains"}
	for name, c := range map[string]struct {
		content *stubCoverageContent
		want    string
	}{
		"no pack":    {&stubCoverageContent{}, covdom.ReadyContentMissing},
		"pack":       {&stubCoverageContent{ready: true}, ""},
		"unreadable": {&stubCoverageContent{err: errors.New("db down")}, ""},
	} {
		t.Run(name, func(t *testing.T) {
			sel := &tenantSelector{asked: map[shared.ID]bool{}, online: map[shared.ID]map[string]bool{tenant: {enumTool: true, "subfinder": true}}}
			s := &Service{sensorSelector: sel, coverageContent: c.content, logger: logger.NewNop()}
			got := s.CoverageReadiness(ctx, tenant, caps)
			assert.Equal(t, c.want, got["enumerate.subdomains"])
			assert.Empty(t, got["discover.subdomains"], "a tool that reads no list is not held")
			require.Len(t, c.content.asked, 1, "only the tool that reads a list is asked about")
			assert.Equal(t, stage.ToolWordlists("dnsx-enum"), c.content.asked[0])
		})
	}
	// A tool without a sensor is reported as such before any content check.
	content := &stubCoverageContent{}
	s := &Service{sensorSelector: &tenantSelector{asked: map[shared.ID]bool{}, online: map[shared.ID]map[string]bool{}},
		coverageContent: content, logger: logger.NewNop()}
	assert.Equal(t, covdom.ReadyNoEligibleSensor, s.CoverageReadiness(ctx, tenant, caps[:1])["enumerate.subdomains"])
	assert.Empty(t, content.asked)
}

// Deep onboarding: a coverage run takes deep depth only for a tool that
// reads a platform wordlist; passive or an unknown depth is refused, before
// any target is checked.
func TestCoverageDepth(t *testing.T) {
	enumTool := toolOf(t, "enumerate.subdomains")
	for raw, want := range map[string]scanworkflow.Depth{"": scanworkflow.DepthStandard, "standard": scanworkflow.DepthStandard, "deep": scanworkflow.DepthDeep} {
		got, err := coverageDepth(raw, enumTool)
		require.NoError(t, err, raw)
		assert.Equal(t, want, got, raw)
	}
	_, err := coverageDepth("deep", toolOf(t, "probe.http"))
	assert.ErrorIs(t, err, shared.ErrValidation, "deep is only for a tool that reads a wordlist")
	_, err = coverageDepth("passive", enumTool)
	assert.ErrorIs(t, err, shared.ErrValidation)
	_, err = coverageDepth("full", enumTool)
	assert.ErrorIs(t, err, shared.ErrValidation)

	_, err = (&Service{logger: logger.NewNop()}).StartCoverage(context.Background(), CoverageInput{
		TenantID: shared.NewID(), Capability: "probe.http", Targets: []string{"example.com"}, Depth: "deep",
	})
	assert.ErrorIs(t, err, shared.ErrValidation)
}

// A deep pass falls back to standard when the platform has no deep list
// (the medium pack revoked), so the first pass of a root never stalls; an
// unreadable answer keeps deep (the claim-time pin decides).
func TestCoverageDeepContent(t *testing.T) {
	ctx := context.Background()
	enumTool := toolOf(t, "enumerate.subdomains")
	for name, c := range map[string]struct {
		content *stubCoverageContent
		want    scanworkflow.Depth
	}{
		"medium pack":    {&stubCoverageContent{ready: true}, scanworkflow.DepthDeep},
		"no medium pack": {&stubCoverageContent{ready: true, noDeep: true}, scanworkflow.DepthStandard},
		"unreadable":     {&stubCoverageContent{err: errors.New("db down")}, scanworkflow.DepthDeep},
	} {
		s := &Service{coverageContent: c.content, logger: logger.NewNop()}
		assert.Equal(t, c.want, s.coverageDeepContent(ctx, shared.NewID(), enumTool, scanworkflow.DepthDeep), name)
		assert.Equal(t, []scanworkflow.Depth{scanworkflow.DepthDeep}, c.content.depths, "%s: the deep class is asked", name)
		// A standard run asks nothing.
		assert.Equal(t, scanworkflow.DepthStandard, s.coverageDeepContent(ctx, shared.NewID(), enumTool, scanworkflow.DepthStandard), name)
		assert.Len(t, c.content.depths, 1, name)
	}
}

// Security: a deep onboarding pass goes through the same full dispatch gate
// as the steady pass. An excluded root, a root outside every scope entry and
// a passive-only root are refused one by one at deep depth too; nothing is
// started.
func TestStartCoverage_DeepOnboardingRefusedOffScope(t *testing.T) {
	const (
		excluded    = "excluded.example.com"
		notOurs     = "not-ours.example.org"
		passiveOnly = "passive-only.example.net"
	)
	acts := &stubActScope{targets: map[string]string{notOurs: actscope.ReasonOutOfDataScope}}
	gate := &stubGate{ceiling: map[string]scopedom.Tier{passiveOnly: scopedom.TierPassive}}
	content := &stubCoverageContent{ready: true}
	svc := &Service{
		scopeExclusions: &stubExclusions{values: map[string]bool{excluded: true}},
		actScope:        acts, attributionGate: gate, coverageContent: content, logger: logger.NewNop(),
	}
	res, err := svc.StartCoverage(context.Background(), CoverageInput{
		TenantID: shared.NewID(), Capability: string(stage.EnumerateSubdomains),
		Targets: []string{excluded, notOurs, passiveOnly}, Depth: "deep",
	})
	require.NoError(t, err)
	assert.Nil(t, res.RunID, "nothing is started")
	assert.Empty(t, res.Kept)
	assert.Len(t, res.Refused, 3)
	assert.Empty(t, content.depths, "no refused root gets as far as choosing its lists")
}
