package retest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/validation"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	retestdom "github.com/openctemio/openctem/api/pkg/domain/retest"
	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/softwarematch"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/domain/vulnmatch"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Fakes: one tenant, one finding, one asset. A lookup with another tenant is
// "not found", like the repositories.

type pvFindings struct {
	f       *vulnerability.Finding
	release string
}

func (p *pvFindings) GetByID(_ context.Context, tenantID, id shared.ID) (*vulnerability.Finding, error) {
	if p.f == nil || p.f.TenantID() != tenantID || p.f.ID() != id {
		return nil, shared.ErrNotFound
	}
	return p.f, nil
}

func (p *pvFindings) RecordTemplateSightings(context.Context, shared.ID, []vulnerability.TemplateSighting) (int64, error) {
	return 0, nil
}

func (p *pvFindings) TemplateBaseline(context.Context, shared.ID, shared.ID) (vulnerability.TemplateProvenance, error) {
	return vulnerability.TemplateProvenance{TemplatesVersion: p.release}, nil
}

type pvAssets struct{ a *asset.Asset }

func (p pvAssets) GetByID(_ context.Context, tenantID, id shared.ID) (*asset.Asset, error) {
	if p.a.TenantID() != tenantID || p.a.ID() != id {
		return nil, shared.ErrNotFound
	}
	return p.a, nil
}

type pvStore struct {
	created []*retestdom.Retest
	runs    map[shared.ID]shared.ID
	settled []retestdom.SettleInput
}

func (p *pvStore) Create(_ context.Context, rt *retestdom.Retest) error {
	p.created = append(p.created, rt)
	return nil
}
func (p *pvStore) SetCommands(context.Context, shared.ID, shared.ID, *shared.ID, *shared.ID) error {
	return nil
}
func (p *pvStore) SetRun(_ context.Context, _, id, runID shared.ID) error {
	if p.runs == nil {
		p.runs = map[shared.ID]shared.ID{}
	}
	p.runs[id] = runID
	return nil
}
func (p *pvStore) GetByID(context.Context, shared.ID, shared.ID) (*retestdom.Retest, error) {
	return nil, shared.ErrNotFound
}
func (p *pvStore) FindPendingByCommand(context.Context, shared.ID, shared.ID) (*retestdom.Retest, error) {
	return nil, nil
}
func (p *pvStore) ListByFinding(context.Context, shared.ID, shared.ID, int) ([]*retestdom.Retest, error) {
	return nil, nil
}
func (p *pvStore) LastRequestedAt(context.Context, shared.ID, shared.ID) (*time.Time, error) {
	return nil, nil
}
func (p *pvStore) CountPending(context.Context, shared.ID, retestdom.Trigger) (int, error) {
	return 0, nil
}
func (p *pvStore) CountPendingForAsset(context.Context, shared.ID, shared.ID) (int, error) {
	return 0, nil
}
func (p *pvStore) ListSettleCandidates(context.Context, time.Time, int) ([]*retestdom.Retest, error) {
	return nil, nil
}
func (p *pvStore) Settle(_ context.Context, in retestdom.SettleInput) (retestdom.SettleResult, error) {
	p.settled = append(p.settled, in)
	return retestdom.SettleResult{Applied: true}, nil
}
func (p *pvStore) RecordRequested(context.Context, *retestdom.Retest, vulnerability.ActivitySource) error {
	return nil
}

type pvDispatcher struct {
	validated []validation.ValidationJob
	tool      []validation.ToolRetestJob
}

func (p *pvDispatcher) Dispatch(_ context.Context, job validation.ValidationJob) (shared.ID, error) {
	p.validated = append(p.validated, job)
	return shared.NewID(), nil
}
func (p *pvDispatcher) Preflight(context.Context, shared.ID, validation.Target) error { return nil }
func (p *pvDispatcher) DispatchToolRetest(_ context.Context, job validation.ToolRetestJob) (shared.ID, error) {
	p.tool = append(p.tool, job)
	return shared.NewID(), nil
}

// pvSensors: the tenant's online sensors and the capabilities and tools
// they offer.
type pvSensors struct {
	retestTools map[string]bool // tools with retest:<tool>
	tools       map[string]bool // tools a sensor runs
	cands       []SensorCandidate
}

func (p pvSensors) HasNucleiValidationSensor(context.Context, shared.ID) (bool, error) {
	return false, nil
}
func (p pvSensors) HasRetestSensor(_ context.Context, _ shared.ID, tool string) (bool, error) {
	return p.retestTools[tool], nil
}
func (p pvSensors) HasRetestTemplatesSensor(context.Context, shared.ID, string) (bool, error) {
	return false, nil
}
func (p pvSensors) RetestTools(context.Context, shared.ID) ([]string, error) { return nil, nil }
func (p pvSensors) RetestSensors(context.Context, shared.ID, []string) ([]SensorCandidate, error) {
	return p.cands, nil
}
func (p pvSensors) HasToolSensor(_ context.Context, _ shared.ID, tool string) (bool, error) {
	return p.tools[tool], nil
}

type pvVersions struct {
	tenant   shared.ID
	link     *softwarematch.FindingLink
	observed []softwarematch.ObservedVersion
	ranges   []softwarematch.AffectedRange
}

func (p *pvVersions) FindingLink(_ context.Context, tenantID, _ shared.ID) (*softwarematch.FindingLink, error) {
	if tenantID != p.tenant {
		return nil, nil
	}
	return p.link, nil
}
func (p *pvVersions) ObservedSince(_ context.Context, tenantID, _, _ shared.ID, _ string, _ time.Time) ([]softwarematch.ObservedVersion, error) {
	if tenantID != p.tenant {
		return nil, nil
	}
	return p.observed, nil
}
func (p *pvVersions) RangesForProduct(context.Context, shared.ID) ([]softwarematch.AffectedRange, error) {
	return p.ranges, nil
}

type pvFingerprinter struct {
	tool, target string
	run          shared.ID
	err          error
}

func (p *pvFingerprinter) StartFingerprint(_ context.Context, _ shared.ID, tool, target string, _ *shared.ID) (shared.ID, error) {
	p.tool, p.target = tool, target
	if p.err != nil {
		return shared.ID{}, p.err
	}
	p.run = shared.NewID()
	return p.run, nil
}

type pvRuns struct{ run *scanrun.Run }

func (p pvRuns) GetByTenantAndID(context.Context, shared.ID, shared.ID) (*scanrun.Run, error) {
	if p.run == nil {
		return nil, shared.ErrNotFound
	}
	return p.run, nil
}

type pvTemplates struct {
	tenant  shared.ID
	sensors map[string][]shared.ID
}

func (p pvTemplates) TemplateSightingSensors(_ context.Context, tenantID shared.ID, _, ruleID string, _ int) ([]shared.ID, error) {
	if tenantID != p.tenant {
		return nil, nil
	}
	return p.sensors[ruleID], nil
}

type pvFixture struct {
	tenant   shared.ID
	finding  *vulnerability.Finding
	asset    *asset.Asset
	findings *pvFindings
	store    *pvStore
	disp     *pvDispatcher
	sensors  pvSensors
	versions *pvVersions
	fp       *pvFingerprinter
	tmpl     pvTemplates
}

func newPVFixture(t *testing.T, source vulnerability.FindingSource, tool, rule string) *pvFixture {
	t.Helper()
	tenant := shared.NewID()
	a, err := asset.NewAssetWithTenant(tenant, "games.example.com", asset.AssetTypeDomain, asset.CriticalityHigh)
	if err != nil {
		t.Fatal(err)
	}
	f, err := vulnerability.NewFinding(tenant, a.ID(), source, tool, vulnerability.SeverityHigh, "finding")
	if err != nil {
		t.Fatal(err)
	}
	f.SetRuleID(rule)
	fx := &pvFixture{
		tenant: tenant, finding: f, asset: a,
		findings: &pvFindings{f: f},
		store:    &pvStore{}, disp: &pvDispatcher{},
		sensors:  pvSensors{retestTools: map[string]bool{"nuclei": true}, tools: map[string]bool{"httpx": true}},
		versions: &pvVersions{tenant: tenant},
		fp:       &pvFingerprinter{},
		tmpl:     pvTemplates{tenant: tenant, sensors: map[string][]shared.ID{}},
	}
	return fx
}

func (fx *pvFixture) service() *Service {
	s := NewService(fx.store, fx.findings, pvAssets{a: fx.asset}, nil, fx.disp, fx.sensors, logger.NewNop())
	s.SetVersionRecheck(fx.versions, fx.fp, pvRuns{})
	s.SetTemplateEvidence(fx.tmpl)
	return s
}

func (fx *pvFixture) request(t *testing.T, s *Service, mode string) (*retestdom.Retest, error) {
	t.Helper()
	return s.Request(context.Background(), RequestInput{TenantID: fx.tenant, FindingID: fx.finding.ID(), Trigger: retestdom.TriggerManual, Mode: mode})
}

func versionLink(fx *pvFixture) *softwarematch.FindingLink {
	return &softwarematch.FindingLink{
		AssetID: fx.asset.ID(), ProductID: shared.NewID(), VersionID: shared.NewID(),
		Product: "nginx", Version: "1.25.2", Source: "technology", LastSeenTool: softwarematch.ToolName,
	}
}

// The production case: a version-match finding (rule CVE-2023-44487) is
// re-checked by re-running the HTTP fingerprint, never by sending its CVE id
// to a sensor as a template id.
func TestRetest_VersionMatchFindingRunsTheFingerprintNotATemplate(t *testing.T) {
	fx := newPVFixture(t, vulnerability.FindingSourceVA, softwarematch.ToolName, "CVE-2023-44487")
	fx.versions.link = versionLink(fx)
	s := fx.service()

	rt, err := fx.request(t, s, ModeDefault)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if rt.Method != retestdom.MethodVersion {
		t.Fatalf("method %q, want version", rt.Method)
	}
	if len(fx.disp.tool) != 0 || len(fx.disp.validated) != 0 {
		t.Fatalf("a sensor job was queued for a version-match finding: tool=%d validate=%d", len(fx.disp.tool), len(fx.disp.validated))
	}
	if fx.fp.tool != "httpx" || fx.fp.target != "games.example.com" {
		t.Fatalf("fingerprint %q on %q, want httpx on games.example.com", fx.fp.tool, fx.fp.target)
	}
	if rt.RunID == nil || *rt.RunID != fx.fp.run || fx.store.runs[rt.ID] != fx.fp.run {
		t.Fatal("the retest is not linked to its fingerprint run")
	}
	if rt.TemplateID != "CVE-2023-44487" {
		t.Fatalf("rule %q", rt.TemplateID)
	}
}

func TestRetest_VersionMatchOfferSaysHowItIsChecked(t *testing.T) {
	fx := newPVFixture(t, vulnerability.FindingSourceVA, softwarematch.ToolName, "CVE-2023-44487")
	fx.versions.link = versionLink(fx)
	o, err := fx.service().Offer(context.Background(), fx.tenant, fx.finding.ID())
	if err != nil {
		t.Fatal(err)
	}
	want := Strategy{Kind: StrategyVersionRecheck, Rule: "CVE-2023-44487", Tool: "httpx", Product: "nginx", Version: "1.25.2"}
	if !o.Available || o.Strategy != want || o.ActiveCheck != nil {
		t.Fatalf("offer %+v, want available %+v and no active check", o, want)
	}
}

// No sensor runs the fingerprint tool: a typed refusal before anything is
// recorded, not a failed run.
func TestRetest_VersionMatchWithoutFingerprintSensorIsRefused(t *testing.T) {
	fx := newPVFixture(t, vulnerability.FindingSourceVA, softwarematch.ToolName, "CVE-2023-44487")
	fx.versions.link = versionLink(fx)
	fx.sensors.tools = map[string]bool{}
	s := fx.service()
	if _, err := fx.request(t, s, ModeDefault); !errors.Is(err, retestdom.ErrNoSensor) {
		t.Fatalf("err %v, want ErrNoSensor", err)
	}
	if len(fx.store.created) != 0 || fx.fp.tool != "" {
		t.Fatal("a refused retest recorded or dispatched something")
	}
	ok, reason, err := s.Availability(context.Background(), fx.tenant, fx.finding.ID())
	if err != nil || ok || reason != ReasonNoSensor {
		t.Fatalf("availability %v %q %v", ok, reason, err)
	}
}

func TestRetest_VersionFromAPackageIsNotRescanned(t *testing.T) {
	fx := newPVFixture(t, vulnerability.FindingSourceVA, softwarematch.ToolName, "CVE-2023-44487")
	link := versionLink(fx)
	link.Source = "package"
	fx.versions.link = link
	ok, reason, err := fx.service().Availability(context.Background(), fx.tenant, fx.finding.ID())
	if err != nil || ok || reason != ReasonVersionSourceNotRescannable {
		t.Fatalf("availability %v %q %v", ok, reason, err)
	}
}

// Another tenant's finding id is not found, also through the version path.
func TestRetest_VersionMatchOtherTenantIsNotFound(t *testing.T) {
	fx := newPVFixture(t, vulnerability.FindingSourceVA, softwarematch.ToolName, "CVE-2023-44487")
	fx.versions.link = versionLink(fx)
	_, err := fx.service().Request(context.Background(), RequestInput{TenantID: shared.NewID(), FindingID: fx.finding.ID(), Trigger: retestdom.TriggerManual})
	if !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("err %v, want not found", err)
	}
	if fx.fp.tool != "" {
		t.Fatal("a fingerprint ran for another tenant's finding")
	}
}

// A scanner reported the version-match finding since: that scanner re-runs
// its own rule.
func TestRetest_VersionMatchSeenByAScannerReRunsItsRule(t *testing.T) {
	fx := newPVFixture(t, vulnerability.FindingSourceVA, softwarematch.ToolName, "CVE-2023-44487")
	link := versionLink(fx)
	link.LastSeenTool = "nuclei"
	fx.versions.link = link
	rt, err := fx.request(t, fx.service(), ModeDefault)
	if err != nil {
		t.Fatal(err)
	}
	if rt.Method != retestdom.MethodTool || len(fx.disp.tool) != 1 || fx.disp.tool[0].Tool != "nuclei" || fx.fp.tool != "" {
		t.Fatalf("method %q tool jobs %d fingerprint %q", rt.Method, len(fx.disp.tool), fx.fp.tool)
	}
}

// The optional active check runs the CVE's template only on a sensor that
// ran it before, addressed to that sensor.
func TestRetest_ActiveCheckGoesToASensorThatHasTheTemplate(t *testing.T) {
	fx := newPVFixture(t, vulnerability.FindingSourceVA, softwarematch.ToolName, "CVE-2021-41773")
	fx.versions.link = versionLink(fx)
	ran := shared.NewID()
	fx.tmpl.sensors["CVE-2021-41773"] = []shared.ID{ran}
	fx.sensors.cands = []SensorCandidate{{ID: shared.NewID()}, {ID: ran}}
	s := fx.service()

	o, err := s.Offer(context.Background(), fx.tenant, fx.finding.ID())
	if err != nil || o.ActiveCheck == nil || !o.ActiveCheck.Available || o.ActiveCheck.Template != "CVE-2021-41773" {
		t.Fatalf("active check %+v %v", o.ActiveCheck, err)
	}
	rt, err := fx.request(t, s, ModeActiveCheck)
	if err != nil {
		t.Fatal(err)
	}
	if rt.Method != retestdom.MethodTool || len(fx.disp.tool) != 1 {
		t.Fatalf("method %q jobs %d", rt.Method, len(fx.disp.tool))
	}
	job := fx.disp.tool[0]
	if job.Tool != "nuclei" || job.RuleID != "CVE-2021-41773" || job.SensorID == nil || *job.SensorID != ran {
		t.Fatalf("job %+v", job)
	}
}

func TestRetest_ActiveCheckWithoutAKnownTemplateIsRefused(t *testing.T) {
	fx := newPVFixture(t, vulnerability.FindingSourceVA, softwarematch.ToolName, "CVE-2023-44487")
	fx.versions.link = versionLink(fx)
	s := fx.service()
	if _, err := fx.request(t, s, ModeActiveCheck); !errors.Is(err, retestdom.ErrNoTemplateSensor) {
		t.Fatalf("err %v, want ErrNoTemplateSensor", err)
	}
	if len(fx.disp.tool) != 0 || len(fx.store.created) != 0 {
		t.Fatal("a refused active check dispatched or recorded something")
	}
	// The sensor that ran it is offline: offered, not available.
	fx.tmpl.sensors["CVE-2023-44487"] = []shared.ID{shared.NewID()}
	o, err := s.Offer(context.Background(), fx.tenant, fx.finding.ID())
	if err != nil || o.ActiveCheck == nil || o.ActiveCheck.Available || o.ActiveCheck.Reason != ReasonNoTemplateSensor {
		t.Fatalf("active check %+v %v", o.ActiveCheck, err)
	}
}

func TestRetest_ActiveCheckOnlyForVersionFindings(t *testing.T) {
	fx := newPVFixture(t, vulnerability.FindingSourceDAST, "nuclei", "CVE-2021-41773")
	if _, err := fx.request(t, fx.service(), ModeActiveCheck); !errors.Is(err, shared.ErrValidation) || errors.Is(err, retestdom.ErrNotEligible) {
		t.Fatalf("err %v, want a validation error", err)
	}
}

// People's findings have no automatic retest: refused with a reason, no job.
func TestRetest_HumanFindingsHaveNoAutomaticRetest(t *testing.T) {
	for _, src := range []vulnerability.FindingSource{vulnerability.FindingSourceManual, vulnerability.FindingSourceBugBounty, vulnerability.FindingSourceRedTeam} {
		t.Run(string(src), func(t *testing.T) {
			fx := newPVFixture(t, src, "manual", "XSS-1")
			s := fx.service()
			_, err := fx.request(t, s, ModeDefault)
			if !errors.Is(err, retestdom.ErrNotEligible) || IneligibleReason(err) != ReasonNoAutomaticRetest {
				t.Fatalf("err %v (%s)", err, IneligibleReason(err))
			}
			o, err := s.Offer(context.Background(), fx.tenant, fx.finding.ID())
			if err != nil || o.Available || o.Reason != ReasonNoAutomaticRetest || o.Strategy.Kind != StrategyNone {
				t.Fatalf("offer %+v %v", o, err)
			}
			if len(fx.disp.tool)+len(fx.disp.validated) != 0 || len(fx.store.created) != 0 {
				t.Fatal("a job was queued")
			}
		})
	}
}

// A nuclei template re-run goes to the sensor that reported the finding.
func TestRetest_TemplateRetestGoesToTheSightingSensor(t *testing.T) {
	fx := newPVFixture(t, vulnerability.FindingSourceDAST, "nuclei", "apache-detect")
	sighting := shared.NewID()
	fx.finding.SetSensorID(sighting)
	fx.sensors.cands = []SensorCandidate{{ID: shared.NewID(), TemplatesVersion: "v10.3.0"}, {ID: sighting, TemplatesVersion: "v10.0.0"}}
	fx.findings.release = "v10.2.0"
	rt, err := fx.request(t, fx.service(), ModeDefault)
	if err != nil {
		t.Fatal(err)
	}
	if rt.Method != retestdom.MethodTool || len(fx.disp.tool) != 1 || fx.disp.tool[0].SensorID == nil || *fx.disp.tool[0].SensorID != sighting {
		t.Fatalf("method %q jobs %+v", rt.Method, fx.disp.tool)
	}
}

// Every online sensor has an older template release than the finding's: a
// typed refusal (and reason), not a run that fails "template not installed".
func TestRetest_TemplateRetestRefusedWhenNoSensorHasTheRelease(t *testing.T) {
	fx := newPVFixture(t, vulnerability.FindingSourceDAST, "nuclei", "apache-detect")
	fx.sensors.cands = []SensorCandidate{{ID: shared.NewID(), TemplatesVersion: "v9.8.0"}}
	fx.findings.release = "v10.2.0"
	s := fx.service()
	if _, err := fx.request(t, s, ModeDefault); !errors.Is(err, retestdom.ErrNoTemplateSensor) {
		t.Fatalf("err %v, want ErrNoTemplateSensor", err)
	}
	if len(fx.disp.tool) != 0 || len(fx.store.created) != 0 {
		t.Fatal("a refused retest dispatched or recorded something")
	}
	o, err := s.Offer(context.Background(), fx.tenant, fx.finding.ID())
	if err != nil || o.Available || o.Reason != ReasonNoTemplateSensor || o.Strategy.Kind != StrategyTemplate || o.Strategy.Rule != "apache-detect" {
		t.Fatalf("offer %+v %v", o, err)
	}
}

func TestRetest_SettleVersionRecheckFromTheRunAndTheInventory(t *testing.T) {
	fx := newPVFixture(t, vulnerability.FindingSourceVA, softwarematch.ToolName, "CVE-2023-44487")
	link := versionLink(fx)
	fx.versions.link = link
	done := time.Now().Add(-10 * time.Minute)
	runID := shared.NewID()
	s := fx.service()
	s.SetVersionRecheck(fx.versions, fx.fp, pvRuns{run: &scanrun.Run{Status: scanrun.RunStatusCompleted, CompletedAt: &done}})
	rt := &retestdom.Retest{ID: shared.NewID(), TenantID: fx.tenant, FindingID: fx.finding.ID(), TemplateID: "CVE-2023-44487",
		Method: retestdom.MethodVersion, RunID: &runID, CreatedAt: done.Add(-time.Minute), Status: retestdom.StatusPending}

	fx.versions.observed = []softwarematch.ObservedVersion{{VersionID: link.VersionID, Raw: "1.25.2", Comparable: true, Scheme: vulnmatch.SchemeGeneric}}
	if ok, err := s.trySettle(context.Background(), rt, false); err != nil || !ok {
		t.Fatalf("settle %v %v", ok, err)
	}
	got := fx.store.settled[len(fx.store.settled)-1]
	if got.Outcome != retestdom.OutcomeStillVulnerable || got.ReasonCode != retestdom.ReasonVersionStillAffected {
		t.Fatalf("settled %s/%s", got.Outcome, got.ReasonCode)
	}

	// Still running: wait.
	s.SetVersionRecheck(fx.versions, fx.fp, pvRuns{run: &scanrun.Run{Status: scanrun.RunStatusRunning}})
	if ok, _ := s.trySettle(context.Background(), rt, false); ok {
		t.Fatal("settled while the fingerprint run was still running")
	}
}

// A refused fingerprint scan (scope, ownership, tier) settles the retest as
// inconclusive and returns the error; nothing else is queued.
func TestRetest_VersionRecheckDispatchFailureSettlesInconclusive(t *testing.T) {
	fx := newPVFixture(t, vulnerability.FindingSourceVA, softwarematch.ToolName, "CVE-2023-44487")
	fx.versions.link = versionLink(fx)
	fx.fp.err = errors.New("refused")
	if _, err := fx.request(t, fx.service(), ModeDefault); err == nil {
		t.Fatal("want an error")
	}
	if len(fx.store.settled) != 1 || fx.store.settled[0].Outcome != retestdom.OutcomeInconclusive {
		t.Fatalf("settled %+v", fx.store.settled)
	}
}

// An imported finding of a tool no sensor runs says so.
func TestRetest_ImportedFindingWithoutSensorSaysImported(t *testing.T) {
	fx := newPVFixture(t, vulnerability.FindingSourceVA, "tenable", "19506")
	fx.finding.SetIngestChannel(vulnerability.IngestChannelIntegration)
	o, err := fx.service().Offer(context.Background(), fx.tenant, fx.finding.ID())
	if err != nil || o.Available || o.Reason != ReasonImportedNoRetest || o.Strategy.Kind != StrategyTemplate {
		t.Fatalf("offer %+v %v", o, err)
	}
}
