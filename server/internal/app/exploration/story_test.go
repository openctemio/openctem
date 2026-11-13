package exploration

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	assetdom "github.com/openctemio/openctem/server/pkg/domain/asset"
	"github.com/openctemio/openctem/server/pkg/domain/exploration"
	"github.com/openctemio/openctem/server/pkg/domain/ingestreceipt"
	scopedom "github.com/openctemio/openctem/server/pkg/domain/scope"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/vulnerability"
)

type fakeFindings struct{ f *vulnerability.Finding }

func (r fakeFindings) GetFindingWithScope(_ context.Context, _, id, _ string, _ bool) (*vulnerability.Finding, error) {
	if r.f == nil || r.f.ID().String() != id {
		return nil, shared.ErrNotFound
	}
	return r.f, nil
}

type fakeAssets struct {
	visible map[shared.ID]*assetdom.Asset
	lineage map[shared.ID]*assetdom.Lineage
}

func (r fakeAssets) GetAssetInCallerScope(_ context.Context, _, id string) (*assetdom.Asset, error) {
	for k, a := range r.visible {
		if k.String() == id {
			return a, nil
		}
	}
	return nil, shared.ErrNotFound
}

func (r fakeAssets) GetLineage(_ context.Context, _, id string) (*assetdom.Lineage, error) {
	for k, l := range r.lineage {
		if k.String() == id {
			return l, nil
		}
	}
	return nil, shared.ErrNotFound
}

type fakeSightings []ingestreceipt.Sighting

func (s fakeSightings) FindingSightings(context.Context, shared.ID, shared.ID) ([]ingestreceipt.Sighting, error) {
	return s, nil
}

type fakeStore struct {
	runs                []exploration.ScanStep
	discovered, scanned *exploration.ScanStep
	receipt             *exploration.ReceiptRef
	calls               int
}

func (s *fakeStore) ScanRuns(context.Context, shared.ID, []exploration.RunRef) ([]exploration.ScanStep, error) {
	s.calls++
	return s.runs, nil
}

func (s *fakeStore) AssetRuns(context.Context, shared.ID, shared.ID) (*exploration.ScanStep, *exploration.ScanStep, error) {
	return s.discovered, s.scanned, nil
}

func (s *fakeStore) AssetReceipt(context.Context, shared.ID, shared.ID) (*exploration.ReceiptRef, error) {
	return s.receipt, nil
}

type fakeScope struct{ entries []*scopedom.Target }

func (m fakeScope) Covering(v string) *scopedom.Target {
	for _, t := range m.entries {
		if t.Matches(v) {
			return t
		}
	}
	return nil
}

func (m fakeScope) Exclusion(string) *scopedom.RuleRef { return nil }

const hiddenMarker = "hidden-mid.example.com"

type storyFixture struct {
	tenant          shared.ID
	asset, mid, top *assetdom.Asset
	finding         *vulnerability.Finding
	run, step       shared.ID
	sensor          shared.ID
	svc             *StoryService
	store           *fakeStore
}

func newStoryFixture(t *testing.T, assetVisible bool) *storyFixture {
	t.Helper()
	f := &storyFixture{tenant: shared.NewID(), run: shared.NewID(), step: shared.NewID(), sensor: shared.NewID()}
	mk := func(name string, typ assetdom.AssetType) *assetdom.Asset {
		a, err := assetdom.NewAsset(name, typ, assetdom.CriticalityHigh)
		if err != nil {
			t.Fatal(err)
		}
		a.SetTenantID(f.tenant)
		return a
	}
	f.top = mk("example.com", assetdom.AssetTypeDomain)
	f.mid = mk(hiddenMarker, assetdom.AssetTypeSubdomain)
	f.asset = mk("api.example.com", assetdom.AssetTypeSubdomain)
	fin, err := vulnerability.NewFinding(f.tenant, f.asset.ID(), vulnerability.FindingSourceDAST, "nuclei",
		vulnerability.SeverityHigh, "m")
	if err != nil {
		t.Fatal(err)
	}
	fin.SetTitle("Exposed admin panel")
	f.finding = fin
	disc := time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC)
	lin := &assetdom.Lineage{Nodes: []assetdom.LineageNode{
		{Depth: 0, ID: f.asset.ID(), Name: f.asset.Name(), Type: assetdom.AssetTypeSubdomain, DiscoverySource: "dns",
			DiscoveryTool: "subfinder", DiscoveredAt: &disc},
		// The caller may not see the middle ancestor.
		{Depth: 1, Hidden: true, Via: "parent"},
		{Depth: 2, ID: f.top.ID(), Name: "example.com", Type: assetdom.AssetTypeDomain, Via: "contains"},
	}}
	assets := fakeAssets{visible: map[shared.ID]*assetdom.Asset{}, lineage: map[shared.ID]*assetdom.Lineage{f.asset.ID(): lin}}
	if assetVisible {
		assets.visible[f.asset.ID()] = f.asset
	}
	scanID := shared.NewID()
	sightings := fakeSightings{}
	base := time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC)
	for i, tool := range []string{"zap", "nuclei", "httpx", "trivy"} {
		s := ingestreceipt.Sighting{Channel: ingestreceipt.ChannelUpload, Tool: tool,
			FirstSeenAt: base.Add(time.Duration(i+1) * time.Hour), LastSeenAt: base.Add(48 * time.Hour), SeenCount: 1}
		if tool == "nuclei" {
			// The first reporter: a scan run on the tenant's sensor.
			s.Channel, s.FirstSeenAt = ingestreceipt.ChannelScan, base
			s.SensorID, s.SensorName = &f.sensor, "dmz-sensor"
			s.LastRunID, s.LastStepRunID = &f.run, &f.step
		}
		sightings = append(sightings, s)
	}
	at := base.Add(-time.Hour)
	f.store = &fakeStore{runs: []exploration.ScanStep{{RunID: f.run, StepRunID: &f.step, ScanID: &scanID, ScanName: "weekly",
		StepName: "Probe web", Capability: "probe.http", Tool: "nuclei", RunStatus: "completed", At: &at}}}
	entry, err := scopedom.NewTarget(f.tenant, scopedom.TargetTypeDomain, "*.example.com", "", "test")
	if err != nil {
		t.Fatal(err)
	}
	matchers := func(context.Context, string) (ScopeMatcher, error) {
		return fakeScope{entries: []*scopedom.Target{entry}}, nil
	}
	f.svc = NewStoryService(fakeFindings{f: fin}, assets, sightings, f.store, matchers)
	return f
}

func kinds(s *exploration.Story) string {
	out := make([]string, 0, len(s.Steps))
	for _, st := range s.Steps {
		k := string(st.Kind)
		if st.Hidden {
			k += "(hidden)"
		}
		out = append(out, k)
	}
	return strings.Join(out, " > ")
}

// The whole chain for a caller who may see everything: scope entry, the
// discovery chain root first, the first reporters (each after its run),
// the finding last; the fourth source is counted, not listed.
func TestFindingStory_FullChainInOrder(t *testing.T) {
	f := newStoryFixture(t, true)
	s, err := f.svc.FindingStory(context.Background(), f.tenant.String(), f.finding.ID().String(),
		Access{IsAdmin: true, Scans: true, Sensors: true, Scope: true})
	if err != nil {
		t.Fatal(err)
	}
	want := "scope_entry > asset > asset(hidden) > asset > scan > report > report > report > finding"
	if got := kinds(s); got != want {
		t.Fatalf("chain\n got %s\nwant %s", got, want)
	}
	if s.Hidden != 1 || s.MoreReports != 1 || s.Subject.Kind != SubjectFinding || s.Subject.ID != f.finding.ID() {
		t.Fatalf("story: hidden %d more %d subject %+v", s.Hidden, s.MoreReports, s.Subject)
	}
	if sc := s.Steps[0].Scope; sc == nil || sc.Pattern != "*.example.com" || sc.AssetID != f.asset.ID() {
		t.Fatalf("scope step: %+v", sc)
	}
	if a := s.Steps[3].Asset; a == nil || a.ID != f.asset.ID() || a.DiscoveryTool != "subfinder" || a.Subject {
		t.Fatalf("finding's asset: %+v", a)
	}
	if sc := s.Steps[4].Scan; sc == nil || sc.Role != exploration.ScanReported || sc.ScanName != "weekly" || sc.Capability != "probe.http" {
		t.Fatalf("scan step: %+v", sc)
	}
	if r := s.Steps[5].Report; r == nil || r.Tool != "nuclei" || r.SensorName != "dmz-sensor" {
		t.Fatalf("first reporter: %+v", r)
	}
	if fs := s.Steps[8].Finding; fs == nil || fs.Title != "Exposed admin panel" {
		t.Fatalf("finding step: %+v", s.Steps[8])
	}
}

// A member without scans:read, sensors:read or the scope permission: the
// run is a hidden step (never read), the sensor is left out, and no scope
// entry is evaluated.
func TestFindingStory_PermissionsNarrowTheStory(t *testing.T) {
	f := newStoryFixture(t, true)
	s, err := f.svc.FindingStory(context.Background(), f.tenant.String(), f.finding.ID().String(), Access{UserID: shared.NewID().String()})
	if err != nil {
		t.Fatal(err)
	}
	want := "asset > asset(hidden) > asset > scan(hidden) > report > report > report > finding"
	if got := kinds(s); got != want {
		t.Fatalf("chain\n got %s\nwant %s", got, want)
	}
	if f.store.calls != 0 {
		t.Fatalf("runs read without scans:read")
	}
	body, _ := json.Marshal(s)
	for _, leak := range []string{"dmz-sensor", f.sensor.String(), "weekly", "Probe web", "*.example.com", hiddenMarker} {
		if strings.Contains(string(body), leak) {
			t.Fatalf("story leaks %q: %s", leak, body)
		}
	}
}

// A finding the caller may read (assigned to them) on an asset outside
// their scope: the asset is one hidden step, its chain and scope are not
// read, and its name never appears.
func TestFindingStory_AssetOutOfScopeIsOneHiddenStep(t *testing.T) {
	f := newStoryFixture(t, false)
	s, err := f.svc.FindingStory(context.Background(), f.tenant.String(), f.finding.ID().String(),
		Access{UserID: shared.NewID().String(), Scans: true, Scope: true})
	if err != nil {
		t.Fatal(err)
	}
	if got := kinds(s); !strings.HasPrefix(got, "asset(hidden) > scan > report") {
		t.Fatalf("chain: %s", got)
	}
	body, _ := json.Marshal(s)
	for _, leak := range []string{f.asset.Name(), f.asset.ID().String(), "example.com"} {
		if strings.Contains(string(body), leak) {
			t.Fatalf("story leaks %q: %s", leak, body)
		}
	}
}

// Not readable as a finding: not found, nothing composed.
func TestFindingStory_NotReadableIsNotFound(t *testing.T) {
	f := newStoryFixture(t, true)
	if _, err := f.svc.FindingStory(context.Background(), f.tenant.String(), shared.NewID().String(), Access{IsAdmin: true}); err == nil {
		t.Fatal("story of a finding the caller cannot read")
	}
	if _, err := f.svc.AssetStory(context.Background(), f.tenant.String(), f.mid.ID().String(), Access{IsAdmin: true}); err == nil {
		t.Fatal("story of an asset the caller cannot read")
	}
}

// An asset story: the run that derived it sits before it, the upload that
// created it and the latest run that scanned it after it.
func TestAssetStory_DiscoveredUploadedScanned(t *testing.T) {
	f := newStoryFixture(t, true)
	at := time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)
	f.store.discovered = &exploration.ScanStep{Role: exploration.ScanDiscovered, RunID: shared.NewID(), Relation: "resolves_to", At: &at}
	f.store.scanned = &exploration.ScanStep{Role: exploration.ScanScanned, RunID: shared.NewID(), At: &at}
	f.store.receipt = &exploration.ReceiptRef{ID: shared.NewID(), SourceKind: "upload", Tool: "nessus", At: at}
	s, err := f.svc.AssetStory(context.Background(), f.tenant.String(), f.asset.ID().String(),
		Access{IsAdmin: true, Scans: true, Scope: true})
	if err != nil {
		t.Fatal(err)
	}
	want := "scope_entry > asset > asset(hidden) > scan > asset > report > scan"
	if got := kinds(s); got != want {
		t.Fatalf("chain\n got %s\nwant %s", got, want)
	}
	if a := s.Steps[4].Asset; a == nil || !a.Subject {
		t.Fatalf("subject step: %+v", s.Steps[4])
	}
	if r := s.Steps[5].Report; r == nil || r.Channel != "upload" || r.Tool != "nessus" || r.ReceiptID == nil {
		t.Fatalf("upload step: %+v", r)
	}

	// Without scans:read both runs are hidden steps.
	s, err = f.svc.AssetStory(context.Background(), f.tenant.String(), f.asset.ID().String(), Access{IsAdmin: true})
	if err != nil {
		t.Fatal(err)
	}
	if got := kinds(s); got != "asset > asset(hidden) > scan(hidden) > asset > report > scan(hidden)" || s.Hidden != 3 {
		t.Fatalf("no scans:read: %s (hidden %d)", got, s.Hidden)
	}
}
