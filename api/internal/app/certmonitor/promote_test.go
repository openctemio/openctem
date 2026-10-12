package certmonitor

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/ingest"
	assetdom "github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/verifieddomain"
)

// fakeInventory is an asset store the fake ingester writes into.
type fakeInventory struct {
	byName  map[string]*assetdom.Asset
	ingests int
	tenants []shared.ID
	reports [][]string
}

func newFakeInventory() *fakeInventory { return &fakeInventory{byName: map[string]*assetdom.Asset{}} }

func (f *fakeInventory) GetByNames(_ context.Context, _ shared.ID, names []string) (map[string]*assetdom.Asset, error) {
	out := map[string]*assetdom.Asset{}
	for _, n := range names {
		if a, ok := f.byName[n]; ok {
			out[n] = a
		}
	}
	return out, nil
}

func (f *fakeInventory) Ingest(_ context.Context, agt *sensor.Sensor, in ingest.Input) (*ingest.Output, error) {
	f.ingests++
	f.tenants = append(f.tenants, *agt.TenantID)
	out := &ingest.Output{AssetMap: map[string]shared.ID{}}
	var names []string
	for _, a := range in.Report.Assets {
		if a.Properties[assetdom.PropKeyDiscoverySource] != assetdom.DiscoverySourceCertTransparency {
			return nil, fmt.Errorf("discovery source not stamped on %s", a.Value)
		}
		as, err := assetdom.NewAssetWithTenant(*agt.TenantID, a.Value, assetdom.AssetTypeSubdomain, assetdom.CriticalityMedium)
		if err != nil {
			return nil, err
		}
		f.byName[a.Value] = as
		out.AssetMap[a.ID] = as.ID()
		names = append(names, a.Value)
	}
	f.reports = append(f.reports, names)
	return out, nil
}

// memAttribution is an in-memory AttributionStore.
type memAttribution struct {
	evidence map[string]map[attribution.Rule]attribution.Evidence
	records  map[string]attribution.Record
}

func newMemAttribution() *memAttribution {
	return &memAttribution{evidence: map[string]map[attribution.Rule]attribution.Evidence{}, records: map[string]attribution.Record{}}
}

func (m *memAttribution) UpsertEvidence(_ context.Context, _ shared.ID, ev []attribution.Evidence) error {
	for _, e := range ev {
		if m.evidence[e.AssetID] == nil {
			m.evidence[e.AssetID] = map[attribution.Rule]attribution.Evidence{}
		}
		m.evidence[e.AssetID][e.Rule] = e
	}
	return nil
}

func (m *memAttribution) FiredRules(_ context.Context, _ shared.ID, ids []string) (map[string][]attribution.Rule, error) {
	out := map[string][]attribution.Rule{}
	for _, id := range ids {
		for r := range m.evidence[id] {
			out[id] = append(out[id], r)
		}
	}
	return out, nil
}

func (m *memAttribution) Records(_ context.Context, _ shared.ID, ids []string) (map[string]attribution.Record, error) {
	out := map[string]attribution.Record{}
	for _, id := range ids {
		if r, ok := m.records[id]; ok {
			out[id] = r
		}
	}
	return out, nil
}

func (m *memAttribution) SaveAutomatic(_ context.Context, _ shared.ID, id string, d attribution.Decision) error {
	if cur, ok := m.records[id]; ok && cur.HumanDecided {
		return nil
	}
	m.records[id] = attribution.Record{State: d.State, Confidence: d.Confidence, Reason: d.Reason}
	return nil
}

// ctNames serves, for any queried domain, the given labels under it with a
// current certificate, plus a wildcard-only and a long-expired name.
func ctNames(t *testing.T, labels ...string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d := strings.TrimPrefix(r.URL.Query().Get("q"), "%.")
		future := time.Now().UTC().Add(200 * 24 * time.Hour).Format("2006-01-02T15:04:05")
		past := time.Now().UTC().Add(-400 * 24 * time.Hour).Format("2006-01-02T15:04:05")
		var names []string
		for _, l := range labels {
			names = append(names, l+"."+d)
		}
		_, _ = fmt.Fprintf(w, `[
		  {"name_value":%q,"not_before":"2026-01-05T00:00:00","not_after":%q,"issuer_name":"CA"},
		  {"name_value":"*.wild.%s","not_after":%q},
		  {"name_value":"old.%s","not_after":%q}
		]`, strings.Join(names, "\n"), future, d, future, d, past)
	}))
}

func promotionService(t *testing.T, srvURL string, client *http.Client, tenant shared.ID, assets []*assetdom.Asset) (*Service, *fakeInventory, *memAttribution) {
	t.Helper()
	inv := newFakeInventory()
	for _, a := range assets {
		inv.byName[a.Name()] = a
	}
	attr := newMemAttribution()
	svc := NewService(&fakeAssetRepo{assets: assets}, newFakeExposureRepo(), srvURL, testLogger())
	svc.setHTTPClient(client)
	svc.SetPromotion(inv, inv, attr)
	return svc, inv, attr
}

// Names under a verified domain become confirmed assets (O4: strong rule,
// 99); names under a domain the tenant only listed wait for review (85).
// Wildcard-only and long-expired names are not promoted.
func TestPromote_StatesByRootOrigin(t *testing.T) {
	tenant := shared.NewID()
	srv := ctNames(t, "www", "api")
	defer srv.Close()

	listed := mustDomainAsset(t, tenant, "listed.com")
	svc, inv, attr := promotionService(t, srv.URL, srv.Client(), tenant, []*assetdom.Asset{listed})
	now := time.Now().UTC()
	svc.SetDomainSources(fakeVerified{list: []*verifieddomain.VerifiedDomain{
		verifieddomain.Reconstruct(shared.NewID(), tenant, "proven.com", "tok", verifieddomain.StatusVerified, &now, &now, now, now),
	}}, nil)

	if _, err := svc.MonitorTenant(context.Background(), tenant); err != nil {
		t.Fatal(err)
	}
	want := map[string]attribution.State{
		"www.proven.com": attribution.StateConfirmed, "api.proven.com": attribution.StateConfirmed,
		"www.listed.com": attribution.StateNeedsReview, "api.listed.com": attribution.StateNeedsReview,
	}
	for name, state := range want {
		a, ok := inv.byName[name]
		if !ok {
			t.Errorf("%s not promoted", name)
			continue
		}
		rec := attr.records[a.ID().String()]
		if rec.State != state {
			t.Errorf("%s: state %q, want %q", name, rec.State, state)
		}
		if len(attr.evidence[a.ID().String()]) != 1 {
			t.Errorf("%s: %d evidence rows, want 1", name, len(attr.evidence[a.ID().String()]))
		}
	}
	for _, name := range []string{"wild.proven.com", "old.proven.com", "wild.listed.com", "old.listed.com"} {
		if _, ok := inv.byName[name]; ok {
			t.Errorf("%s promoted (wildcard-only or long expired)", name)
		}
	}
	for _, tn := range inv.tenants {
		if tn != tenant {
			t.Fatalf("ingested under tenant %s, want %s", tn, tenant)
		}
	}
	ev := attr.evidence[inv.byName["www.proven.com"].ID().String()][attribution.RuleVerifiedRoot]
	if ev.Technique != assetdom.DiscoverySourceCertTransparency || ev.Source != SourceCRTSH || ev.Observed["root"] != "proven.com" {
		t.Errorf("evidence = %+v", ev)
	}
}

// A name that is already an asset keeps its standing: a legacy asset (no
// record) gets evidence but no needs_review record, and is not re-ingested.
func TestPromote_ExistingAssetKeepsStanding(t *testing.T) {
	tenant := shared.NewID()
	srv := ctNames(t, "www")
	defer srv.Close()
	listed := mustDomainAsset(t, tenant, "listed.com")
	legacy, _ := assetdom.NewAssetWithTenant(tenant, "www.listed.com", assetdom.AssetTypeSubdomain, assetdom.CriticalityHigh)
	svc, inv, attr := promotionService(t, srv.URL, srv.Client(), tenant, []*assetdom.Asset{listed, legacy})

	if _, err := svc.MonitorTenant(context.Background(), tenant); err != nil {
		t.Fatal(err)
	}
	if inv.ingests != 0 {
		t.Errorf("an existing asset was re-ingested %d times", inv.ingests)
	}
	if _, ok := attr.records[legacy.ID().String()]; ok {
		t.Error("legacy asset got an attribution record (would demote it to needs_review)")
	}
	if len(attr.evidence[legacy.ID().String()]) != 1 {
		t.Error("legacy asset got no evidence")
	}
}

// Automation never overrides a human decision, and re-runs are idempotent.
func TestPromote_HumanDecisionAndRerun(t *testing.T) {
	tenant := shared.NewID()
	srv := ctNames(t, "www")
	defer srv.Close()
	listed := mustDomainAsset(t, tenant, "listed.com")
	svc, inv, attr := promotionService(t, srv.URL, srv.Client(), tenant, []*assetdom.Asset{listed})

	if _, err := svc.MonitorTenant(context.Background(), tenant); err != nil {
		t.Fatal(err)
	}
	id := inv.byName["www.listed.com"].ID().String()
	attr.records[id] = attribution.Record{State: attribution.StateRejected, HumanDecided: true}

	if _, err := svc.MonitorTenant(context.Background(), tenant); err != nil {
		t.Fatal(err)
	}
	if attr.records[id].State != attribution.StateRejected {
		t.Errorf("human rejection overridden: %+v", attr.records[id])
	}
	if inv.ingests != 1 {
		t.Errorf("second run re-ingested an existing name (%d ingests)", inv.ingests)
	}
}

// The per-run cap bounds new assets; verified names go first.
func TestPromote_CapPrefersVerified(t *testing.T) {
	tenant := shared.NewID()
	labels := make([]string, 30)
	for i := range labels {
		labels[i] = fmt.Sprintf("h%02d", i)
	}
	srv := ctNames(t, labels...)
	defer srv.Close()
	listed := mustDomainAsset(t, tenant, "listed.com")
	svc, inv, _ := promotionService(t, srv.URL, srv.Client(), tenant, []*assetdom.Asset{listed})
	now := time.Now().UTC()
	svc.SetDomainSources(fakeVerified{list: []*verifieddomain.VerifiedDomain{
		verifieddomain.Reconstruct(shared.NewID(), tenant, "proven.com", "tok", verifieddomain.StatusVerified, &now, &now, now, now),
	}}, nil)
	svc.maxPromotions = 40

	if _, err := svc.MonitorTenant(context.Background(), tenant); err != nil {
		t.Fatal(err)
	}
	var verified, listedN int
	for n := range inv.byName {
		switch {
		case strings.HasSuffix(n, ".proven.com"):
			verified++
		case strings.HasSuffix(n, ".listed.com") && n != "listed.com":
			listedN++
		}
	}
	if verified != 30 || listedN != 10 {
		t.Fatalf("promoted %d verified + %d listed, want 30 + 10 (cap 40, verified first)", verified, listedN)
	}
}

// Without promotion wired the sweep behaves as before: exposures only.
func TestPromote_OffWithoutWiring(t *testing.T) {
	tenant := shared.NewID()
	srv := ctNames(t, "www")
	defer srv.Close()
	svc := NewService(&fakeAssetRepo{assets: []*assetdom.Asset{mustDomainAsset(t, tenant, "listed.com")}}, newFakeExposureRepo(), srv.URL, testLogger())
	svc.setHTTPClient(srv.Client())
	if n, err := svc.MonitorTenant(context.Background(), tenant); err != nil || n == 0 {
		t.Fatalf("n=%d err=%v", n, err)
	}
}

// fakeJoin covers the names under one root; err makes it fail.
type fakeJoin struct {
	root  string
	err   error
	asked map[string]string
}

func (f *fakeJoin) JoinEvidence(_ context.Context, _ shared.ID, names map[string]string) ([]attribution.Evidence, error) {
	f.asked = names
	if f.err != nil {
		return nil, f.err
	}
	var out []attribution.Evidence
	for id, n := range names {
		if strings.HasSuffix(n, "."+f.root) {
			out = append(out, attribution.Evidence{AssetID: id, Rule: attribution.RuleMatchesScopeTarget, Weight: 0.99, Source: "scope_target:x"})
		}
	}
	return out, nil
}

// A promoted name a permanent scope target covers is confirmed without
// review (RFC-054 §4.3); a name it does not cover still waits; a failing
// join confirms nothing.
func TestPromote_ScopeJoinConfirms(t *testing.T) {
	tenant := shared.NewID()
	srv := ctNames(t, "www")
	defer srv.Close()
	listed := mustDomainAsset(t, tenant, "listed.com")
	other := mustDomainAsset(t, tenant, "other.com")
	svc, inv, attr := promotionService(t, srv.URL, srv.Client(), tenant, []*assetdom.Asset{listed, other})
	join := &fakeJoin{root: "listed.com"}
	svc.SetScopeJoin(join)
	if _, err := svc.MonitorTenant(context.Background(), tenant); err != nil {
		t.Fatal(err)
	}
	if got := attr.records[inv.byName["www.listed.com"].ID().String()].State; got != attribution.StateConfirmed {
		t.Errorf("www.listed.com = %q, want confirmed through matches_scope_target", got)
	}
	if got := attr.records[inv.byName["www.other.com"].ID().String()].State; got != attribution.StateNeedsReview {
		t.Errorf("www.other.com = %q, want needs_review", got)
	}
	if len(join.asked) == 0 {
		t.Fatal("the join was not asked")
	}

	tenant2 := shared.NewID()
	listed2 := mustDomainAsset(t, tenant2, "listed.com")
	svc2, inv2, attr2 := promotionService(t, srv.URL, srv.Client(), tenant2, []*assetdom.Asset{listed2})
	svc2.SetScopeJoin(&fakeJoin{root: "listed.com", err: fmt.Errorf("db down")})
	if _, err := svc2.MonitorTenant(context.Background(), tenant2); err != nil {
		t.Fatal(err)
	}
	if got := attr2.records[inv2.byName["www.listed.com"].ID().String()].State; got != attribution.StateNeedsReview {
		t.Errorf("a failing join confirmed a name: %q", got)
	}
}
