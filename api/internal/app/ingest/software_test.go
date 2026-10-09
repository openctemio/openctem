package ingest

import (
	"context"
	"sort"
	"testing"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/software"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func TestSoftwareObservations(t *testing.T) {
	a := &ctis.Asset{
		ID:   "a1",
		Type: ctis.AssetTypeHTTPService,
		Technologies: []ctis.Technology{
			{Name: "WordPress", Version: "6.1.1", Confidence: 90},
			{Name: "nginx", CPE: "cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*"},
		},
		Services: []ctis.ServiceInfo{
			{Port: 22, Protocol: "tcp", Banner: "OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"},
			{Port: 3306, Product: "MySQL", Version: "5.7.33"},
		},
		IdentityHints: &ctis.IdentityHints{OSCPE: "cpe:/o:canonical:ubuntu_linux:20.04"},
		Properties: ctis.Properties{
			"technologies": []any{"PHP:7.4.3", "Cloudflare"},
			"server":       "Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips",
		},
	}
	got := softwareObservations(a)
	type row struct{ name, version, cpe, source, location string }
	var rows []row
	for _, o := range got {
		rows = append(rows, row{o.Name, o.Version, o.CPE, o.Source, o.Location})
	}
	want := []row{
		{"WordPress", "6.1.1", "", software.SourceTechnology, ""},
		{"nginx", "", "cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*", software.SourceTechnology, ""},
		{"OpenSSH", "8.2p1 Ubuntu-4ubuntu0.5", "", software.SourceService, "tcp/22"},
		{"MySQL", "5.7.33", "", software.SourceService, "tcp/3306"},
		{"", "", "cpe:/o:canonical:ubuntu_linux:20.04", software.SourceOS, ""},
		{"PHP", "7.4.3", "", software.SourceTechnology, ""},
		{"Cloudflare", "", "", software.SourceTechnology, ""},
		{"Apache", "2.4.6 (CentOS)", "", software.SourceService, ""},
		{"OpenSSL", "1.0.2k-fips", "", software.SourceService, ""},
	}
	if len(rows) != len(want) {
		t.Fatalf("got %d observations: %+v", len(rows), rows)
	}
	for i := range want {
		if rows[i] != want[i] {
			t.Errorf("observation %d = %+v, want %+v", i, rows[i], want[i])
		}
	}
	if got[0].ToolConfidence != 90 {
		t.Errorf("tool confidence lost")
	}
}

func TestSoftwareObservations_OpenPort(t *testing.T) {
	withBanner := &ctis.Asset{Type: ctis.AssetTypeOpenPort, Properties: ctis.Properties{
		"service": "ssh", "version": "OpenSSH 8.2p1 Ubuntu 4ubuntu0.5", "protocol": "tcp",
	}}
	got := softwareObservations(withBanner)
	if len(got) != 1 || got[0].Name != "OpenSSH" || got[0].Version != "8.2p1 Ubuntu 4ubuntu0.5" || got[0].Source != software.SourceOpenPort {
		t.Fatalf("got %+v", got)
	}
	// A bare version with a generic service name parses to nothing usable.
	bare := &ctis.Asset{Type: ctis.AssetTypeOpenPort, Properties: ctis.Properties{"service": "ssh", "version": "8.2p1"}}
	obs := softwareObservations(bare)
	if len(obs) != 1 {
		t.Fatalf("got %+v", obs)
	}
	if _, ok := software.Parse(obs[0]); ok {
		t.Fatal("generic service name became a product")
	}
}

// fakeSoftwareRepo records what ingest writes.
type fakeSoftwareRepo struct {
	resolved []software.Identity
	links    []software.Link
	curated  int
}

func (f *fakeSoftwareRepo) EnsureCurated(context.Context, []software.Curated) error {
	f.curated++
	return nil
}

func (f *fakeSoftwareRepo) Resolve(_ context.Context, _ shared.ID, ids []software.Identity) (map[software.Identity]software.ProductRef, error) {
	out := map[software.Identity]software.ProductRef{}
	for _, id := range ids {
		f.resolved = append(f.resolved, id)
		out[id] = software.ProductRef{ID: shared.NewID(), Global: id.Name == "nginx"}
	}
	return out, nil
}

func (f *fakeSoftwareRepo) EnsureVersion(context.Context, shared.ID, software.ProductRef, software.VersionKey) (shared.ID, error) {
	return shared.NewID(), nil
}

func (f *fakeSoftwareRepo) UpsertLinks(_ context.Context, _ shared.ID, links []software.Link) (software.LinkResult, error) {
	f.links = append(f.links, links...)
	ids := make([]shared.ID, 0, len(links))
	for _, l := range links {
		ids = append(ids, l.AssetID)
	}
	return software.LinkResult{Inserted: len(links), ChangedAssets: ids}, nil
}

type fakeSink struct{ assets []shared.ID }

func (f *fakeSink) SoftwareChanged(_ shared.ID, ids []shared.ID) { f.assets = append(f.assets, ids...) }

// Only assets the report may write get software; the curated list is
// written once; the matcher hears about changed assets.
func TestRecordSoftware_ScopeAndSink(t *testing.T) {
	repo := &fakeSoftwareRepo{}
	sink := &fakeSink{}
	s := &Service{logger: logger.NewNop()}
	s.SetSoftwareRepository(repo)
	s.SetSoftwareChangeSink(sink)

	allowed, denied := shared.NewID(), shared.NewID()
	report := &ctis.Report{Assets: []ctis.Asset{
		{ID: "a", Properties: ctis.Properties{"technologies": []any{"nginx:1.18.0"}}},
		{ID: "b", Properties: ctis.Properties{"technologies": []any{"nginx:1.20.0"}}},
		{ID: "c", Properties: ctis.Properties{"technologies": []any{"nginx:1.22.0"}}}, // not in the map
	}}
	scope := &alterScope{allowed: map[shared.ID]bool{allowed: true}}
	s.recordSoftware(context.Background(), shared.NewID(), scope, report, map[string]shared.ID{"a": allowed, "b": denied})
	s.recordSoftware(context.Background(), shared.NewID(), scope, report, map[string]shared.ID{"a": allowed, "b": denied})

	if repo.curated != 1 {
		t.Errorf("curated written %d times", repo.curated)
	}
	if len(repo.links) != 2 || repo.links[0].AssetID != allowed || repo.links[1].AssetID != allowed {
		t.Fatalf("links: %+v", repo.links)
	}
	if repo.links[0].Confidence != software.ConfidenceCuratedName {
		t.Errorf("confidence %d", repo.links[0].Confidence)
	}
	if len(sink.assets) != 2 || sink.assets[0] != allowed {
		t.Errorf("sink: %+v", sink.assets)
	}
}

func TestRecordSoftware_Caps(t *testing.T) {
	repo := &fakeSoftwareRepo{}
	s := &Service{logger: logger.NewNop()}
	s.SetSoftwareRepository(repo)
	techs := make([]any, 0, 300)
	for i := 0; i < 300; i++ {
		techs = append(techs, "product"+string(rune('a'+i%26))+string(rune('a'+i/26))+":1.0.0")
	}
	assetMap := map[string]shared.ID{}
	report := &ctis.Report{}
	for i := 0; i < 30; i++ {
		ref := "asset" + string(rune('a'+i))
		report.Assets = append(report.Assets, ctis.Asset{ID: ref, Properties: ctis.Properties{"technologies": techs}})
		assetMap[ref] = shared.NewID()
	}
	s.recordSoftware(context.Background(), shared.NewID(), &alterScope{all: true}, report, assetMap)
	per := map[shared.ID]int{}
	for _, l := range repo.links {
		per[l.AssetID]++
	}
	counts := make([]int, 0, len(per))
	for _, n := range per {
		counts = append(counts, n)
	}
	sort.Ints(counts)
	if len(repo.links) != maxSoftwarePerReport || counts[len(counts)-1] != maxSoftwarePerAsset {
		t.Fatalf("links %d, max per asset %d", len(repo.links), counts[len(counts)-1])
	}
}
