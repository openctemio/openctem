package toolfacts

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
)

const toywebDescriptor = `{"name":"toyweb","implements":[{"capability":"dast.web@1","params":{"max_duration_minutes":{"key":"max_minutes"},"profile":{"key":" "}}},{"capability":"made.up@1","params":{"x":{"key":"y"}}}]}`

func contract(version string, implements ...string) *sensor.ToolContract {
	return &sensor.ToolContract{APIVersion: sensor.ToolContractAPIVersion, Version: version, Class: "target-scan", Tier: "T2",
		Implements: implements, Digest: "sha256:" + version}
}

func manifest(tools ...sensor.ManifestTool) map[shared.ID]*sensor.ManifestVersion {
	return map[shared.ID]*sensor.ManifestVersion{shared.NewID(): {Manifest: sensor.Manifest{Tools: tools}}}
}

// A contract's capabilities, in its order, its batch flag and the param
// mapping of its descriptor become the tool's facts; a capability the
// taxonomy does not know, an empty key, a tool without a contract and a
// tool not installed contribute nothing.
func TestFacts_FromContracts(t *testing.T) {
	toy := contract("1.0.0", "dast.web@1")
	toy.Descriptor = json.RawMessage(toywebDescriptor)
	naabu := contract("2.0.0", "scan.ports@1", "discover.hosts@1")
	naabu.Batch = true
	facts := Facts(manifest(
		sensor.ManifestTool{Name: "ToyWeb", Installed: true, Contract: toy},
		sensor.ManifestTool{Name: "naabu", Installed: true, Contract: naabu},
		sensor.ManifestTool{Name: "nocontract", Installed: true},
		sensor.ManifestTool{Name: "absent", Installed: false, Contract: contract("1.0.0", "probe.http@1")},
	))
	if len(facts) != 2 || facts[0].Name != "naabu" || facts[1].Name != "toyweb" {
		t.Fatalf("facts = %+v", facts)
	}
	if !slices.Equal(facts[0].Implements, []stage.Key{stage.ScanPorts, stage.DiscoverHosts}) || !facts[0].Batch {
		t.Fatalf("naabu = %+v", facts[0])
	}
	if got := facts[1].Params[stage.DASTWeb]; len(got) != 1 || got["max_duration_minutes"] != "max_minutes" {
		t.Fatalf("toyweb params = %v", facts[1].Params)
	}
	if _, ok := facts[1].Params["made.up"]; ok {
		t.Fatal("a capability the contract does not implement got a mapping")
	}
}

// Per tool name the highest contract version wins, whichever sensor (the
// organization's or the platform's) reports it.
func TestFacts_HighestVersionWins(t *testing.T) {
	old := contract("1.2.0", "probe.http@1")
	newer := contract("1.10.0", "probe.http@1", "crawl.web@1")
	for _, order := range [][]map[shared.ID]*sensor.ManifestVersion{
		{manifest(sensor.ManifestTool{Name: "tool", Installed: true, Contract: old}), manifest(sensor.ManifestTool{Name: "tool", Installed: true, Contract: newer})},
		{manifest(sensor.ManifestTool{Name: "tool", Installed: true, Contract: newer}), manifest(sensor.ManifestTool{Name: "tool", Installed: true, Contract: old})},
	} {
		facts := Facts(order...)
		if len(facts) != 1 || len(facts[0].Implements) != 2 {
			t.Fatalf("facts = %+v", facts)
		}
	}
}

type fakeManifests struct {
	byTenant map[shared.ID]map[shared.ID]*sensor.ManifestVersion
	platform map[shared.ID]*sensor.ManifestVersion
	calls    int
	err      error
}

func (f *fakeManifests) CurrentManifestsByTenant(_ context.Context, tenantID shared.ID) (map[shared.ID]*sensor.ManifestVersion, error) {
	f.calls++
	return f.byTenant[tenantID], f.err
}

func (f *fakeManifests) CurrentPlatformManifests(context.Context) (map[shared.ID]*sensor.ManifestVersion, error) {
	return f.platform, f.err
}

// SECURITY: each organization's catalog is its own sensors' facts plus the
// platform's; the cache is keyed by organization and expires.
func TestLoader_PerTenantAndCached(t *testing.T) {
	a, b := shared.NewID(), shared.NewID()
	src := &fakeManifests{
		byTenant: map[shared.ID]map[shared.ID]*sensor.ManifestVersion{
			a: manifest(sensor.ManifestTool{Name: "tool-a", Installed: true, Contract: contract("1.0.0", "probe.http@1")}),
		},
		platform: manifest(sensor.ManifestTool{Name: "plat", Installed: true, Contract: contract("1.0.0", "crawl.web@1")}),
	}
	now := time.Unix(1000, 0)
	l := New(src)
	l.now = func() time.Time { return now }
	catA, err := l.Catalog(context.Background(), a)
	if err != nil {
		t.Fatal(err)
	}
	catB, _ := l.Catalog(context.Background(), b)
	if len(catA.ForTool("tool-a")) != 1 || len(catA.ForTool("plat")) != 1 {
		t.Fatal("tenant A misses its own or the platform's tool")
	}
	if len(catB.ForTool("tool-a")) != 0 || len(catB.ForTool("plat")) != 1 {
		t.Fatal("tenant B sees tenant A's tool, or misses the platform's")
	}
	_, _ = l.Catalog(context.Background(), a)
	if src.calls != 2 {
		t.Fatalf("manifest reads = %d, want 2 (one per tenant, then cached)", src.calls)
	}
	now = now.Add(CacheTTL + time.Second)
	_, _ = l.Catalog(context.Background(), a)
	if src.calls != 3 {
		t.Fatalf("manifest reads = %d after expiry, want 3", src.calls)
	}
	src.err = errors.New("db down")
	now = now.Add(CacheTTL + time.Second)
	if _, err := l.Catalog(context.Background(), a); err == nil {
		t.Fatal("a read error was hidden")
	}
	var nilLoader *Loader
	if cat, err := nilLoader.Catalog(context.Background(), a); err != nil || len(cat.ToolNames()) != 0 {
		t.Fatal("a nil loader must be the empty catalog")
	}
}
