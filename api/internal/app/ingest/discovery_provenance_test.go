package ingest

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A sensor report cannot claim a provenance that keeps a planted asset out
// of the lifecycle (manual, import, integration) or a discovery time in the
// future; a trusted upload keeps what it says (sensor → platform review,
// discovery provenance).
func TestIngest_SensorCannotClaimProvenance(t *testing.T) {
	future := time.Now().Add(100 * 365 * 24 * time.Hour)
	report := func() *ctis.Report {
		return &ctis.Report{Assets: []ctis.Asset{{
			ID: "a1", Type: ctis.AssetTypeDomain, Value: "planted.example.com", Name: "planted.example.com",
			DiscoveredAt: &future,
			Properties:   ctis.Properties{asset.PropKeyDiscoverySource: "manual"},
		}}}
	}
	run := func(scope *alterScope) *asset.Asset {
		repo := newMemAssetRepo()
		p, _ := newDiscoveryProcessor(repo)
		tenant := shared.NewID()
		if _, err := p.processBatch(context.Background(), tenant, report(), &Output{}, nil, false, scope); err != nil {
			t.Fatal(err)
		}
		return repo.rows[tenant]["planted.example.com"]
	}

	got := run(newAlterScope(Binding{Kind: BindingCommand, Targets: []string{"example.com"}}))
	if got == nil {
		t.Fatal("asset not created")
	}
	if got.DiscoverySource() != DiscoverySourceSensor {
		t.Errorf("a sensor report recorded discovery_source %q, want %q", got.DiscoverySource(), DiscoverySourceSensor)
	}
	if d := got.DiscoveredAt(); d == nil || d.After(time.Now()) {
		t.Errorf("discovered_at %v is in the future", d)
	}

	trusted := run(fullScope())
	if trusted.DiscoverySource() != asset.DiscoverySourceManual {
		t.Errorf("a trusted upload recorded %q, want its own manual", trusted.DiscoverySource())
	}
}
