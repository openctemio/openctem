package ingest

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type deviceRepo struct {
	CorrelationRepo
	byIP map[string][]*asset.Asset
}

func (r deviceRepo) FindNetworkDevicesByIPs(_ context.Context, _ shared.ID, ips []string) (map[string][]*asset.Asset, error) {
	out := map[string][]*asset.Asset{}
	for _, ip := range ips {
		out[ip] = r.byIP[ip]
	}
	return out, nil
}

func netDevice(t *testing.T, tenant shared.ID, name, sub string) *asset.Asset {
	t.Helper()
	a, err := asset.NewAssetWithSubType(name, asset.AssetTypeNetwork, sub, asset.CriticalityLow)
	if err != nil {
		t.Fatal(err)
	}
	a.SetTenantID(tenant)
	a.MarkSeen()
	return a
}

// A device of another tenant, or a network segment, is never a match even
// when the store returns it; one device of the tenant is.
func TestCorrelateNetworkDevice(t *testing.T) {
	tenant := shared.NewID()
	props := map[string]any{"ip_addresses": []any{"192.0.2.1"}}
	cases := []struct {
		name  string
		found []*asset.Asset
		match bool
	}{
		{"own device", []*asset.Asset{netDevice(t, tenant, "core-sw-01", "switch")}, true},
		{"another tenant's device", []*asset.Asset{netDevice(t, shared.NewID(), "core-sw-01", "switch")}, false},
		{"a segment", []*asset.Asset{netDevice(t, tenant, "office-lan", "subnet")}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := NewAssetCorrelator(deviceRepo{byIP: map[string][]*asset.Asset{"192.0.2.1": tc.found}}, logger.NewNop(), CorrelationConfig{})
			res, err := c.CorrelateNetworkDevice(context.Background(), tenant, "192.0.2.1", props, CorrelationConfig{})
			if err != nil {
				t.Fatal(err)
			}
			if (res.Matched != nil) != tc.match {
				t.Fatalf("matched = %v, want %v", res.Matched != nil, tc.match)
			}
			if res.Matched != nil && res.ShouldRename {
				t.Fatal("an address must not rename a named device")
			}
		})
	}
}
