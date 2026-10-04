package ingest

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// ipOnlyRepo answers FindByIPs with a fixed set of assets; the other lookups
// are not used by CorrelateHost.
type ipOnlyRepo struct {
	CorrelationRepo
	byIP map[string][]*asset.Asset
}

func (r ipOnlyRepo) FindByIPs(_ context.Context, _ shared.ID, ips []string) (map[string][]*asset.Asset, error) {
	out := make(map[string][]*asset.Asset)
	for _, ip := range ips {
		if as, ok := r.byIP[ip]; ok {
			out[ip] = as
		}
	}
	return out, nil
}

func hostSeenAgo(t *testing.T, name string, ago time.Duration) *asset.Asset {
	t.Helper()
	seen := time.Now().Add(-ago)
	return asset.Reconstitute(shared.NewID(), shared.NewID(), nil, name,
		asset.AssetTypeHost, asset.CriticalityMedium, asset.StatusActive, asset.ScopeInternal,
		asset.ExposureUnknown, 0, 0, "", nil, map[string]any{"ip_addresses": []any{"10.9.0.5"}},
		"", "", "", "", nil, "", "", "", nil,
		nil, "", false, false, nil, false, nil, "", "", "", "",
		seen, seen, seen, seen)
}

// TestCorrelateHost_IPTrustWindow pins the owner's 7-day rule: an IP match
// counts only if the matched asset was seen within the last 7 days. A DHCP
// lease handed to another machine after 8 days must not merge or rename.
func TestCorrelateHost_IPTrustWindow(t *testing.T) {
	if DefaultIPTrustWindowDays != 7 {
		t.Fatalf("DefaultIPTrustWindowDays = %d, want 7", DefaultIPTrustWindowDays)
	}
	tests := []struct {
		name      string
		ago       time.Duration
		wantMatch bool
	}{
		{"seen 6 days ago", 6 * 24 * time.Hour, true},
		{"seen 8 days ago (DHCP reuse)", 8 * 24 * time.Hour, false},
		{"seen 29 days ago (inside the old 30-day window)", 29 * 24 * time.Hour, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			old := hostSeenAgo(t, "old-host", tt.ago)
			c := NewAssetCorrelator(ipOnlyRepo{byIP: map[string][]*asset.Asset{"10.9.0.5": {old}}},
				logger.NewNop(), CorrelationConfig{})
			res, err := c.CorrelateHost(context.Background(), shared.NewID(), "new-host",
				map[string]any{"ip_addresses": []any{"10.9.0.5"}})
			if err != nil {
				t.Fatal(err)
			}
			if got := res.Matched != nil; got != tt.wantMatch {
				t.Fatalf("matched = %v, want %v", got, tt.wantMatch)
			}
			if !tt.wantMatch && res.ShouldRename {
				t.Fatal("an IP outside the window must not rename the asset")
			}
		})
	}
}

// A tenant override still wins over the system default.
func TestCorrelateHost_TenantWindowOverride(t *testing.T) {
	old := hostSeenAgo(t, "old-host", 10*24*time.Hour)
	c := NewAssetCorrelator(ipOnlyRepo{byIP: map[string][]*asset.Asset{"10.9.0.5": {old}}},
		logger.NewNop(), CorrelationConfig{})
	cfg := c.config.WithTenantOverrides(14, 0)
	res, err := c.CorrelateHost(context.Background(), shared.NewID(), "new-host",
		map[string]any{"ip_addresses": []any{"10.9.0.5"}}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if res.Matched == nil {
		t.Fatal("a 14-day tenant window should accept an asset seen 10 days ago")
	}
}
