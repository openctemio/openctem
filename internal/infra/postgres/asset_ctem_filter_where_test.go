package postgres

import (
	"strings"
	"testing"
	"time"

	"github.com/openctemio/api/pkg/domain/asset"
)

// TestBuildWhereClause_CTEMDimensions verifies the CTEM inventory filter
// dimensions each add the expected SQL fragment and bind the expected args.
// buildWhereClause does not touch the receiver, so a zero repo is fine and no
// database is required — this always runs (unlike the *_db_test.go checks).
func TestBuildWhereClause_CTEMDimensions(t *testing.T) {
	r := &AssetRepository{}
	tenant := "11111111-1111-1111-1111-111111111111"

	tests := []struct {
		name         string
		filter       asset.Filter
		wantContains []string
		wantArg      any // one representative arg that must be present
	}{
		{
			name:         "business unit ids",
			filter:       asset.NewFilter().WithBusinessUnitIDs("bu-1", "bu-2"),
			wantContains: []string{"FROM business_unit_assets ba", "ba.business_unit_id IN ("},
			wantArg:      "bu-1",
		},
		{
			name:         "has owner true",
			filter:       asset.NewFilter().WithTenantID(tenant).WithHasOwner(true),
			wantContains: []string{"EXISTS (SELECT 1 FROM asset_owners ao", "tenant_members"},
			wantArg:      tenant,
		},
		{
			name:         "has owner false uses NOT EXISTS",
			filter:       asset.NewFilter().WithTenantID(tenant).WithHasOwner(false),
			wantContains: []string{"NOT EXISTS (SELECT 1 FROM asset_owners ao"},
			wantArg:      tenant,
		},
		{
			name:         "data classifications",
			filter:       asset.NewFilter().WithDataClassifications("confidential", "secret"),
			wantContains: []string{"a.data_classification IN ("},
			wantArg:      "confidential",
		},
		{
			name:         "control plane true",
			filter:       asset.NewFilter().WithIsControlPlane(true),
			wantContains: []string{"FROM asset_relationships ar", "ar.is_control_plane = true"},
		},
		{
			name:         "control plane false uses NOT EXISTS",
			filter:       asset.NewFilter().WithIsControlPlane(false),
			wantContains: []string{"NOT EXISTS (SELECT 1 FROM asset_relationships ar"},
		},
		{
			name:         "internet accessible",
			filter:       asset.NewFilter().WithIsInternetAccessible(true),
			wantContains: []string{"a.is_internet_accessible = $"},
			wantArg:      true,
		},
		{
			name:         "environments",
			filter:       asset.NewFilter().WithEnvironments("production", "dr"),
			wantContains: []string{"a.environment IN ("},
			wantArg:      "production",
		},
		{
			name:         "last seen range",
			filter:       asset.NewFilter().WithLastSeenAfter(time.Unix(1000, 0)).WithLastSeenBefore(time.Unix(2000, 0)),
			wantContains: []string{"a.last_seen >= $", "a.last_seen <= $"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			where, args := r.buildWhereClause(tc.filter)
			for _, frag := range tc.wantContains {
				if !strings.Contains(where, frag) {
					t.Errorf("where clause missing %q\ngot: %s", frag, where)
				}
			}
			if tc.wantArg != nil {
				found := false
				for _, a := range args {
					if a == tc.wantArg {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("args missing %v; got %#v", tc.wantArg, args)
				}
			}
		})
	}
}

// TestBuildWhereClause_HasOwnerRequiresTenant guards the tenant-scoping contract:
// asset_owners has no tenant_id column, so has_owner must be a no-op without a
// tenant filter rather than leak the presence check across tenants.
func TestBuildWhereClause_HasOwnerRequiresTenant(t *testing.T) {
	r := &AssetRepository{}
	where, _ := r.buildWhereClause(asset.NewFilter().WithHasOwner(true)) // no tenant
	if strings.Contains(where, "asset_owners") {
		t.Errorf("has_owner must be skipped without a tenant filter; got: %s", where)
	}
}

// TestBuildWhereClause_BackCompat verifies an empty filter still produces no
// conditions (today's behavior).
func TestBuildWhereClause_BackCompat(t *testing.T) {
	r := &AssetRepository{}
	where, args := r.buildWhereClause(asset.NewFilter())
	if where != "" {
		t.Errorf("empty filter should produce empty where clause; got: %s", where)
	}
	if len(args) != 0 {
		t.Errorf("empty filter should bind no args; got: %#v", args)
	}
}
