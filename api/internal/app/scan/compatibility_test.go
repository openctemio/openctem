package scan

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/tool"
)

// fakeMappings answers GetCompatibleAssetTypes from a fixed admin mapping
// table (target type -> asset types); every other method is unused.
type fakeMappings struct {
	tool.TargetMappingRepository
	rows map[string][]asset.AssetType
}

func (f *fakeMappings) GetCompatibleAssetTypes(_ context.Context, targets []string, names []asset.AssetType) ([]asset.AssetType, error) {
	var out []asset.AssetType
	for _, t := range targets {
		for _, at := range f.rows[t] {
			for _, n := range names {
				if n == at {
					out = append(out, at)
				}
			}
		}
	}
	return out, nil
}

func pair(t asset.AssetType, sub string) asset.TypeRef { return asset.TypeRef{Type: t, SubType: sub} }

// Probe for RFC-042 §6.3.8 Q2: the target mappings named only alias types
// for url, so every stored application was reported "skipped" by url
// scanners (ZAP, nuclei url).
func TestFilterAssetsForScan_StoredApplicationsAreURLTargets(t *testing.T) {
	svc := NewAssetFilterService(&fakeMappings{}, nil)
	res, err := svc.FilterAssetsForScan(context.Background(), []string{"url"}, "nuclei", map[asset.TypeRef]int64{
		pair(asset.AssetTypeApplication, "website"):    3,
		pair(asset.AssetTypeApplication, "api"):        2,
		pair(asset.AssetTypeApplication, ""):           1,
		pair(asset.AssetTypeService, "discovered_url"): 4,
		pair(asset.AssetTypeApplication, "mobile_app"): 5,
		pair(asset.AssetTypeRepository, ""):            6,
		pair(asset.AssetTypeUnclassified, ""):          7,
		pair(asset.AssetType("website"), ""):           8, // a legacy row under the alias name
	})
	if err != nil {
		t.Fatal(err)
	}
	// unclassified assets cannot be decided: dispatched, as the gate does
	if res.ScannedAssets != 3+2+1+4+8+7 {
		t.Errorf("scanned = %d, want %d (by type %v)", res.ScannedAssets, 3+2+1+4+8+7, res.ScannedByType)
	}
	if res.SkippedAssets != 5+6 {
		t.Errorf("skipped = %d, want %d (by type %v)", res.SkippedAssets, 5+6, res.SkippedByType)
	}
	if res.UnclassifiedAssets != 7 {
		t.Errorf("unclassified = %d, want 7", res.UnclassifiedAssets)
	}
	if res.SkippedByType["application/mobile_app"] != 5 || res.ScannedByType["application/website"] != 3 {
		t.Errorf("labels: scanned %v skipped %v", res.ScannedByType, res.SkippedByType)
	}
}

// An admin target mapping adds a pair the registry does not list; it can
// never take a registry pair away. A mapping row still naming an alias is
// read as the pair the alias stands for.
func TestFilterAssetsForScan_AdminMappingsExtendTheRegistry(t *testing.T) {
	svc := NewAssetFilterService(&fakeMappings{rows: map[string][]asset.AssetType{
		"host": {asset.AssetTypeRepository, asset.AssetTypeFirewall},
	}}, nil)
	res, err := svc.FilterAssetsForScan(context.Background(), []string{"host"}, "nmap", map[asset.TypeRef]int64{
		pair(asset.AssetTypeHost, ""):             1,
		pair(asset.AssetTypeRepository, ""):       2,
		pair(asset.AssetTypeNetwork, "firewall"):  4,
		pair(asset.AssetTypeNetwork, "vpc"):       8,
		pair(asset.AssetTypeIdentity, "iam_user"): 16,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.ScannedAssets != 1+2+4 || res.SkippedAssets != 8+16 {
		t.Errorf("scanned %d skipped %d (scanned %v skipped %v)", res.ScannedAssets, res.SkippedAssets, res.ScannedByType, res.SkippedByType)
	}
}

// A tool that declares no target type the platform knows cannot be decided
// for: nothing is refused.
func TestFilterAssetsForScan_UnknownToolTargetsScanEverything(t *testing.T) {
	svc := NewAssetFilterService(&fakeMappings{}, nil)
	res, err := svc.FilterAssetsForScan(context.Background(), []string{"quantum"}, "x", map[asset.TypeRef]int64{
		pair(asset.AssetTypeRepository, ""):   2,
		pair(asset.AssetTypeUnclassified, ""): 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.ScannedAssets != 3 || res.SkippedAssets != 0 {
		t.Errorf("scanned %d skipped %d", res.ScannedAssets, res.SkippedAssets)
	}
}
