package unit

import (
	"testing"

	"github.com/openctemio/api/pkg/domain/asset"
)

func TestResolveTypeAlias(t *testing.T) {
	tests := []struct {
		input       asset.AssetType
		wantCore    asset.AssetType
		wantSubType string
	}{
		// Legacy types → consolidated
		{"firewall", "network", "firewall"},
		{"load_balancer", "network", "load_balancer"},
		{"vpc", "network", "vpc"},
		{"subnet", "network", "subnet"},
		{"compute", "host", "compute"},
		{"serverless", "host", "serverless"},
		{"website", "application", "website"},
		{"web_application", "application", "web_application"},
		{"api", "application", "api"},
		{"mobile_app", "application", "mobile_app"},
		{"iam_user", "identity", "iam_user"},
		{"iam_role", "identity", "iam_role"},
		{"service_account", "identity", "service_account"},
		{"data_store", "database", "data_store"},
		{"s3_bucket", "storage", "s3_bucket"},
		{"container_registry", "storage", "container_registry"},
		{"kubernetes_cluster", "kubernetes", "cluster"},
		{"kubernetes_namespace", "kubernetes", "namespace"},
		{"http_service", "service", "http"},
		{"open_port", "service", "open_port"},
		{"discovered_url", "service", "discovered_url"},

		// Core types → no alias (pass-through)
		{"domain", "domain", ""},
		{"host", "host", ""},
		{"network", "network", ""},
		{"database", "database", ""},
		{"repository", "repository", ""},
		{"container", "container", ""},
		{"unclassified", "unclassified", ""},
	}

	for _, tt := range tests {
		t.Run(string(tt.input), func(t *testing.T) {
			core, sub := asset.ResolveTypeAlias(tt.input)
			if core != tt.wantCore {
				t.Errorf("ResolveTypeAlias(%q) core = %q, want %q", tt.input, core, tt.wantCore)
			}
			if sub != tt.wantSubType {
				t.Errorf("ResolveTypeAlias(%q) sub = %q, want %q", tt.input, sub, tt.wantSubType)
			}
		})
	}
}

func TestParseAssetType_NewTypes(t *testing.T) {
	newTypes := []string{"application", "identity", "kubernetes"}
	for _, typStr := range newTypes {
		t.Run(typStr, func(t *testing.T) {
			parsed, err := asset.ParseAssetType(typStr)
			if err != nil {
				t.Fatalf("ParseAssetType(%q) failed: %v", typStr, err)
			}
			if string(parsed) != typStr {
				t.Errorf("ParseAssetType(%q) = %q", typStr, parsed)
			}
		})
	}
}

func TestCategoryForType(t *testing.T) {
	tests := []struct {
		assetType asset.AssetType
		want      asset.Category
	}{
		{"domain", asset.CategoryExternalSurface},
		{"host", asset.CategoryInfrastructure},
		{"network", asset.CategoryNetwork},
		{"firewall", asset.CategoryNetwork},
		{"database", asset.CategoryData},
		{"repository", asset.CategoryCode},
		{"iam_user", asset.CategoryIdentity},
		{"application", asset.CategoryApplication},
		{"identity", asset.CategoryIdentity},
		{"kubernetes", asset.CategoryInfrastructure},
		{"unclassified", asset.CategoryOther},
		{"unknown_type", asset.CategoryOther},
	}

	for _, tt := range tests {
		t.Run(string(tt.assetType), func(t *testing.T) {
			got := asset.CategoryForType(tt.assetType)
			if got != tt.want {
				t.Errorf("CategoryForType(%q) = %q, want %q", tt.assetType, got, tt.want)
			}
		})
	}
}

func TestSubTypeOnEntity(t *testing.T) {
	a, err := asset.NewAsset("test-fw", asset.AssetTypeNetwork, asset.CriticalityHigh)
	if err != nil {
		t.Fatal(err)
	}

	// Initially empty
	if a.SubType() != "" {
		t.Errorf("new asset sub_type should be empty, got %q", a.SubType())
	}

	// Set sub_type
	a.SetSubType("firewall")
	if a.SubType() != "firewall" {
		t.Errorf("expected sub_type=firewall, got %q", a.SubType())
	}

	// Category should be network
	if a.Category() != asset.CategoryNetwork {
		t.Errorf("expected category=network, got %q", a.Category())
	}
}
