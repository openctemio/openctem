package ingest

import (
	"testing"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func dnsAsset(typ ctis.AssetType, name, visibility string, internet bool) *ctis.Asset {
	return &ctis.Asset{ID: name, Type: typ, Value: name, IsInternetAccessible: internet,
		Properties: ctis.Properties{"zone_visibility": visibility, "dns_zone": "corp"}}
}

// A name of a private zone is created private and not internet-accessible,
// even when the report also says it is internet-accessible; a public-zone
// name keeps the public default; only DNS names are affected.
func TestPrivateZoneExposure(t *testing.T) {
	p := NewAssetProcessor(nil, logger.NewNop())
	tenant := shared.NewID()
	cases := []struct {
		name     string
		ca       *ctis.Asset
		exposure asset.Exposure
		internet bool
	}{
		{"private subdomain", dnsAsset(ctis.AssetTypeSubdomain, "db.example.com", "private", false), asset.ExposurePrivate, false},
		{"private wins over the internet flag", dnsAsset(ctis.AssetTypeSubdomain, "api.example.com", "PRIVATE", true), asset.ExposurePrivate, false},
		{"private domain", dnsAsset(ctis.AssetTypeDomain, "example.net", "private", false), asset.ExposurePrivate, false},
		{"public subdomain", dnsAsset(ctis.AssetTypeSubdomain, "www.example.com", "public", false), asset.ExposurePublic, false},
		{"no visibility", dnsAsset(ctis.AssetTypeSubdomain, "mail.example.com", "", false), asset.ExposurePublic, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, err := p.createAssetFromCTIS(tenant, tc.ca, &ctis.Tool{Name: "gcp-dns"})
			if err != nil {
				t.Fatal(err)
			}
			if a.Exposure() != tc.exposure || a.IsInternetAccessible() != tc.internet {
				t.Fatalf("exposure %s internet %v, want %s %v", a.Exposure(), a.IsInternetAccessible(), tc.exposure, tc.internet)
			}
			claim := p.attributeClaims(tc.ca)[asset.AttrExposure]
			if tc.exposure == asset.ExposurePrivate && claim != "private" {
				t.Fatalf("exposure claim %q, want private", claim)
			}
		})
	}
	host := &ctis.Asset{ID: "h", Type: ctis.AssetTypeHost, Value: "10.0.0.5", Properties: ctis.Properties{"zone_visibility": "private"}}
	if privateZone(host) {
		t.Fatal("a host is not a DNS name of a zone")
	}
}
