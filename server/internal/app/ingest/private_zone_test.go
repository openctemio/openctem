package ingest

import (
	"testing"

	"github.com/openctemio/ctis/v2"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func dnsAsset(typ ctis.AssetType, name string, internet *bool) *ctis.Asset {
	return &ctis.Asset{ID: "d1", Type: typ, Value: name, IsInternetAccessible: internet}
}

// A name of a private zone is a domain_name with is_internet_accessible
// false: created private and not internet-accessible. A name with no signal
// or a reachable one keeps the public default; only DNS names are affected;
// the old properties.zone_visibility carries no meaning.
func TestPrivateZoneExposure(t *testing.T) {
	p := NewAssetProcessor(nil, logger.NewNop())
	tenant := shared.NewID()
	cases := []struct {
		name     string
		ca       *ctis.Asset
		exposure asset.Exposure
	}{
		{"private subdomain", dnsAsset(ctis.AssetTypeDomainName, "db.example.com", ctis.Bool(false)), asset.ExposurePrivate},
		{"private domain", dnsAsset(ctis.AssetTypeDomainName, "example.net", ctis.Bool(false)), asset.ExposurePrivate},
		{"reachable subdomain", dnsAsset(ctis.AssetTypeDomainName, "www.example.com", ctis.Bool(true)), asset.ExposurePublic},
		{"no signal", dnsAsset(ctis.AssetTypeDomainName, "mail.example.com", nil), asset.ExposurePublic},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, err := p.createAssetFromCTIS(tenant, tc.ca, &ctis.Tool{Name: "gcp-dns"})
			if err != nil {
				t.Fatal(err)
			}
			private := tc.exposure == asset.ExposurePrivate
			if a.Exposure() != tc.exposure || (private && a.IsInternetAccessible()) {
				t.Fatalf("exposure %s internet %v, want %s", a.Exposure(), a.IsInternetAccessible(), tc.exposure)
			}
			claim := p.attributeClaims(tc.ca)[asset.AttrExposure]
			if private && claim != "private" {
				t.Fatalf("exposure claim %q, want private", claim)
			}
		})
	}
	host := &ctis.Asset{ID: "h", Type: ctis.AssetTypeHost, Value: "10.0.0.5", IsInternetAccessible: ctis.Bool(false)}
	if privateZone(host) {
		t.Fatal("a host is not a DNS name of a zone")
	}
	legacy := dnsAsset(ctis.AssetTypeDomainName, "x.example.com", nil)
	legacy.Properties = ctis.Properties{"zone_visibility": "private"}
	if privateZone(legacy) {
		t.Fatal("properties.zone_visibility must carry no meaning")
	}
}
