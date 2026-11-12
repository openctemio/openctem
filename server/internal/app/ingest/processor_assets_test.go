package ingest

import (
	"strings"
	"unicode/utf8"

	"testing"

	"github.com/openctemio/ctis/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openctemio/openctem/server/pkg/domain/asset"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/logger"
)

func TestInferAssetExposure(t *testing.T) {
	mk := func(name string, typ asset.AssetType, props map[string]any) *asset.Asset {
		a, err := asset.NewAsset(name, typ, asset.CriticalityMedium)
		if err != nil {
			t.Fatalf("NewAsset: %v", err)
		}
		if props != nil {
			a.SetProperties(props)
		}
		return a
	}
	mkSub := func(name string, typ asset.AssetType, sub string) *asset.Asset {
		a, err := asset.NewAssetWithSubType(name, typ, sub, asset.CriticalityMedium)
		if err != nil {
			t.Fatalf("NewAssetWithSubType: %v", err)
		}
		return a
	}
	cases := []struct {
		name string
		a    *asset.Asset
		want asset.Exposure
	}{
		{"domain is internet-facing", mk("example.com", asset.AssetTypeDomain, nil), asset.ExposurePublic},
		{"legacy ip string (public)", mk("web-1", asset.AssetTypeHost, map[string]any{"ip": "8.8.8.8"}), asset.ExposurePublic},
		{"legacy ip string (private)", mk("db-1", asset.AssetTypeHost, map[string]any{"ip": "10.0.0.5"}), asset.ExposureUnknown},
		// The shapes normalised host properties really have: []string right
		// after ingest, []any once read back from JSONB.
		{"ip_addresses []string (public)", mk("web-2", asset.AssetTypeHost, map[string]any{"ip_addresses": []string{"10.0.0.7", "8.8.4.4"}}), asset.ExposurePublic},
		{"ip_addresses []any (public)", mk("web-3", asset.AssetTypeHost, map[string]any{"ip_addresses": []any{"1.1.1.1"}}), asset.ExposurePublic},
		{"ip_addresses (private only)", mk("db-2", asset.AssetTypeHost, map[string]any{"ip_addresses": []any{"10.0.0.5", "192.168.1.4"}}), asset.ExposureUnknown},
		{"ip_address.address (public)", mk("web-4", asset.AssetTypeHost, map[string]any{"ip_address": map[string]any{"address": "9.9.9.9"}}), asset.ExposurePublic},
		{"host with no IP stays unknown", mk("worker-1", asset.AssetTypeHost, nil), asset.ExposureUnknown},
		{"ip_address (public) via name", mk("203.0.113.9", asset.AssetTypeIPAddress, nil), asset.ExposurePublic},
		{"ip_address (private) via name", mk("192.168.1.10", asset.AssetTypeIPAddress, nil), asset.ExposureUnknown},
		// RFC-042 §6.3.8: web applications and APIs are stored as
		// (application, sub_type); exposure used to be keyed on the alias
		// names website/api, which are never stored, so these stayed unknown.
		{"stored web application", mkSub("https://app.example.com", asset.AssetTypeApplication, "website"), asset.ExposurePublic},
		{"stored api", mkSub("https://api.example.com", asset.AssetTypeApplication, "api"), asset.ExposurePublic},
		{"stored mobile app has no default", mkSub("com.example.app", asset.AssetTypeApplication, "mobile_app"), asset.ExposureUnknown},
		{"certificate is internet-facing", mk("example.com", asset.AssetTypeCertificate, nil), asset.ExposurePublic},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := inferAssetExposure(c.a); got != c.want {
				t.Fatalf("inferAssetExposure = %q, want %q", got, c.want)
			}
		})
	}
}

// The address must land in ip_addresses (what IP correlation searches) for
// the host shapes sdk-go's scanners emit, or a renamed host is never matched.
func TestBuildPropertiesFromCTIS_KeepsAddressForCorrelation(t *testing.T) {
	p := NewAssetProcessor(nil, logger.NewNop())

	t.Run("nessus: ip_address as a string", func(t *testing.T) {
		props := p.buildPropertiesFromCTIS(&ctis.Asset{
			Type: ctis.AssetTypeHost, Value: "web-01.corp.example", Name: "web-01.corp.example",
			Properties: ctis.Properties{"ip_address": "10.0.0.9"},
		})
		assert.ElementsMatch(t, []string{"10.0.0.9"}, props["ip_addresses"])
		assert.NotContains(t, props, "ip_address", "a synonym folds into ip_addresses (RFC-042 §6.3.9)")
	})

	t.Run("vuls: hostname as name, address as value", func(t *testing.T) {
		props := p.buildPropertiesFromCTIS(&ctis.Asset{
			Type: ctis.AssetTypeIPAddress, Value: "10.0.0.10", Name: "web-02",
			Technical: &ctis.AssetTechnical{IPAddress: &ctis.IPAddressTechnical{Version: 4, Hostname: "web-02"}},
		})
		// The stored name is the value (the address); a display name adds nothing.
		assert.NotContains(t, props, "ip_addresses")
	})

	t.Run("host named by hostname, value is its address", func(t *testing.T) {
		props := p.buildPropertiesFromCTIS(&ctis.Asset{
			Type: ctis.AssetTypeHost, Value: "10.0.0.11", Name: "web-03",
			Properties: ctis.Properties{"ip": "10.0.0.11"},
		})
		assert.ElementsMatch(t, []string{"10.0.0.11"}, props["ip_addresses"], "no duplicate entry")
	})

	t.Run("value equal to name adds nothing", func(t *testing.T) {
		props := p.buildPropertiesFromCTIS(&ctis.Asset{Type: ctis.AssetTypeIPAddress, Value: "10.0.0.12", Name: "10.0.0.12"})
		assert.NotContains(t, props, "ip_addresses")
	})
}

// TestCreateAssetFromCTIS_HostExposure goes through the real ingest mapping:
// host normalisation moves properties.ip into ip_addresses and deletes ip,
// which is why exposure inference never fired for hosts before.
func TestCreateAssetFromCTIS_HostExposure(t *testing.T) {
	p := NewAssetProcessor(nil, logger.NewNop())
	tenantID := shared.NewID()
	cases := []struct {
		name string
		in   ctis.Asset
		want asset.Exposure
	}{
		{"public IP in properties.ip", ctis.Asset{Type: ctis.AssetTypeHost, Value: "web-1.corp", Properties: ctis.Properties{"ip": "8.8.8.8"}}, asset.ExposurePublic},
		{"private IP in properties.ip", ctis.Asset{Type: ctis.AssetTypeHost, Value: "db-1.corp", Properties: ctis.Properties{"ip": "10.0.0.5"}}, asset.ExposureUnknown},
		{"public IP in properties.ip_addresses", ctis.Asset{Type: ctis.AssetTypeHost, Value: "web-2.corp", Properties: ctis.Properties{"ip_addresses": []any{"10.1.1.1", "1.1.1.1"}}}, asset.ExposurePublic},
		{"private IPs in properties.ip_addresses", ctis.Asset{Type: ctis.AssetTypeHost, Value: "db-2.corp", Properties: ctis.Properties{"ip_addresses": []any{"172.16.3.4"}}}, asset.ExposureUnknown},
		{"public IP as an ip_address string (nessus)", ctis.Asset{Type: ctis.AssetTypeHost, Value: "web-3.corp", Properties: ctis.Properties{"ip_address": "9.9.9.9"}}, asset.ExposurePublic},
		{"private IP as an ip_address string (nessus)", ctis.Asset{Type: ctis.AssetTypeHost, Value: "db-3.corp", Properties: ctis.Properties{"ip_address": "10.9.9.9"}}, asset.ExposureUnknown},
		{"host named by its public IP", ctis.Asset{Type: ctis.AssetTypeHost, Value: "8.8.4.4"}, asset.ExposurePublic},
		{"host named by its private IP", ctis.Asset{Type: ctis.AssetTypeHost, Value: "192.168.10.20"}, asset.ExposureUnknown},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := c.in
			a, err := p.createAssetFromCTIS(tenantID, &in, nil)
			require.NoError(t, err)
			_, hasLegacy := a.Properties()["ip"]
			assert.False(t, hasLegacy, "host normalisation should have removed properties.ip")
			assert.Equal(t, c.want, a.Exposure())
		})
	}
}

// TestCreateAssetFromCTIS_LongNonASCIIDescriptionStaysValidUTF8: a
// description over the 4 KB cap is cut on a character boundary. A byte cut
// in the middle of a Vietnamese or CJK character left invalid UTF-8, which
// PostgreSQL refuses (SQLSTATE 22021): the asset and its findings were not
// stored.
func TestCreateAssetFromCTIS_LongNonASCIIDescriptionStaysValidUTF8(t *testing.T) {
	p := NewAssetProcessor(nil, logger.NewNop())
	tenantID := shared.NewID()
	for _, text := range []string{
		"Máy chủ ứng dụng nội bộ của phòng kế toán, ",
		"社内会計部門のアプリケーションサーバー、",
		"内部财务部门的应用服务器，",
		"x" + "Lỗ hổng 脆弱性 🔒",
	} {
		// Every offset of the cut: the 4096th byte lands in each byte of a
		// multi-byte character at least once.
		for pad := 0; pad < 4; pad++ {
			desc := strings.Repeat("a", pad) + strings.Repeat(text, 4096/len(text)+2)
			in := ctis.Asset{Type: ctis.AssetTypeHost, Value: "app-1.example.com", Description: desc}
			a, err := p.createAssetFromCTIS(tenantID, &in, nil)
			require.NoError(t, err)
			got := a.Description()
			assert.True(t, utf8.ValidString(got), "description is not valid UTF-8 (pad %d, %q)", pad, text)
			assert.LessOrEqual(t, len(got), 4096)
			assert.Greater(t, len(got), 4096-4)
			assert.True(t, strings.HasPrefix(desc, got))
		}
	}
}
