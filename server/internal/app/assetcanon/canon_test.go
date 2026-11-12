package assetcanon

import (
	"testing"

	"github.com/openctemio/openctem/server/pkg/domain/asset"
)

// Golden corpus per stored type: the stored name (as the 1.x ingest stored
// it) and the name the 2.0 ingest gives the same asset. "" = left as is.
func TestCanonicalName(t *testing.T) {
	digest := "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	cases := []struct {
		typ  asset.AssetType
		sub  string
		name string
		want string
	}{
		// Already canonical: unchanged (same input, same record).
		{asset.AssetTypeDomain, "", "example.com", "example.com"},
		{asset.AssetTypeSubdomain, "", "api.example.com", "api.example.com"},
		{asset.AssetTypeIPAddress, "", "203.0.113.5", "203.0.113.5"},
		{asset.AssetTypeIPAddress, "", "2001:db8::1", "2001:db8::1"},
		{asset.AssetTypeNetwork, "", "10.0.0.0/8", "10.0.0.0/8"},
		{asset.AssetTypeService, "open_port", "203.0.113.5:443:tcp", "203.0.113.5:443:tcp"},
		{asset.AssetTypeService, "http", "https://example.com", "https://example.com"},
		{asset.AssetTypeRepository, "", "github.com/acme/api", "github.com/acme/api"},
		// IDNA: a Unicode host name becomes its A-label.
		{asset.AssetTypeSubdomain, "", "bücher.example.com", "xn--bcher-kva.example.com"},
		{asset.AssetTypeDomain, "", "bücher.de", "xn--bcher-kva.de"},
		{asset.AssetTypeService, "http", "https://bücher.example.com", "https://xn--bcher-kva.example.com"},
		{asset.AssetTypeService, "open_port", "bücher.example.com:443:tcp", "xn--bcher-kva.example.com:443:tcp"},
		// URL path: dot segments removed, percent encoding normalized, case kept.
		{asset.AssetTypeService, "http", "https://example.com/a/../Admin", "https://example.com/Admin"},
		// Container image digest form.
		{asset.AssetTypeContainer, "image", "nginx@" + digest, "docker.io/library/nginx@" + digest},
		// No canonical form: left as it is.
		{asset.AssetTypeContainer, "image", "nginx:1.25", ""},
		{asset.AssetTypeDomain, "", "*.example.com", ""},
		{asset.AssetTypeApplication, "website", "https://Example.com/x", ""},
		{asset.AssetTypeIdentity, "iam_user", "arn:aws:iam::1:user/Bob", ""},
	}
	for _, c := range cases {
		got, ok := CanonicalName(c.typ, c.sub, c.name)
		if c.want == "" {
			if ok {
				t.Errorf("%s/%s %q: got %q, want left as is", c.typ, c.sub, c.name, got)
			}
			continue
		}
		if !ok || got != c.want {
			t.Errorf("%s/%s %q: got %q (%v), want %q", c.typ, c.sub, c.name, got, ok, c.want)
		}
		// Idempotent: the canonical name is its own canonical name.
		if again, ok := CanonicalName(c.typ, c.sub, got); !ok || again != got {
			t.Errorf("%s/%s %q: not idempotent: %q -> %q", c.typ, c.sub, c.name, got, again)
		}
	}
}
