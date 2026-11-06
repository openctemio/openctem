package firstparty

import (
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/versions"
	"github.com/openctemio/openctem/api/pkg/contentpkg"
)

func TestSASTRules(t *testing.T) {
	raw, err := SASTRules("v0.1.0", []byte("tarball"), "0123456789abcdef0123456789abcdef01234567", ">=0.9.0")
	if err != nil {
		t.Fatal(err)
	}
	m, err := contentpkg.ParseManifest(raw)
	if err != nil {
		t.Fatal(err)
	}
	if m.ID != "openctem/sast-rules" || m.Version != "0.1.0" || m.Provenance.BuildIdentity != SASTRulesWorkflow+"@refs/tags/v0.1.0" ||
		m.Artifact.Digest != contentpkg.Digest([]byte("tarball")) || !m.License.ServiceUse {
		t.Fatalf("manifest: %+v", m)
	}
}

// Every product of the sensor product catalog becomes a valid package
// whose build identity is the product's release identity at its tag.
func TestSensorProducts(t *testing.T) {
	for _, p := range versions.Products() {
		raw, err := SensorProduct(p, Image{Digest: "sha256:" + strings.Repeat("0", 64), Size: 10, SPDX: "GPL-3.0-only"}, ">=0.9.0")
		if err != nil {
			t.Fatalf("%s: %v", p.Key, err)
		}
		m, err := contentpkg.ParseManifest(raw)
		if err != nil {
			t.Fatalf("%s: %v", p.Key, err)
		}
		if m.Type != contentpkg.TypeSensors || m.Artifact.Ref != p.Image || m.Provenance.BuildIdentity != p.ReleaseIdentity+"@refs/tags/"+p.Latest {
			t.Fatalf("%s: %+v", p.Key, m)
		}
	}
	if _, err := SensorProduct(versions.Products()[0], Image{Digest: "sha256:" + strings.Repeat("0", 64), Size: 10}, ">=0.9.0"); err == nil {
		t.Fatal("a product without a license")
	}
}

func TestFeed(t *testing.T) {
	raw, err := Feed("program-feed", "Program feed", 3, []byte("keyset"), ">=0.9.0")
	if err != nil {
		t.Fatal(err)
	}
	m, err := contentpkg.ParseManifest(raw)
	if err != nil || m.Version != "3.0.0" || m.Type != contentpkg.TypeFeeds || m.License.Redistribution {
		t.Fatalf("feed: %v %+v", err, m)
	}
}
