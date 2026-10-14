package versions

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// rootManifest is the repository's versions.yaml (two levels above api/).
func rootManifest(t *testing.T) []byte {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	b, err := os.ReadFile(filepath.Join(filepath.Dir(file), "..", "..", "..", "versions.yaml"))
	if err != nil {
		t.Skipf("no repository versions.yaml next to this module: %v", err)
	}
	return b
}

func TestManifestParses(t *testing.T) {
	if _, err := Parse(manifestYAML); err != nil {
		t.Fatalf("embedded versions.yaml: %v", err)
	}
}

// The embedded copy is the repository's versions.yaml, byte for byte
// (sync-versions.sh writes it).
func TestEmbeddedCopyMatchesRoot(t *testing.T) {
	if root := rootManifest(t); !bytes.Equal(root, manifestYAML) {
		t.Fatal("api/internal/versions/versions.yaml differs from versions.yaml: run .github/scripts/release/sync-versions.sh")
	}
}

// Every getter returns the value versions.yaml holds, read here the way the
// release scripts read it (two levels, no YAML library).
func TestGettersEqualManifest(t *testing.T) {
	get := func(section, key string) string {
		cur := ""
		for _, line := range strings.Split(string(manifestYAML), "\n") {
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if !strings.HasPrefix(line, " ") {
				cur = strings.TrimSuffix(strings.TrimSpace(line), ":")
				continue
			}
			k, v, _ := strings.Cut(strings.TrimSpace(line), ":")
			if cur == section && k == key {
				return strings.Trim(strings.TrimSpace(v), `"`)
			}
		}
		t.Fatalf("%s.%s not in versions.yaml", section, key)
		return ""
	}
	for name, c := range map[string][2]string{
		"PlatformRelease": {PlatformRelease(), get("platform", "release")},
		"SensorLatest":    {SensorLatest(), get("sensor", "latest")},
		"SensorMin":       {SensorMin(), get("sensor", "min")},
		"SensorImage":     {SensorImage(), get("sensor", "image")},
		"SDKLatest":       {SDKLatest(), get("sdk", "latest")},
		"SDKAdvisories":   {strings.Join(SDKAdvisories(), " "), strings.Join(strings.Fields(get("sdk", "advisories")), " ")},
		"CIRunnerLatest":  {CIRunnerLatest(), get("ci", "latest")},
		"CIRunnerMin":     {CIRunnerMin(), get("ci", "min")},
	} {
		if c[0] != c[1] {
			t.Errorf("%s() = %q, versions.yaml says %q", name, c[0], c[1])
		}
	}
	if p, ok := LookupProduct(get("sensor", "product")); !ok || p.ID != DefaultProductID {
		t.Errorf("sensor.product is %q, want %q", get("sensor", "product"), DefaultProductID)
	}
	ct, ok := LookupProduct(get("connector-tenable", "product"))
	if !ok || ct.Latest != get("connector-tenable", "latest") || ct.Image != get("connector-tenable", "image") {
		t.Errorf("connector-tenable entry = %+v", ct)
	}
}

const validManifest = `platform:
  release: v1.2.3
sensor:
  product: openctemio-sensor
  latest: v0.5.0
  min: ""
  image: ghcr.io/openctemio/sensor
  install: sensor
  release_identity: https://github.com/openctemio/sensor/.github/workflows/docker-publish.yml
other:
  product: openctemio-other
  latest: v0.1.0
  min: v0.1.0
  image: registry.example.com:5000/team/other
  install: other
  release_identity: https://github.com/openctemio/other/.github/workflows/images.yml
sdk:
  latest: v0.3.0
  advisories: "v0.1.0 v0.2.1"
ci:
  latest: v0.3.0
  min: ""
chart:
  version: 0.1.0
`

func TestParseValid(t *testing.T) {
	m, err := Parse([]byte(validManifest))
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Products) != 2 || m.Products[0].ID != "openctemio-sensor" || m.Products[1].Key != "other" {
		t.Fatalf("products = %+v", m.Products)
	}
	if got := m.Products[1].ImageRef(); got != "registry.example.com:5000/team/other:v0.1.0" {
		t.Errorf("ImageRef = %q", got)
	}
	if strings.Join(m.SDKAdvisories, ",") != "v0.1.0,v0.2.1" {
		t.Errorf("advisories = %v", m.SDKAdvisories)
	}
}

// A malformed manifest is an error, never a fallback.
func TestParseRejects(t *testing.T) {
	for name, c := range map[string]struct{ old, new, want string }{
		"not yaml":             {"platform:", "platform: [", "not YAML"},
		"bad version":          {"release: v1.2.3", "release: 1.2", "platform.release"},
		"pre-release":          {"latest: v0.5.0", "latest: v0.5.0-rc.1", "sensor.latest"},
		"missing section":      {"chart:\n  version: 0.1.0\n", "", `section "chart" is missing`},
		"unknown key":          {"  advisories:", "  minimum: v0.1.0\n  advisories:", "sdk.minimum: unknown key"},
		"missing key":          {"  install: other\n", "", "other.install is missing"},
		"required empty":       {"latest: v0.1.0", `latest: ""`, "other.latest must be set"},
		"list value":           {`advisories: "v0.1.0 v0.2.1"`, "advisories: [v0.1.0]", "sdk.advisories: must be a string"},
		"bad advisory":         {"v0.2.1", "latest", "sdk.advisories"},
		"three levels":         {"  min: v0.1.0\n", "  min:\n    x: y\n", "other.min: must be a string"},
		"image with tag":       {"team/other\n", "team/other:v1\n", "other.image"},
		"shell in image":       {"team/other\n", "team/other;rm\n", "other.image"},
		"foreign identity":     {"openctemio/other/.github", "evil/other/.github", "release_identity"},
		"duplicate product":    {"product: openctemio-other", "product: openctemio-sensor", "listed twice"},
		"bad product id":       {"product: openctemio-other", "product: Other/Thing", "other.product"},
		"no scanning sensor":   {"product: openctemio-sensor", "product: openctemio-scanner", "scanning sensor"},
		"bad section name":     {"other:\n", "Other_X:\n", "section name"},
		"bad install":          {"install: other", "install: ../x", "other.install"},
		"duplicate key":        {"  min: v0.1.0\n", "  min: v0.1.0\n  min: v0.1.0\n", "other.min"},
		"min above latest":     {"min: v0.1.0", "min: v0.2.0", "other.min v0.2.0 is newer"},
		"ci min above latest":  {"ci:\n  latest: v0.3.0\n  min: \"\"", "ci:\n  latest: v0.3.0\n  min: v0.4.0", "ci.min v0.4.0 is newer"},
		"bad chart":            {"version: 0.1.0", "version: v0.1.0", "chart.version"},
		"duplicate section":    {"chart:\n", "ci:\n  latest: v0.3.0\n  min: \"\"\nchart:\n", "ci"},
		"top level not a map":  {validManifest, "- a\n", "top level"},
		"section not a map":    {"chart:\n  version: 0.1.0", "chart: 0.1.0", "chart: must be a mapping"},
		"ci min not a version": {"ci:\n  latest: v0.3.0\n  min: \"\"", "ci:\n  latest: v0.3.0\n  min: x", "ci.min"},
	} {
		t.Run(name, func(t *testing.T) {
			in := strings.Replace(validManifest, c.old, c.new, 1)
			if in == validManifest {
				t.Fatalf("test case does not change the manifest")
			}
			_, err := Parse([]byte(in))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("Parse error = %v, want it to mention %q", err, c.want)
			}
		})
	}
}

func TestMustParsePanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("mustParse accepted a malformed manifest")
		}
	}()
	mustParse([]byte("platform: ["))
}

func TestGettersReturnCopies(t *testing.T) {
	ps := Products()
	ps[0].Latest = "v9.9.9"
	if SensorLatest() == "v9.9.9" {
		t.Fatal("Products() exposes the catalog")
	}
}
