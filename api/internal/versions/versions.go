// Package versions is the version manifest built into the API: a copy of the
// repository's versions.yaml (api/docs/rfcs/RFC-037), embedded at build time
// and parsed once when the package is loaded.
//
// versions.yaml lives at the repository root, outside the Go module, and
// go:embed cannot reach outside the module. .github/scripts/release/
// sync-versions.sh therefore writes a byte-for-byte copy next to this file,
// its --check (CI "Version consistency") fails while the two differ, and
// TestEmbeddedCopyMatchesRoot fails the Go tests too. Every version default
// of the API comes from here, so a release bump changes YAML only.
//
// A malformed manifest is a build error, never a silent fallback: the package
// panics while loading, which fails every test of every package that imports
// it, and TestManifestParses names the problem.
package versions

import (
	_ "embed"
	"fmt"
	"regexp"
	"strings"

	"golang.org/x/mod/semver"
	"gopkg.in/yaml.v3"
)

//go:embed versions.yaml
var manifestYAML []byte

// DefaultProductID is the product of a sensor that reports none: the
// scanning sensor, the only product before sensors reported theirs.
const DefaultProductID = "openctemio-sensor"

// InstallSensor is the install snippet set of the scanning sensor (the
// unprefixed configs/sensor-templates/<format>.tmpl files).
const InstallSensor = "sensor"

// Product is one sensor product of the catalog.
type Product struct {
	// Key is the product's section in versions.yaml ("sensor").
	Key string
	// ID is the product token the sensor reports ("openctemio-sensor").
	ID string
	// Latest is the newest release (vX.Y.Z).
	Latest string
	// Min is the oldest supported release; "" = no minimum.
	Min string
	// Image is the published image repository, without a tag.
	Image string
	// Install names the install snippet set (InstallSensor, or the prefix
	// of the product's own template files).
	Install string
	// ReleaseIdentity is the workflow that signs the image; the certificate
	// identity of a release is it + "@refs/tags/" + the tag.
	ReleaseIdentity string
}

// ImageRef is the image of the product's latest release.
func (p Product) ImageRef() string { return p.Image + ":" + p.Latest }

// Manifest is the parsed versions.yaml.
type Manifest struct {
	PlatformRelease string
	Products        []Product
	SDKLatest       string
	SDKAdvisories   []string
	CIRunnerLatest  string
	CIRunnerMin     string
	ChartVersion    string
}

// Product returns the catalog entry of a product id.
func (m *Manifest) Product(id string) (Product, bool) {
	for _, p := range m.Products {
		if p.ID == id {
			return p, true
		}
	}
	return Product{}, false
}

var embedded = mustParse(manifestYAML)

func mustParse(b []byte) *Manifest {
	m, err := Parse(b)
	if err != nil {
		panic("versions: the embedded versions.yaml is invalid (run .github/scripts/release/sync-versions.sh --check): " + err.Error())
	}
	return m
}

// Embedded is the manifest built into this binary.
func Embedded() *Manifest { return embedded }

// PlatformRelease is platform.release.
func PlatformRelease() string { return embedded.PlatformRelease }

// Products is the sensor product catalog, in manifest order. The slice is a
// copy.
func Products() []Product { return append([]Product(nil), embedded.Products...) }

// LookupProduct returns the catalog entry of a product id.
func LookupProduct(id string) (Product, bool) { return embedded.Product(id) }

// SensorLatest is the scanning sensor's latest release.
func SensorLatest() string { return defaultProduct().Latest }

// SensorMin is the scanning sensor's minimum release ("" = none).
func SensorMin() string { return defaultProduct().Min }

// SensorImage is the scanning sensor's image repository, without a tag.
func SensorImage() string { return defaultProduct().Image }

// SDKLatest is sdk.latest (informational).
func SDKLatest() string { return embedded.SDKLatest }

// SDKAdvisories lists the SDK releases with a published security advisory.
// The slice is a copy.
func SDKAdvisories() []string { return append([]string(nil), embedded.SDKAdvisories...) }

// CIRunnerLatest is ci.latest.
func CIRunnerLatest() string { return embedded.CIRunnerLatest }

// CIRunnerMin is ci.min ("" = none).
func CIRunnerMin() string { return embedded.CIRunnerMin }

func defaultProduct() Product {
	p, _ := embedded.Product(DefaultProductID) // Parse requires it
	return p
}

var (
	versionRE      = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)
	chartVersionRE = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
	// productIDRE matches what the API keeps of a reported product token
	// (pkg/domain/sensor/build.go).
	productIDRE  = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	sectionKeyRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
	// imageRE is an image repository without a tag or digest, safe in a
	// shell snippet.
	imageRE   = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]*(:[0-9]+)?(/[a-z0-9][a-z0-9._-]*)+$`)
	installRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
	// identityRE is a GitHub Actions workflow of the openctemio organization.
	identityRE = regexp.MustCompile(`^https://github\.com/openctemio/[a-z0-9._-]+/\.github/workflows/[a-z0-9._-]+\.ya?ml$`)
)

// sections other than products, with their keys and whether each may be "".
var fixedSections = map[string]map[string]bool{
	"platform": {"release": false},
	"sdk":      {"latest": false, "advisories": true},
	"ci":       {"latest": false, "min": true},
	"chart":    {"version": false},
}

var productKeys = map[string]bool{
	"product": false, "latest": false, "min": true, "image": false, "install": false, "release_identity": false,
}

// Parse reads a manifest and checks every value. It accepts only the
// two-level subset the release scripts read: top-level sections of scalar
// "key: value" pairs.
func Parse(b []byte) (*Manifest, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("not YAML: %w", err)
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, fmt.Errorf("the top level must be a mapping of sections")
	}
	top := doc.Content[0]
	m := &Manifest{}
	seen := map[string]bool{}
	for i := 0; i+1 < len(top.Content); i += 2 {
		name, body := top.Content[i].Value, top.Content[i+1]
		if seen[name] {
			return nil, fmt.Errorf("section %q appears twice", name)
		}
		seen[name] = true
		keys, fixed := fixedSections[name]
		if !fixed {
			keys = productKeys
		}
		vals, err := section(name, body, keys)
		if err != nil {
			return nil, err
		}
		if fixed {
			if err := m.setFixed(name, vals); err != nil {
				return nil, err
			}
			continue
		}
		p, err := product(name, vals)
		if err != nil {
			return nil, err
		}
		if _, dup := m.Product(p.ID); dup {
			return nil, fmt.Errorf("%s: product %q is listed twice", name, p.ID)
		}
		m.Products = append(m.Products, p)
	}
	for name := range fixedSections {
		if !seen[name] {
			return nil, fmt.Errorf("section %q is missing", name)
		}
	}
	if _, ok := m.Product(DefaultProductID); !ok {
		return nil, fmt.Errorf("the scanning sensor (product %s) is missing", DefaultProductID)
	}
	return m, nil
}

// section reads one section: exactly the keys allowed, each once, each a
// plain string; "" only where allowed.
func section(name string, body *yaml.Node, keys map[string]bool) (map[string]string, error) {
	if !sectionKeyRE.MatchString(name) {
		return nil, fmt.Errorf("section name %q is not lower-case letters, digits and dashes", name)
	}
	if body.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("%s: must be a mapping of key: value", name)
	}
	vals := make(map[string]string, len(keys))
	for i := 0; i+1 < len(body.Content); i += 2 {
		k, v := body.Content[i].Value, body.Content[i+1]
		if _, ok := keys[k]; !ok {
			return nil, fmt.Errorf("%s.%s: unknown key", name, k)
		}
		if _, dup := vals[k]; dup {
			return nil, fmt.Errorf("%s.%s: appears twice", name, k)
		}
		if v.Kind != yaml.ScalarNode || (v.Tag != "!!str" && v.Tag != "!!null") {
			return nil, fmt.Errorf("%s.%s: must be a string", name, k)
		}
		vals[k] = v.Value
	}
	for k, optional := range keys {
		v, ok := vals[k]
		if !ok {
			return nil, fmt.Errorf("%s.%s is missing", name, k)
		}
		if v == "" && !optional {
			return nil, fmt.Errorf("%s.%s must be set", name, k)
		}
	}
	return vals, nil
}

func (m *Manifest) setFixed(name string, v map[string]string) error {
	switch name {
	case "platform":
		m.PlatformRelease = v["release"]
		return checkVersion("platform.release", m.PlatformRelease)
	case "sdk":
		m.SDKLatest = v["latest"]
		if err := checkVersion("sdk.latest", m.SDKLatest); err != nil {
			return err
		}
		for _, a := range strings.Fields(v["advisories"]) {
			if err := checkVersion("sdk.advisories", a); err != nil {
				return err
			}
			m.SDKAdvisories = append(m.SDKAdvisories, a)
		}
	case "ci":
		m.CIRunnerLatest, m.CIRunnerMin = v["latest"], v["min"]
		if err := checkVersion("ci.latest", m.CIRunnerLatest); err != nil {
			return err
		}
		if m.CIRunnerMin != "" {
			if err := checkVersion("ci.min", m.CIRunnerMin); err != nil {
				return err
			}
			if semver.Compare(m.CIRunnerMin, m.CIRunnerLatest) > 0 {
				return fmt.Errorf("ci.min %s is newer than ci.latest %s", m.CIRunnerMin, m.CIRunnerLatest)
			}
		}
	case "chart":
		m.ChartVersion = v["version"]
		if !chartVersionRE.MatchString(m.ChartVersion) {
			return fmt.Errorf("chart.version %q is not X.Y.Z", m.ChartVersion)
		}
	}
	return nil
}

func product(name string, v map[string]string) (Product, error) {
	p := Product{
		Key: name, ID: v["product"], Latest: v["latest"], Min: v["min"],
		Image: v["image"], Install: v["install"], ReleaseIdentity: v["release_identity"],
	}
	if !productIDRE.MatchString(p.ID) {
		return p, fmt.Errorf("%s.product %q is not a product token (lower-case, digits, '.', '_', '-')", name, p.ID)
	}
	if err := checkVersion(name+".latest", p.Latest); err != nil {
		return p, err
	}
	if p.Min != "" {
		if err := checkVersion(name+".min", p.Min); err != nil {
			return p, err
		}
		if semver.Compare(p.Min, p.Latest) > 0 {
			return p, fmt.Errorf("%s.min %s is newer than %s.latest %s", name, p.Min, name, p.Latest)
		}
	}
	if !imageRE.MatchString(p.Image) {
		return p, fmt.Errorf("%s.image %q is not an image repository without a tag", name, p.Image)
	}
	if !installRE.MatchString(p.Install) {
		return p, fmt.Errorf("%s.install %q is not a snippet set name", name, p.Install)
	}
	if !identityRE.MatchString(p.ReleaseIdentity) {
		return p, fmt.Errorf("%s.release_identity %q is not an openctemio GitHub workflow URL", name, p.ReleaseIdentity)
	}
	return p, nil
}

func checkVersion(key, v string) error {
	if !versionRE.MatchString(v) {
		return fmt.Errorf("%s %q is not vX.Y.Z", key, v)
	}
	return nil
}
