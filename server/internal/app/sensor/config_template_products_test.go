package sensor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/openctemio/openctem/api/internal/versions"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// The product the API assumes for a sensor that reports none is the
// catalog's scanning sensor.
func TestDefaultProductIsTheCatalogs(t *testing.T) {
	if sensordom.DefaultProduct != versions.DefaultProductID {
		t.Fatalf("sensor.DefaultProduct %q != versions.DefaultProductID %q", sensordom.DefaultProduct, versions.DefaultProductID)
	}
}

// Every product in versions.yaml has install snippets: at least a docker run
// that parses as shell and runs the product's image, never "latest".
func TestTemplates_EveryCatalogProductInstalls(t *testing.T) {
	for _, p := range versions.Products() {
		for _, dir := range templateSources {
			svc := NewSensorConfigTemplateService(dir, logger.NewNop())
			if !svc.HasInstallSet(p.Install) {
				t.Fatalf("[%s] product %s: no docker template for snippet set %q", dir, p.ID, p.Install)
			}
			data := fullData(t)
			data.Image, data.Install, data.ReleaseIdentity = p.ImageRef(), p.Install, p.ReleaseIdentity
			out, err := svc.Render(data)
			if err != nil {
				t.Fatalf("[%s] %s: %v", dir, p.ID, err)
			}
			if !strings.Contains(out.Docker, p.ImageRef()) || strings.Contains(out.Docker, ":latest") {
				t.Errorf("[%s] %s docker does not run %s:\n%s", dir, p.ID, p.ImageRef(), out.Docker)
			}
			bashSyntaxOK(t, dir+" "+p.ID+" docker", out.Docker)
			continuationLinesOK(t, dir+" "+p.ID+" docker", out.Docker)
			if out.Compose != "" {
				var doc map[string]any
				if err := yaml.Unmarshal([]byte(out.Compose), &doc); err != nil {
					t.Errorf("[%s] %s compose is not YAML: %v\n%s", dir, p.ID, err, out.Compose)
				}
			}
		}
	}
}

// The connector's snippets run the connector, check its signature against
// its own release workflow, and leave out the formats it does not ship.
func TestTemplates_ConnectorTenable(t *testing.T) {
	p, ok := versions.LookupProduct("openctemio-connector-tenable")
	if !ok {
		t.Skip("connector-tenable is not in the catalog")
	}
	data := fullData(t)
	data.Image, data.Install, data.ReleaseIdentity = p.ImageRef(), p.Install, p.ReleaseIdentity
	out := render(t, shippedTemplatesDir, data)
	for _, want := range []string{
		"--certificate-identity '" + p.ReleaseIdentity + "@refs/tags/" + p.Latest + "'",
		"/etc/openctem/connectors:/etc/openctem/connectors:ro",
		"SENSOR_CA_CERT_FILE=",
		"-e SENSOR_API_KEY='rda_4b1e0123456789abcdef'",
	} {
		if !strings.Contains(out.Docker, want) {
			t.Errorf("docker lacks %q:\n%s", want, out.Docker)
		}
	}
	for _, bad := range []string{"seccomp", "sensor-policy.yaml"} {
		if strings.Contains(out.Docker, bad) {
			t.Errorf("the connector runs no scanner, but its docker snippet sets up %q", bad)
		}
	}
	if out.Kubernetes != "" || out.Helm != "" || out.Policy != "" {
		t.Error("formats the connector does not ship must be empty")
	}
}

// A missing product set never falls back to the scanner's snippets.
func TestTemplates_UnknownInstallSetIsAnError(t *testing.T) {
	data := fullData(t)
	data.Install = "no-such-product"
	if _, err := NewSensorConfigTemplateService(shippedTemplatesDir, logger.NewNop()).Render(data); err == nil {
		t.Fatal("an unknown snippet set rendered")
	}
}

// Every shipped template is built in (the generator globs the directory).
func TestTemplates_EveryShippedFileIsBuiltIn(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(shippedTemplatesDir, "*", "*.tmpl"))
	if err != nil || len(files) == 0 {
		t.Fatalf("glob: %v", err)
	}
	for _, f := range files {
		key := templateKey(filepath.Base(filepath.Dir(f)), strings.TrimSuffix(filepath.Base(f), ".tmpl"))
		if _, ok := builtinTemplates[key]; !ok {
			t.Errorf("%s is not built in: run go generate ./internal/app/sensor/", f)
		}
	}
}

// toyProductsDir holds the install snippets of a product the platform has
// never heard of (acme-toy): a directory of templates, nothing in Go.
const toyProductsDir = "testdata/sensor-products"

// A new sensor product needs no platform change: a directory of templates
// in the templates dir is loaded next to the shipped sets and rendered with
// the product's image from the catalog; the shipped sets keep working from
// their built-in copies.
func TestTemplates_ProductSetAddedOnDisk(t *testing.T) {
	t.Cleanup(func() { _ = versions.LoadExtraProducts("") })
	if err := versions.LoadExtraProducts("../../versions/testdata/toy-products.yaml"); err != nil {
		t.Fatal(err)
	}
	p, ok := versions.LookupProduct("acme-toy-sensor")
	if !ok {
		t.Fatal("toy product not in the catalog")
	}
	svc := NewSensorConfigTemplateService(toyProductsDir, logger.NewNop())
	if !svc.HasInstallSet(p.Install) {
		t.Fatalf("the %s snippet set on disk was not loaded", p.Install)
	}
	data := fullData(t)
	data.Image, data.Install = p.ImageRef(), p.Install
	out, err := svc.Render(data)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.Docker, "ghcr.io/acme/toy-sensor:v1.2.3") || !strings.Contains(out.Docker, "TOY_PLATFORM_URL='https://192.0.2.204'") {
		t.Fatalf("toy docker snippet:\n%s", out.Docker)
	}
	bashSyntaxOK(t, "toy docker", out.Docker)
	if out.Kubernetes != "" || out.Helm != "" {
		t.Error("formats the toy product does not ship must be empty")
	}
	// The shipped scanning sensor still renders (built-in fallback).
	data = fullData(t)
	if out, err := svc.Render(data); err != nil || !strings.Contains(out.Docker, data.Image) {
		t.Fatalf("scanning sensor with a toy-only directory: %v", err)
	}
}

// SECURITY: only <set>/<format>.tmpl files with a plain set name and a known
// format are loaded from the directory; anything else is ignored.
func TestTemplates_OnlyWellFormedSetsLoad(t *testing.T) {
	dir := t.TempDir()
	for _, p := range []string{"Bad Set/docker.tmpl", "okset/notaformat.tmpl", "okset/docker.tmpl"} {
		if err := os.MkdirAll(filepath.Join(dir, filepath.Dir(p)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, p), []byte("echo {{.Image}}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	svc := NewSensorConfigTemplateService(dir, logger.NewNop())
	if !svc.HasInstallSet("okset") || svc.HasInstallSet("Bad Set") {
		t.Fatal("set loading")
	}
	svc.mu.RLock()
	_, odd := svc.templates["okset/notaformat"]
	svc.mu.RUnlock()
	if odd {
		t.Fatal("an unknown format was loaded")
	}
}

// A release learned from the release feed pins the image by tag and digest;
// the signature check still names the release tag (never a piece of the
// digest), so an image signed for another release does not verify.
func TestTemplates_DigestPinnedImage(t *testing.T) {
	t.Cleanup(func() { versions.SetLearned(nil) })
	digest := "sha256:" + strings.Repeat("0f", 32)
	versions.SetLearned(map[string]versions.Learned{"connector-tenable": {Version: "v9.8.7", Digest: digest}})
	p, ok := versions.LookupProduct("openctemio-connector-tenable")
	if !ok {
		t.Skip("connector-tenable is not in the catalog")
	}
	data := fullData(t)
	data.Image, data.Install, data.ReleaseIdentity = p.ImageRef(), p.Install, p.ReleaseIdentity
	out := render(t, shippedTemplatesDir, data)
	for _, want := range []string{
		p.Image + ":v9.8.7@" + digest,
		"--certificate-identity '" + p.ReleaseIdentity + "@refs/tags/v9.8.7'",
	} {
		if !strings.Contains(out.Docker, want) {
			t.Errorf("docker lacks %q:\n%s", want, out.Docker)
		}
	}
}

func TestImageTag(t *testing.T) {
	for in, want := range map[string]string{
		"ghcr.io/openctemio/sensor:v1.2.3":                                   "v1.2.3",
		"ghcr.io/openctemio/sensor:v1.2.3@sha256:" + strings.Repeat("a", 64): "v1.2.3",
		"registry.local:5000/sec/sensor:v1.2.3":                              "v1.2.3",
		"registry.local:5000/sec/sensor":                                     "",
		"ghcr.io/openctemio/sensor@sha256:" + strings.Repeat("a", 64):        "",
		"registry.local:5000/sec/sensor@sha256:" + strings.Repeat("a", 64):   "",
	} {
		if got := imageTag(in); got != want {
			t.Errorf("imageTag(%q) = %q, want %q", in, got, want)
		}
	}
}
