package sensor

import (
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
	files, err := filepath.Glob(filepath.Join(shippedTemplatesDir, "*.tmpl"))
	if err != nil || len(files) == 0 {
		t.Fatalf("glob: %v", err)
	}
	for _, f := range files {
		if _, ok := builtinTemplates[strings.TrimSuffix(filepath.Base(f), ".tmpl")]; !ok {
			t.Errorf("%s is not built in: run go generate ./internal/app/sensor/", f)
		}
	}
}
