package handler

// The sensor product catalog as the Sensors page sees it (versions.yaml,
// api/docs/rfcs/RFC-037 §11): the products whose install snippets the
// platform renders and whose release lines it judges sensors against.

import (
	"regexp"

	"github.com/openctemio/openctem/api/internal/versions"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
)

// SensorInstallProduct is one catalog product as the handler uses it.
type SensorInstallProduct struct {
	// ID is the product token a sensor of it reports.
	ID string
	// Latest and Min are its release line (Min "" = no minimum).
	Latest string
	Min    string
	// Image is the image, with its pinned tag, the install snippets run.
	Image string
	// Install is its snippet set; ReleaseIdentity the workflow that signs
	// its image.
	Install         string
	ReleaseIdentity string
}

// SensorProductResponse is one sensor product the platform knows.
type SensorProductResponse struct {
	// ID is the product token a sensor of it reports
	// ("openctemio-sensor"). The console names it.
	ID string `json:"id"`
	// LatestVersion is its newest release: the install snippets pin it and
	// older sensors of the product show "update available".
	LatestVersion string `json:"latest_version"`
	// MinVersion is its oldest supported release; "" = no minimum.
	MinVersion string `json:"min_version"`
	// Image is the image, with its pinned tag, its install snippets run.
	Image string `json:"image"`
}

// CatalogInstallProducts is the built-in catalog with each product's
// published image.
func CatalogInstallProducts() []SensorInstallProduct {
	ps := versions.Products()
	out := make([]SensorInstallProduct, 0, len(ps))
	for _, p := range ps {
		out = append(out, SensorInstallProduct{
			ID: p.ID, Latest: p.Latest, Min: p.Min, Image: p.ImageRef(),
			Install: p.Install, ReleaseIdentity: p.ReleaseIdentity,
		})
	}
	return out
}

// SetProducts sets the sensor product catalog: the install snippets of each
// product and the release line its sensors are compared with.
func (h *SensorHandler) SetProducts(ps []SensorInstallProduct) {
	h.products = append([]SensorInstallProduct(nil), ps...)
	lines := make(map[string]sensor.ReleaseLine, len(ps))
	for _, p := range ps {
		lines[p.ID] = sensor.ReleaseLine{Latest: p.Latest, Min: p.Min}
	}
	h.healthPolicy.Products = lines
	h.healthPolicy = h.healthPolicy.Normalized()
}

// productResponses is the catalog for the console.
func (h *SensorHandler) productResponses() []SensorProductResponse {
	out := make([]SensorProductResponse, 0, len(h.products))
	for _, p := range h.products {
		out = append(out, SensorProductResponse{ID: p.ID, LatestVersion: p.Latest, MinVersion: p.Min, Image: p.Image})
	}
	return out
}

// productQueryRegexp bounds the product query parameter before the lookup.
var productQueryRegexp = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// installProduct picks the product whose snippets a sensor's install
// dialog shows: the requested one (it must be in the catalog), else the
// product the sensor reports when the catalog knows it, else the scanning
// sensor. ok is false only for a requested product the catalog does not
// list.
func (h *SensorHandler) installProduct(requested string, s *sensor.Sensor) (SensorInstallProduct, bool) {
	find := func(id string) (SensorInstallProduct, bool) {
		for _, p := range h.products {
			if p.ID == id {
				return p, true
			}
		}
		return SensorInstallProduct{}, false
	}
	if requested != "" {
		if !productQueryRegexp.MatchString(requested) {
			return SensorInstallProduct{}, false
		}
		return find(requested)
	}
	if p, ok := find(s.Build.ProductID()); ok {
		return p, true
	}
	if p, ok := find(sensor.DefaultProduct); ok {
		return p, true
	}
	// No catalog wired: the built-in one.
	for _, p := range CatalogInstallProducts() {
		if p.ID == sensor.DefaultProduct {
			return p, true
		}
	}
	return SensorInstallProduct{}, false
}
