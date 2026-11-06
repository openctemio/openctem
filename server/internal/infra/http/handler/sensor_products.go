package handler

// The sensor product catalog as the Sensors page sees it (versions.yaml,
// api/docs/rfcs/RFC-037 §11): the products whose install snippets the
// platform renders and whose release lines it judges sensors against. The
// latest release of a built-in product is resolved on every request, so a
// release learned from the release feed (RFC-037 §12) applies without a
// restart.

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
	// LatestSource says where Latest comes from (versions.SourceBuiltIn,
	// SourceFeed, SourceOperator).
	LatestSource string
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
	// Image is the image, with its pinned tag (and digest when known), its
	// install snippets run.
	Image string `json:"image"`
	// LatestSource says where LatestVersion comes from: "feed" (the signed
	// release feed), "built_in" (the version this platform release was built
	// with: it may be outdated) or "operator" (the operator's product file).
	LatestSource string `json:"latest_source"`
}

// CatalogInstallProducts is the built-in catalog with each product's
// published image.
func CatalogInstallProducts() []SensorInstallProduct {
	ps := versions.Products()
	out := make([]SensorInstallProduct, 0, len(ps))
	for _, p := range ps {
		out = append(out, SensorInstallProduct{
			ID: p.ID, Latest: p.Latest, Min: p.Min, Image: p.ImageRef(),
			Install: p.Install, ReleaseIdentity: p.ReleaseIdentity, LatestSource: p.LatestSource,
		})
	}
	return out
}

// SetProducts sets a fixed sensor product catalog: the install snippets of
// each product and the release line its sensors are compared with.
func (h *SensorHandler) SetProducts(ps []SensorInstallProduct) {
	fixed := append([]SensorInstallProduct(nil), ps...)
	h.SetProductSource(func() []SensorInstallProduct { return fixed })
}

// SetProductSource sets the function that returns the sensor product
// catalog. It is called on every request that needs the catalog (install
// snippets, release lines, the console list), so it must be cheap and safe
// for concurrent use.
func (h *SensorHandler) SetProductSource(src func() []SensorInstallProduct) {
	h.productSource = src
}

// SetSDKLatestSource sets the function that returns the latest SDK release
// sensors are compared with (informational "outdated"); nil keeps the
// health policy's fixed value.
func (h *SensorHandler) SetSDKLatestSource(src func() string) {
	h.sdkLatestSource = src
}

// currentProducts is the catalog now.
func (h *SensorHandler) currentProducts() []SensorInstallProduct {
	if h.productSource == nil {
		return CatalogInstallProducts()
	}
	return h.productSource()
}

// currentPolicy is the handler's health policy with the current release
// lines of the catalog and the current latest SDK release.
func (h *SensorHandler) currentPolicy() sensor.HealthPolicy {
	p := h.healthPolicy
	ps := h.currentProducts()
	lines := make(map[string]sensor.ReleaseLine, len(ps))
	for _, pr := range ps {
		lines[pr.ID] = sensor.ReleaseLine{Latest: pr.Latest, Min: pr.Min}
	}
	p.Products = lines
	if h.sdkLatestSource != nil {
		p.SDKLatestVersion = h.sdkLatestSource()
	}
	return p.Normalized()
}

// productResponses is the catalog for the console.
func (h *SensorHandler) productResponses() []SensorProductResponse {
	ps := h.currentProducts()
	out := make([]SensorProductResponse, 0, len(ps))
	for _, p := range ps {
		out = append(out, SensorProductResponse{ID: p.ID, LatestVersion: p.Latest, MinVersion: p.Min, Image: p.Image,
			LatestSource: p.LatestSource})
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
	products := h.currentProducts()
	find := func(id string) (SensorInstallProduct, bool) {
		for _, p := range products {
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
