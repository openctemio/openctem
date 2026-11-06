package routes

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// include_discovered=true, and only that value, widens the metric
// population (research/124).
func TestIncludeDiscoveredAssets(t *testing.T) {
	for q, want := range map[string]bool{"?include_discovered=true": true, "?include_discovered=1": false, "": false} {
		var got bool
		h := includeDiscoveredAssets(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			got = shared.DiscoveredAssetsIncluded(r.Context())
		}))
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/v1/dashboard/stats"+q, nil))
		if got != want {
			t.Errorf("%q: included = %v, want %v", q, got, want)
		}
	}
}
