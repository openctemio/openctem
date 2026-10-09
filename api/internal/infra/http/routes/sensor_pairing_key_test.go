package routes

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	infrahttp "github.com/openctemio/openctem/api/internal/infra/http"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
)

// H3: the per-pairing limiter of the unauthenticated pairing routes keys on
// the parsed pairing id. A path segment that is not an id is the
// pairing-not-found answer and is never stored as a limiter key (it used to
// be: up to the URL limit per key, kept for 30 minutes).
func TestPairingRoutes_LimiterKeysOnlyPairingIDs(t *testing.T) {
	rl := middleware.NewTelemetryRateLimiter(1, 5, 30*time.Minute, logger.NewNop())
	t.Cleanup(rl.Stop)
	r := infrahttp.NewChiRouter()
	reached := 0
	r.GET(protov2.PathPrefix+"/pairings/{pairing_id}", func(w http.ResponseWriter, _ *http.Request) {
		reached++
		w.WriteHeader(http.StatusOK)
	}, perPairingChain(rl)...)
	h := r.Handler()

	for i := range 50 {
		rec := httptest.NewRecorder()
		junk := strings.Repeat(string(rune(97+i%26)), 4096)
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, protov2.PathPrefix+"/pairings/"+junk, nil))
		if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), string(protov2.ProblemPairingNotFound)) {
			t.Fatalf("junk id: %d %s", rec.Code, rec.Body.String())
		}
	}
	if reached != 0 || rl.Keys() != 0 {
		t.Fatalf("junk ids reached the handler %d times and left %d limiter keys", reached, rl.Keys())
	}

	// A real id is limited per pairing, in canonical form (case does not
	// make a second key).
	id := shared.NewID().String()
	for _, p := range []string{id, strings.ToUpper(id)} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, protov2.PathPrefix+"/pairings/"+p, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("pairing id %s: %d", p, rec.Code)
		}
	}
	if rl.Keys() != 1 {
		t.Fatalf("%d limiter keys, want 1", rl.Keys())
	}
}
