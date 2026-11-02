package routes

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	sensorapp "github.com/openctemio/openctem/api/internal/app/sensor"
	"github.com/openctemio/openctem/api/internal/config"
	infrahttp "github.com/openctemio/openctem/api/internal/infra/http"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// GET /api/v1/sensors/platform-ca is public (no session, no key, no tenant)
// and rate limited per IP like the other public install files.
func TestPlatformCARoute_PublicAndRateLimited(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Route Test Root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "root.crt")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}

	if sensorapp.PlatformCAPath != "/api/v1/sensors/platform-ca" {
		t.Fatalf("the sensor and the snippets use %s; sensor_pairing.go mounts /api/v1/sensors/platform-ca", sensorapp.PlatformCAPath)
	}
	log := logger.NewNop()
	limit, stop := middleware.RateLimitWithStop(&config.RateLimitConfig{
		Enabled: true, RequestsPerSec: 0.001, Burst: 2, CleanupInterval: time.Minute,
	}, log)
	defer stop()
	router := infrahttp.NewChiRouter()
	registerSensorInstallRoutes(router, handler.NewPlatformCAHandler(sensorapp.NewPlatformCASource(path), log), limit)

	get := func() *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, sensorapp.PlatformCAPath, nil)
		req.RemoteAddr = "198.51.100.7:4242"
		router.Handler().ServeHTTP(rec, req)
		return rec
	}
	for i := range 2 {
		if rec := get(); rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/x-pem-file" {
			t.Fatalf("request %d without credentials: status %d", i, rec.Code)
		}
	}
	if rec := get(); rec.Code != http.StatusTooManyRequests {
		t.Errorf("over the budget: status %d, want 429", rec.Code)
	}

	// Not configured: the route still exists and answers 404.
	off := infrahttp.NewChiRouter()
	registerSensorInstallRoutes(off, nil, func(next http.Handler) http.Handler { return next })
	rec := httptest.NewRecorder()
	off.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, sensorapp.PlatformCAPath, nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("unconfigured: status %d, want 404", rec.Code)
	}
}
