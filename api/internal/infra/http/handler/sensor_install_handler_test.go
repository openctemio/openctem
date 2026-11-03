package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	sensorapp "github.com/openctemio/openctem/api/internal/app/sensor"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func installHandler(t *testing.T) *SensorHandler {
	t.Helper()
	h := NewSensorHandler(nil, nil, logger.NewNop())
	h.SetTemplateService(sensorapp.NewSensorConfigTemplateService("/nonexistent-uses-builtins", logger.NewNop()))
	h.SetPublicAPIURL("https://ctem.example.test")
	h.SetJobSigningRoot(func(context.Context) string { return "root-2026a" })
	return h
}

func postInstall(h *SensorHandler, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sensors/install-templates", strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.InstallTemplates(rec, req)
	return rec
}

func TestInstallTemplates_PairingCommandsWithoutKey(t *testing.T) {
	h := installHandler(t)
	rec := postInstall(h, `{"pairing_code":"k7qm4ztd"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control = %q", rec.Header().Get("Cache-Control"))
	}
	var resp SensorConfigTemplatesResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	for name, text := range map[string]string{"docker": resp.Docker, "compose": resp.Compose,
		"kubernetes": resp.Kubernetes, "cli": resp.CLI} {
		if text == "" {
			t.Errorf("%s is empty", name)
			continue
		}
		// The code is normalised and formatted the way the sensor prints it.
		if !strings.Contains(text, "K7QM-4ZTD") || !strings.Contains(text, "SENSOR_JOB_SIGNING_ROOT") {
			t.Errorf("%s lacks the code or the signing root:\n%s", name, text)
		}
		if strings.Contains(text, "SENSOR_API_KEY") || strings.Contains(text, "octs_") {
			t.Errorf("%s carries an API key:\n%s", name, text)
		}
		if !strings.Contains(text, "https://ctem.example.test") {
			t.Errorf("%s does not point at the public URL", name)
		}
	}
	if resp.Policy == "" || resp.APIURL != "https://ctem.example.test" || resp.APIKeyIncluded {
		t.Errorf("policy=%v api_url=%q api_key_included=%v", resp.Policy != "", resp.APIURL, resp.APIKeyIncluded)
	}
	// No Helm (the bundled sensor installs with the platform), no config
	// or env file for a pairing install.
	if resp.Helm != "" || resp.YAML != "" || resp.Env != "" {
		t.Error("a pairing install answers only docker, compose, kubernetes, cli and policy")
	}
}

func TestInstallTemplates_InteractiveHasNoCode(t *testing.T) {
	rec := postInstall(installHandler(t), `{}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "SENSOR_PAIRING_CODE") {
		t.Error("an install without a code passes SENSOR_PAIRING_CODE")
	}
}

func TestInstallTemplates_RefusesBadInput(t *testing.T) {
	h := installHandler(t)
	for _, body := range []string{
		`{"pairing_code":"ABC"}`,
		`{"pairing_code":"K7QM-4ZTU"}`,
		`{"pairing_code":"K7QM-4ZTD'; rm -rf /"}`,
		`{"api_key":"octs_x"}`,
		`{"product":"no-such-product"}`,
		`not json`,
	} {
		if rec := postInstall(h, body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", body, rec.Code)
		}
	}
}

func TestInstallTemplates_IgnoresAMalformedSigningRoot(t *testing.T) {
	h := installHandler(t)
	h.SetJobSigningRoot(func(context.Context) string { return "root'; touch /tmp/x" })
	rec := postInstall(h, `{}`)
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "SENSOR_JOB_SIGNING_ROOT") {
		t.Errorf("status %d; a malformed root reached the commands", rec.Code)
	}
}

// With a private platform CA every install command pins its root, the
// answer describes the CA for the console, and the multi-sensor kit's
// command carries the pin too.
func TestInstallTemplates_PinThePlatformCA(t *testing.T) {
	h := installHandler(t)
	path := filepath.Join(t.TempDir(), "root.crt")
	if err := os.WriteFile(path, platformCARootPEM(t), 0o600); err != nil {
		t.Fatal(err)
	}
	h.SetPlatformCA(sensorapp.NewPlatformCASource(path))
	rec := postInstall(h, `{"pairing_code":"k7qm4ztd"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var resp SensorConfigTemplatesResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	ca := resp.PlatformCA
	if ca == nil || len(ca.Pin) != 64 || ca.DownloadPath != "/api/v1/sensors/platform-ca" || len(ca.Certificates) != 1 {
		t.Fatalf("platform_ca = %+v", ca)
	}
	c := ca.Certificates[0]
	if !c.Root || c.CommonName != "Test Internal CA - ECC Root" || c.SHA256Hex != ca.Pin || resp.CAFingerprintSHA256 != c.SHA256 {
		t.Errorf("certificate = %+v fingerprint=%q", c, resp.CAFingerprintSHA256)
	}
	for name, text := range map[string]string{"docker": resp.Docker, "compose": resp.Compose,
		"kubernetes": resp.Kubernetes, "cli": resp.CLI} {
		if !strings.Contains(text, "SENSOR_CA_SHA256") || !strings.Contains(text, ca.Pin) {
			t.Errorf("%s does not pin the root:\n%s", name, text)
		}
	}
	if !strings.Contains(resp.Multi, "./sensors.sh add 'openctem-sensor' --api-url 'https://ctem.example.test' --pairing-code 'K7QM-4ZTD' --ca-sha256 "+ca.Pin) {
		t.Errorf("multi:\n%s", resp.Multi)
	}
}

// Without a private CA nothing is pinned and platform_ca is absent; the kit
// command is still offered.
func TestInstallTemplates_NoPlatformCA(t *testing.T) {
	rec := postInstall(installHandler(t), `{}`)
	var resp SensorConfigTemplatesResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.PlatformCA != nil || strings.Contains(rec.Body.String(), "SENSOR_CA_SHA256") || strings.Contains(rec.Body.String(), "platform_ca") ||
		strings.Contains(resp.Multi, "--ca-sha256") || !strings.Contains(resp.Multi, "./sensors.sh add") {
		t.Errorf("unexpected CA in the answer: %+v multi=%q", resp.PlatformCA, resp.Multi)
	}
}

func TestInstallTemplatesRead_GetHasNoCodeAndRefusesBadProduct(t *testing.T) {
	h := installHandler(t)
	rec := httptest.NewRecorder()
	h.InstallTemplatesRead(rec, httptest.NewRequest(http.MethodGet, "/api/v1/sensors/install-templates", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "SENSOR_PAIRING_CODE") || !strings.Contains(rec.Body.String(), "https://ctem.example.test") {
		t.Error("GET must render the code-less commands")
	}
	rec = httptest.NewRecorder()
	h.InstallTemplatesRead(rec, httptest.NewRequest(http.MethodGet, "/api/v1/sensors/install-templates?product=nope", nil))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("bad product: status %d, want 400", rec.Code)
	}
}
