package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
