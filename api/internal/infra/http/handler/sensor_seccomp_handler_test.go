package handler

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	sensorapp "github.com/openctemio/openctem/api/internal/app/sensor"
)

func TestServeSensorSeccompProfile(t *testing.T) {
	w := httptest.NewRecorder()
	ServeSensorSeccompProfile(w, httptest.NewRequest(http.MethodGet, sensorapp.SeccompProfilePath, nil))
	if w.Code != http.StatusOK || !bytes.Equal(w.Body.Bytes(), sensorapp.SeccompProfile()) {
		t.Fatalf("status %d, body is the profile: %v", w.Code, bytes.Equal(w.Body.Bytes(), sensorapp.SeccompProfile()))
	}
	if got := w.Header().Get("X-Content-SHA256"); got != sensorapp.SeccompProfileSHA256 {
		t.Fatalf("digest header %q", got)
	}
	if w.Header().Get("Content-Type") != "application/json" || w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("headers %v", w.Header())
	}
}
