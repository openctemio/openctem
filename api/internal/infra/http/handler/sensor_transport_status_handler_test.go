package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGetTransportStatus(t *testing.T) {
	get := func(h *SensorHandler) SensorTransportStatus {
		t.Helper()
		rec := httptest.NewRecorder()
		h.GetTransportStatus(rec, httptest.NewRequest(http.MethodGet, "/api/v1/sensors/transport", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d", rec.Code)
		}
		var out SensorTransportStatus
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	// Not wired (v3 off): off, nothing advertised.
	if st := get(&SensorHandler{}); st.Mode != "off" || st.GRPC.State != "unavailable" || st.GRPC.Endpoint != "" {
		t.Fatalf("unwired status: %+v", st)
	}
	h := &SensorHandler{}
	h.SetTransportStatus(func() SensorTransportStatus {
		return SensorTransportStatus{Mode: "auto", HTTPSPath: "/api/v3/sensor",
			GRPC: SensorTransportGRPC{State: "unavailable", Endpoint: "sensors.example.test:443", Reason: "foreign_certificate"}}
	})
	if st := get(h); st.Mode != "auto" || st.HTTPSPath != "/api/v3/sensor" || st.GRPC.Reason != "foreign_certificate" {
		t.Fatalf("wired status: %+v", st)
	}
}
