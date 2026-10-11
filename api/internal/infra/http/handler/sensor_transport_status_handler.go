package handler

// The platform's sensor transport status (docs/rfcs/RFC-059-sensor-transport-v3.md
// §7): which protocol v3 bindings this platform serves, and whether its gRPC
// binding passes the self-probe that decides if sensors are told about it.
// Platform configuration, the same for every organization: no tenant data.

import (
	"net/http"
	"time"
)

// SensorTransportGRPC is the gRPC binding's state.
type SensorTransportGRPC struct {
	// State: advertised (the self-probe passes; sensors use gRPC), pending
	// (first probe running), unavailable (see Reason).
	State     string     `json:"state"`
	Endpoint  string     `json:"endpoint,omitempty"`
	Reason    string     `json:"reason,omitempty"`
	CheckedAt *time.Time `json:"checked_at,omitempty"`
}

// SensorTransportStatus is GET /sensors/transport.
type SensorTransportStatus struct {
	// Mode: auto, or off (protocol v3 not served; every sensor on v2).
	Mode string `json:"mode"`
	// HTTPSPath is the HTTPS binding's path; empty when v3 is off.
	HTTPSPath string              `json:"https_path,omitempty"`
	GRPC      SensorTransportGRPC `json:"grpc"`
}

// SetTransportStatus sets what GET /sensors/transport reports.
func (h *SensorHandler) SetTransportStatus(f func() SensorTransportStatus) { h.transportStatus = f }

// GetTransportStatus godoc
// @Summary      Get the sensor transport status
// @Description  Protocol v3 bindings this platform serves and the gRPC binding's self-probe state.
// @Tags         Sensors
// @Produce      json
// @Success      200  {object}  SensorTransportStatus
// @Security     BearerAuth
// @Router       /sensors/transport [get]
func (h *SensorHandler) GetTransportStatus(w http.ResponseWriter, _ *http.Request) {
	st := SensorTransportStatus{Mode: "off", GRPC: SensorTransportGRPC{State: "unavailable", Reason: "transport_off"}}
	if h.transportStatus != nil {
		st = h.transportStatus()
	}
	writeJSON(w, http.StatusOK, st)
}
