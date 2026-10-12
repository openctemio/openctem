package handler

// The platform's sensor transport status (docs/rfcs/RFC-059-sensor-transport-v3.md
// §7): which protocol v3 bindings this platform serves, and whether its gRPC
// binding passes the self-probe that decides if sensors are told about it.
// Installation infrastructure: reported on Console > Operations (platform
// admins) only, never to organization users.

import "time"

// SensorTransportGRPC is the gRPC binding's state.
type SensorTransportGRPC struct {
	// State: advertised (the self-probe passes; sensors use gRPC), pending
	// (first probe running), unavailable (see Reason).
	State    string `json:"state"`
	Endpoint string `json:"endpoint,omitempty"`
	// RequiresALPN: the endpoint is reached through the gateway's ALPN
	// routing on the platform's own port; only sensors that offer the
	// sensor ALPN id use it, older ones stay on the HTTPS binding.
	RequiresALPN bool       `json:"requires_alpn,omitempty"`
	Reason       string     `json:"reason,omitempty"`
	CheckedAt    *time.Time `json:"checked_at,omitempty"`
}

// SensorTransportStatus is the sensor_transport part of GET /admin/operations.
type SensorTransportStatus struct {
	// Mode: auto, or off (protocol v3 not served; every sensor on v2).
	Mode string `json:"mode"`
	// HTTPSPath is the HTTPS binding's path; empty when v3 is off.
	HTTPSPath string              `json:"https_path,omitempty"`
	GRPC      SensorTransportGRPC `json:"grpc"`
}
