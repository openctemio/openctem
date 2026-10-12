package routes

// Transport telemetry (docs/rfcs/RFC-059-sensor-transport-v3.md T13): every
// heartbeat records the protocol and the binding it arrived on, decided by
// the platform (not by what the sensor claims), and the sensor's sanitized
// fallback reason.

import (
	"bytes"
	"context"
	"net/http"
	"strings"
	"testing"

	"connectrpc.com/connect"

	sensorv3 "github.com/openctemio/openctem/api/pkg/sensorproto/v3"
	"github.com/openctemio/openctem/api/pkg/sensorsig"
)

func (h *v3Harness) protocolOf(sensorID string) (version int, binding, reason string) {
	h.t.Helper()
	var b, r *string
	if err := h.db.QueryRow(`SELECT protocol_version, protocol_binding, protocol_fallback_reason FROM sensors WHERE id = $1`,
		sensorID).Scan(&version, &b, &r); err != nil {
		h.t.Fatal(err)
	}
	if b != nil {
		binding = *b
	}
	if r != nil {
		reason = *r
	}
	return version, binding, reason
}

func TestSensorV3_HeartbeatRecordsTheBinding(t *testing.T) {
	h := newV3Harness(t)
	tid := h.newTenant()
	s := h.newKeyBound(tid)
	ctx := context.Background()

	// HTTPS binding: the platform records https even if the sensor claims grpc.
	_, err := h.client(s, false).Heartbeat(ctx, connect.NewRequest(&sensorv3.HeartbeatRequest{
		HeartbeatJson: []byte(`{"version":"1.0.0"}`),
		Transport: &sensorv3.Transport{Binding: sensorv3.Binding_BINDING_GRPC,
			FallbackReason: "grpc_unreachable\r\nInjected: " + strings.Repeat("x", 400)},
	}))
	if err != nil {
		t.Fatal(err)
	}
	v, b, r := h.protocolOf(s.id)
	if v != 3 || b != "https" || !strings.HasPrefix(r, "grpc_unreachableInjected: ") || len(r) != 256 {
		t.Fatalf("https: v=%d binding=%q reason=%q (%d)", v, b, r, len(r))
	}

	// gRPC binding (mTLS).
	m := h.withMTLS()
	issued, err := h.client(s, false).IssueCertificate(ctx, connect.NewRequest(&sensorv3.IssueCertificateRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	g := m.grpcClient(t, s, issued.Msg.GetCertificateChainPem(), issued.Msg.GetCaBundlePem())
	if _, err := g.Heartbeat(ctx, connect.NewRequest(&sensorv3.HeartbeatRequest{HeartbeatJson: []byte(`{}`),
		Transport: &sensorv3.Transport{Binding: sensorv3.Binding_BINDING_GRPC}})); err != nil {
		t.Fatal(err)
	}
	if v, b, r := h.protocolOf(s.id); v != 3 || b != "grpc" || r != "" {
		t.Fatalf("grpc: v=%d binding=%q reason=%q", v, b, r)
	}
}

func TestSensorV2_HeartbeatRecordsTheReportedFallback(t *testing.T) {
	h := newV3Harness(t)
	tid := h.newTenant()
	s := h.newKeyBound(tid)
	body := []byte(`{"version":"1.0.0","transport":{"binding":"grpc","fallback_reason":"platform_without_v3"}}`)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, h.srv.URL+"/api/v2/sensor/heartbeat", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	hc := &http.Client{Transport: &sensorsig.Transport{Signer: s.signer, Base: h.srv.Client().Transport}}
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	// The binding is what the platform served (v2), not what the body claims.
	if v, b, r := h.protocolOf(s.id); v != 2 || b != "v2" || r != "platform_without_v3" {
		t.Fatalf("v2: v=%d binding=%q reason=%q", v, b, r)
	}
}
