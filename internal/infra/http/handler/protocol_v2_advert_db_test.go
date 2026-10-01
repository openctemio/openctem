package handler

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"testing"

	"github.com/openctemio/api/pkg/sensorproto/legacyv1"
	protov2 "github.com/openctemio/api/pkg/sensorproto/v2"
)

// RFC-026 WP-A7: a v1 sensor discovers v2 results on its heartbeat by asking
// (X-OpenCTEM-Sensor-Features: results-v2). The answer is one header; the
// body is byte-identical, and a sensor that does not ask sees nothing new.
func TestProtocolV1_HeartbeatAdvertisesV2OnlyWhenAsked(t *testing.T) {
	h := newV1Harness(t) // the harness wires SetV2Advertised(true), as production does

	heartbeat := func(features string) (http.Header, []byte) {
		t.Helper()
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, h.srv.URL+legacyv1.HeartbeatPath,
			bytes.NewReader([]byte(`{"status":"online"}`)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+h.key)
		if features != "" {
			req.Header.Set(legacyv1.HeaderSensorFeatures, features)
		}
		resp, err := h.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("heartbeat %d: %s", resp.StatusCode, raw)
		}
		return resp.Header, raw
	}

	plainHdr, plainBody := heartbeat("")
	if v := plainHdr.Get(protov2.HeaderProtocolAdvert); v != "" {
		t.Fatalf("a v1 sensor that did not ask got %s: %s", protov2.HeaderProtocolAdvert, v)
	}
	askHdr, askBody := heartbeat("doorbell-not, Results-V2")
	if v := askHdr.Get(protov2.HeaderProtocolAdvert); v != "2" {
		t.Fatalf("advertisement %q, want 2", v)
	}
	if !bytes.Equal(plainBody, askBody) {
		t.Fatalf("the body changed:\n%s\n%s", plainBody, askBody)
	}
	// Other features alone do not trigger it.
	if v, _ := heartbeat("doorbell"); v.Get(protov2.HeaderProtocolAdvert) != "" {
		t.Fatal("advertised to a doorbell-only sensor")
	}

	// Off: never advertised.
	h.ingest.SetV2Advertised(false)
	if v, _ := heartbeat(protov2.FeatureResultsV2); v.Get(protov2.HeaderProtocolAdvert) != "" {
		t.Fatal("advertised while v2 results are off")
	}
}
