package routes

// Hostile sensor suite: malicious payloads a compromised sensor (or a hostile
// tool inside it) may send, replayed against protocol v2 and protocol v3
// through the real routes. Each case names the finding of the sensor →
// platform security review it guards (docs/rfcs/RFC-040-platform-sensor-mutual-distrust.md,
// "Sensor → platform input review").

import (
	"bytes"
	"context"
	"runtime"
	"testing"

	"connectrpc.com/connect"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
	sensorv3 "github.com/openctemio/openctem/api/pkg/sensorproto/v3"
)

// itemFlood is a schema-valid v2 segment whose findings array holds n empty
// objects: 3 bytes each on the wire, an 840-byte ctis.Finding each once
// decoded.
func itemFlood(n int) []byte {
	var b bytes.Buffer
	b.WriteString(`{"version":"1.0","metadata":{"timestamp":"2026-10-01T12:00:00Z"},"tool":{"name":"semgrep"},"findings":[`)
	for i := range n {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString("{}")
	}
	b.WriteString("]}")
	return b.Bytes()
}

// floodItems is enough empty findings that decoding them before counting
// allocates several hundred MiB, while the body stays near 1 MiB.
const floodItems = 400_000

// maxFloodAlloc bounds what refusing the flood may allocate in total.
const maxFloodAlloc = 128 << 20

// allocated runs f and returns the bytes the process allocated meanwhile.
func allocated(f func()) uint64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	f()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

// C1: item counts are checked before the body is decoded. A segment of
// empty findings far over the per-segment limit is refused as
// report-too-large without allocating the decoded structs.
func TestHostileSensor_ItemFloodRefusedBeforeDecode(t *testing.T) {
	body := itemFlood(floodItems)

	t.Run("v2", func(t *testing.T) {
		h := newV2Harness(t, v2HarnessOpts{})
		var status int
		var raw []byte
		n := allocated(func() {
			resp, b := h.do("PUT", "/api/v2/sensor/results/"+newReportID(), body)
			status, raw = resp.StatusCode, b
			h.expect(resp, raw, 413, "report-too-large")
		})
		if n > maxFloodAlloc {
			t.Fatalf("refusing a %d-byte flood allocated %d MiB (status %d), want under %d MiB",
				len(body), n>>20, status, maxFloodAlloc>>20)
		}
	})

	t.Run("v3", func(t *testing.T) {
		h := newV3Harness(t)
		s := h.newKeyBound(h.newTenant())
		c := h.client(s, true)
		var err error
		n := allocated(func() {
			_, err = c.PutResult(context.Background(), connect.NewRequest(&sensorv3.PutResultRequest{
				ReportId: shared.NewID().String(), Content: body, ContentType: protov2.MediaTypeCTIS, ContentDigest: digestOf(body)}))
		})
		if p := problemOf(t, err); p.GetType() != protov2.ProblemTypeBase+string(protov2.ProblemReportTooLarge) {
			t.Fatalf("problem %q, want report-too-large", p.GetType())
		}
		if n > maxFloodAlloc {
			t.Fatalf("refusing a %d-byte flood over v3 allocated %d MiB, want under %d MiB", len(body), n>>20, maxFloodAlloc>>20)
		}
	})
}
