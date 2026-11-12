package handler

import (
	"testing"
	"time"

	"github.com/openctemio/openctem/server/pkg/domain/ingestreceipt"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// The sensor of a sighting is shown only with sensors:read, a scan's name
// only with scans:read; a purged receipt is not linked.
func TestToSightingResponses_PermissionsAndReceipt(t *testing.T) {
	sensor, scan, receipt, run := shared.NewID(), shared.NewID(), shared.NewID(), shared.NewID()
	rows := []ingestreceipt.Sighting{{Channel: ingestreceipt.ChannelScan, SensorID: &sensor, SensorName: "edge-1",
		Tool: "nuclei", ScanID: &scan, ScanName: "weekly", FirstSeenAt: time.Now(), LastSeenAt: time.Now(), SeenCount: 3,
		LastReceiptID: &receipt, ReceiptKept: true, LastRunID: &run}}

	full := toSightingResponses(rows, true, true)[0]
	if full.Sensor == nil || full.Sensor.ID != sensor.String() || full.Sensor.Name != "edge-1" ||
		full.Scan == nil || full.Scan.Name != "weekly" || full.ReceiptID != receipt.String() || full.RunID != run.String() {
		t.Fatalf("full = %+v", full)
	}
	bare := toSightingResponses(rows, false, false)[0]
	if bare.Sensor != nil {
		t.Fatalf("sensor shown without sensors:read: %+v", bare.Sensor)
	}
	if bare.Scan == nil || bare.Scan.ID != scan.String() || bare.Scan.Name != "" {
		t.Fatalf("scan without scans:read = %+v", bare.Scan)
	}
	rows[0].ReceiptKept = false
	if got := toSightingResponses(rows, true, true)[0]; got.ReceiptID != "" {
		t.Fatalf("purged receipt linked: %q", got.ReceiptID)
	}
}
