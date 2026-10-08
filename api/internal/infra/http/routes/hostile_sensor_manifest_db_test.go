package routes

// Hostile sensor suite (see hostile_sensor_db_test.go): manifest history.

import (
	"fmt"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/sensor"
)

// M8: any unknown member changes the manifest digest, so a sensor can make
// every PUT a new version. The stored history stays bounded whatever the
// age of the versions.
func TestHostileSensor_ManifestHistoryIsBounded(t *testing.T) {
	oldBurst := v2WriteBurstPerSensor
	v2WriteBurstPerSensor = 1000
	t.Cleanup(func() { v2WriteBurstPerSensor = oldBurst })
	h := newCtlHarness(t)
	s := h.newLimitedSensor(h.tenantID, "manifest-flood", nil, nil, 5)

	for i := range sensor.ManifestVersionsHardCap + 10 {
		body := manifestBody("v3.11.1")
		body["labels"] = map[string]any{"n": fmt.Sprint(i)}
		if out := h.putManifest(s, body); !out.Changed {
			t.Fatalf("PUT %d: unchanged, want a new version each time", i)
		}
	}
	if n, _ := h.manifestRows(s); n > sensor.ManifestVersionsHardCap {
		t.Fatalf("%d stored versions, want at most %d", n, sensor.ManifestVersionsHardCap)
	}
}
