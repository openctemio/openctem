package postgres

import (
	"encoding/json"
	"log"

	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// sensorManifestPostureSQL is the "posture" member of the sensor's current
// manifest (the sensor_manifests row whose digest is sensors.manifest_digest),
// NULL when there is none. One lookup on the (sensor_id, digest) unique index
// per row, so a list reads it in the same query. The manifest row must belong
// to the sensor's own tenant.
func sensorManifestPostureSQL(alias string) string {
	return `(SELECT m.manifest->'posture' FROM sensor_manifests m
		  WHERE m.sensor_id = ` + alias + `.id AND m.digest = ` + alias + `.manifest_digest
		    AND m.tenant_id IS NOT DISTINCT FROM ` + alias + `.tenant_id)`
}

// scanManifestPosture reads the stored posture, sanitized again on read; nil
// when none (or unreadable).
func scanManifestPosture(id shared.ID, raw []byte) *sensor.ManifestPosture {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var p sensor.ManifestPosture
	if err := json.Unmarshal(raw, &p); err != nil {
		log.Printf("[DEBUG] failed to unmarshal sensor manifest posture (id=%s): %v", id, err)
		return nil
	}
	return sensor.SanitizeManifestPosture(&p)
}
