package postgres

import (
	"context"
	"encoding/json"
	"fmt"
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

// HasConfinedSensor reports whether the tenant has an active sensor of its
// own that reported net.confined@1 (its tool runs are network-confined).
// What an administrator declared never counts.
func (r *SensorRepository) HasConfinedSensor(ctx context.Context, tenantID shared.ID) (bool, error) {
	var ok bool
	err := r.db.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM sensors
			WHERE tenant_id = $1 AND status = 'active'
			  AND scope = 'organization'
			  AND $2 = ANY(COALESCE(reported_capabilities, ARRAY[]::text[])))`,
		tenantID.String(), sensor.CapabilityNetConfined).Scan(&ok)
	if err != nil {
		return false, fmt.Errorf("look up confined sensors: %w", err)
	}
	return ok, nil
}
