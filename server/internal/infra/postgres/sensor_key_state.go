package postgres

import (
	"encoding/json"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/sensor"
)

// A sensor has up to two kinds of credential: the inline key on the sensors
// row (api_key_hash / api_key_prefix / key_expires_at — the bootstrap key) and
// rotating keys in sensor_api_keys, issued by self-renewal under rotation
// overlap. Renewal retires the inline key with a short grace, so after the
// first renewal key_expires_at is in the past while the sensor works with a
// sensor_api_keys row. The helpers here are the SQL side of
// sensor.Sensor.KeyState: every query that needs "the sensor's key" must use
// them, never key_expires_at / api_key_prefix directly.

// sensorActiveKeySQL selects the sensor's current rotating key as a JSON
// object (prefix, expires_at, last_used_at), or NULL when it has none: the
// active, non-revoked row with the latest expiry (a never-expiring row ranks
// first), newest first on ties. alias is the sensors table alias.
func sensorActiveKeySQL(alias string) string {
	return `(SELECT json_build_object('prefix', k.key_prefix, 'expires_at', k.expires_at, 'last_used_at', k.last_used_at)
		   FROM sensor_api_keys k
		  WHERE k.sensor_id = ` + alias + `.id AND k.is_active AND k.revoked_at IS NULL
		  ORDER BY k.expires_at DESC NULLS FIRST, k.created_at DESC
		  LIMIT 1)`
}

// sensorLegacyKeySQL is true when the sensor's effective key (the current
// rotating key from sensorActiveKeySQL, else the inline key) is a legacy rda_
// key: the SQL side of sensor.Sensor.IsLegacyKey.
func sensorLegacyKeySQL(alias string) string {
	return `(COALESCE(` + sensorActiveKeySQL(alias) + `->>'prefix', ` + alias + `.api_key_prefix) LIKE 'rda\_%')`
}

// sensorKeyUsableSQL is true when the sensor holds at least one credential
// that still authenticates: an unexpired inline key, or an active,
// non-revoked, unexpired rotating key. This is what dispatch must check;
// key_expires_at alone said "expired" for every sensor that had renewed.
func sensorKeyUsableSQL(alias string) string {
	return `((` + alias + `.key_expires_at IS NULL OR ` + alias + `.key_expires_at > NOW())
		OR EXISTS (SELECT 1 FROM sensor_api_keys uk
		            WHERE uk.sensor_id = ` + alias + `.id AND uk.is_active AND uk.revoked_at IS NULL
		              AND (uk.expires_at IS NULL OR uk.expires_at > NOW())))`
}

// activeKeyJSON is the shape sensorActiveKeySQL returns.
type activeKeyJSON struct {
	Prefix     string     `json:"prefix"`
	ExpiresAt  *time.Time `json:"expires_at"`
	LastUsedAt *time.Time `json:"last_used_at"`
}

// parseActiveKey decodes sensorActiveKeySQL's column. NULL (no rotating key)
// and an undecodable value both yield nil, which makes KeyState fall back to
// the inline key.
func parseActiveKey(raw []byte) *sensor.ActiveKey {
	if len(raw) == 0 {
		return nil
	}
	var k activeKeyJSON
	if err := json.Unmarshal(raw, &k); err != nil || k.Prefix == "" {
		return nil
	}
	return &sensor.ActiveKey{Prefix: k.Prefix, ExpiresAt: k.ExpiresAt, LastUsedAt: k.LastUsedAt}
}
