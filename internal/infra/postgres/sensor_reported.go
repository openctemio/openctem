package postgres

// Sensor-reported capabilities (docs/rfcs/RFC-029-sensor-protocol-v2-and-sdk-stability.md
// §4.3.1): reading and writing the reported_* columns, and the catalog
// lookup that sanitizes a report. Dispatch queries read the generated
// effective_* columns (migration 000253).

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"

	"github.com/lib/pq"

	"github.com/openctemio/api/pkg/domain/sensor"
	"github.com/openctemio/api/pkg/domain/shared"
)

// sensorReportArgs are the UPDATE arguments of a capability report. A NULL
// argument leaves its column as it is.
type sensorReportArgs struct {
	tools        sql.NullString // jsonb
	toolNames    any            // text[] or nil
	capabilities any            // text[] or nil
	maxJobs      sql.NullInt32
	clearMaxJobs bool // store NULL (the sensor reports no ceiling)
	os           sql.NullString
	arch         sql.NullString
	present      bool
}

func sensorReportArgsOf(r *sensor.CapabilityReport) (sensorReportArgs, error) {
	var c sensorReportArgs
	if r == nil {
		return c, nil
	}
	if r.Tools != nil {
		raw, err := json.Marshal(r.Tools)
		if err != nil {
			return c, fmt.Errorf("failed to marshal reported tools: %w", err)
		}
		c.tools = sql.NullString{String: string(raw), Valid: true}
		c.toolNames = pq.Array(r.InstalledToolNames())
		c.present = true
	}
	if r.Capabilities != nil {
		c.capabilities = pq.Array(r.Capabilities)
		c.present = true
	}
	if r.NoCeiling && r.MaxConcurrentJobs <= 0 {
		c.clearMaxJobs = true
		c.present = true
	}
	if r.MaxConcurrentJobs > 0 {
		c.maxJobs = sql.NullInt32{Int32: int32(min(r.MaxConcurrentJobs, sensor.MaxReportedJobs)), Valid: true} //nolint:gosec // clamped to 1..100
		c.present = true
	}
	if r.OS != "" {
		c.os = sql.NullString{String: r.OS, Valid: true}
		c.present = true
	}
	if r.Arch != "" {
		c.arch = sql.NullString{String: r.Arch, Valid: true}
		c.present = true
	}
	return c, nil
}

// scanReported builds the stored report from its columns.
func scanReported(id shared.ID, tools []byte, caps pq.StringArray, maxJobs sql.NullInt32,
	osName, arch sql.NullString, at sql.NullTime) sensor.CapabilityReport {
	var r sensor.CapabilityReport
	if len(tools) > 0 {
		if err := json.Unmarshal(tools, &r.Tools); err != nil {
			log.Printf("[DEBUG] failed to unmarshal sensor reported tools (id=%s): %v", id, err)
			r.Tools = nil
		} else if r.Tools == nil {
			r.Tools = []sensor.ReportedTool{}
		}
	}
	if caps != nil {
		r.Capabilities = append([]string{}, caps...)
	}
	if maxJobs.Valid {
		r.MaxConcurrentJobs = int(maxJobs.Int32)
	}
	r.OS = osName.String
	r.Arch = arch.String
	if at.Valid {
		t := at.Time
		r.ReportedAt = &t
	}
	return r
}

// KnownCapabilityNames looks the names of a capability report up in the
// tool catalog (active tools: the platform's and, for a tenant sensor, the
// tenant's own) and the capability registry, in one round trip.
func (r *SensorRepository) KnownCapabilityNames(ctx context.Context, tenantID *shared.ID, tools, capabilities []string) (map[string]bool, map[string]bool, error) {
	knownTools, knownCaps := map[string]bool{}, map[string]bool{}
	if len(tools) == 0 && len(capabilities) == 0 {
		return knownTools, knownCaps, nil
	}
	var tid sql.NullString
	if tenantID != nil {
		tid = sql.NullString{String: tenantID.String(), Valid: true}
	}
	query := `
		SELECT 't' AS kind, name FROM tools
		WHERE name = ANY($2::text[])
		  AND is_active = TRUE
		  AND (tenant_id IS NULL OR tenant_id = $1::uuid)
		UNION
		SELECT 'c' AS kind, name FROM capabilities
		WHERE name = ANY($3::text[])
		  AND (tenant_id IS NULL OR tenant_id = $1::uuid)
	`
	rows, err := r.db.QueryContext(ctx, query, tid, pq.Array(tools), pq.Array(capabilities))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to look up reported capabilities: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var kind, name string
		if err := rows.Scan(&kind, &name); err != nil {
			return nil, nil, fmt.Errorf("failed to scan known capability name: %w", err)
		}
		if kind == "t" {
			knownTools[name] = true
		} else {
			knownCaps[name] = true
		}
	}
	if err := rows.Err(); err != nil {
		return nil, nil, fmt.Errorf("failed to iterate known capability names: %w", err)
	}
	return knownTools, knownCaps, nil
}
