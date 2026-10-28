package postgres

import (
	"context"
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// TemplateSightingSensors returns the sensors of the tenant that reported a
// finding of the rule with the tool (its latest sighting), most recent first,
// at most limit. A sensor that ran a template has it installed: the retest
// of a version-match finding offers that template as an optional active
// check only on such a sensor (docs/architecture/finding-retest-strategy.md).
// Only the tenant's own findings are read.
func (r *FindingRepository) TemplateSightingSensors(ctx context.Context, tenantID shared.ID, tool, ruleID string, limit int) ([]shared.ID, error) {
	if ruleID == "" || tool == "" {
		return nil, nil
	}
	if limit <= 0 || limit > 20 {
		limit = 10
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT sensor_id FROM findings
		WHERE tenant_id = $1 AND rule_id = $2 AND COALESCE(last_seen_tool, tool_name) = $3 AND sensor_id IS NOT NULL
		GROUP BY sensor_id
		ORDER BY MAX(last_seen_at) DESC
		LIMIT $4`, tenantID.String(), ruleID, tool, limit)
	if err != nil {
		return nil, fmt.Errorf("template sightings: %w", err)
	}
	defer rows.Close()
	var out []shared.ID
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("template sightings: %w", err)
		}
		if sid, err := shared.IDFromString(id); err == nil {
			out = append(out, sid)
		}
	}
	return out, rows.Err()
}
