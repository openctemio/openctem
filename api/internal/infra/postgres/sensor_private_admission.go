package postgres

// Private targets on the organization's own sensors (RFC-054 §14, R5): a
// private address no scan zone covers may be dispatched when the sensors that
// can take the job are the organization's own and their operator-written
// local policy allows private ranges; the sensor's allow list then decides
// each address. The platform never learns the ranges (the report carries the
// policy's shape only).

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// privateEligibleSQL is true for a sensor whose reported local policy is
// enforced, allows private ranges and is not stopped by its kill switch.
const privateEligibleSQL = `(s.reported_local_policy->>'state' = 'enforced'
	AND COALESCE((s.reported_local_policy->>'kill_switch')::boolean, false) = false
	AND COALESCE((s.reported_local_policy->'summary'->>'allow_private')::boolean, false))`

// PrivateTargetAdmission answers whether private targets outside every scan
// zone may go to the tenant's own sensors. With sensorID (the claiming or
// pinned sensor): that sensor is the tenant's, not a platform sensor, active,
// and eligible. Without: the tenant has at least one dispatchable own sensor
// and every dispatchable own sensor is eligible (so whichever claims the job
// enforces a policy that allows private ranges). Tenant-scoped.
func (r *SensorRepository) PrivateTargetAdmission(ctx context.Context, tenantID shared.ID, sensorID *shared.ID) (bool, error) {
	if sensorID != nil {
		var ok bool
		err := r.db.QueryRowContext(ctx, `
			SELECT `+privateEligibleSQL+`
			FROM sensors s
			WHERE s.tenant_id = $1 AND s.id = $2
			  AND NOT s.is_platform_sensor AND s.status = 'active'`,
			tenantID.String(), sensorID.String()).Scan(&ok)
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		if err != nil {
			return false, fmt.Errorf("private target admission: %w", err)
		}
		return ok, nil
	}
	var eligible, other int
	err := r.db.QueryRowContext(ctx, `
		SELECT count(*) FILTER (WHERE `+privateEligibleSQL+`),
		       count(*) FILTER (WHERE NOT `+privateEligibleSQL+`)
		FROM sensors s
		WHERE s.tenant_id = $1
		  AND NOT s.is_platform_sensor
		  AND s.status = 'active'
		  AND s.health IN `+sensorDispatchableHealthSQL+`
		  AND s.last_seen_at IS NOT NULL
		  AND `+sensorKeyUsableSQL("s"),
		tenantID.String()).Scan(&eligible, &other)
	if err != nil {
		return false, fmt.Errorf("private target admission: %w", err)
	}
	return eligible > 0 && other == 0, nil
}
