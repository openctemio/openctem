package postgres

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// RecordTicketingHealth stores (problem non-nil) or clears (nil) the
// ticketing health of one kind of issue on an integration of the tenant:
// metadata.ticketing_health.<kind>. It writes that key alone, so it never
// races a concurrent save of the rest of the integration. Clearing writes
// only when the key exists.
func (r *IntegrationRepository) RecordTicketingHealth(ctx context.Context, tenantID, id shared.ID, kind string, problem any) error {
	if problem == nil {
		_, err := r.db.ExecContext(ctx, `
			UPDATE integrations
			   SET metadata = metadata #- ARRAY['ticketing_health', $3::text]
			 WHERE tenant_id = $1 AND id = $2
			   AND metadata -> 'ticketing_health' -> $3::text IS NOT NULL`,
			tenantID.String(), id.String(), kind)
		if err != nil {
			return fmt.Errorf("clear ticketing health: %w", err)
		}
		return nil
	}
	value, err := json.Marshal(problem)
	if err != nil {
		return fmt.Errorf("marshal ticketing health: %w", err)
	}
	_, err = r.db.ExecContext(ctx, `
		UPDATE integrations
		   SET metadata = jsonb_set(COALESCE(metadata, '{}'::jsonb), '{ticketing_health}',
		           COALESCE(metadata -> 'ticketing_health', '{}'::jsonb) || jsonb_build_object($3::text, $4::jsonb))
		 WHERE tenant_id = $1 AND id = $2`,
		tenantID.String(), id.String(), kind, string(value))
	if err != nil {
		return fmt.Errorf("record ticketing health: %w", err)
	}
	return nil
}
