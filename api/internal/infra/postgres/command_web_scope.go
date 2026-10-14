package postgres

// The create guard of the command repository: every command passes it
// before it is stored, so a web job gets the web scope of its tenant's path
// exclusions whatever path created it (docs/rfcs/RFC-056-web-attack-surface.md
// §5, RFC-055 §6.1).

import (
	"context"
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/command"
)

// SetCreateGuard wires the guard every command passes before it is stored
// (the scope service's web job guard).
func (r *CommandRepository) SetCreateGuard(g command.CreateGuard) { r.guard = g }

// tenantHasPathRuleSQL: the tenant has a path exclusion that may be in
// effect (a superset of what the web scope is built from).
const tenantHasPathRuleSQL = `
	SELECT EXISTS (
		SELECT 1 FROM scope_exclusions
		WHERE tenant_id = $1 AND exclusion_type = 'path' AND status = 'active'
	)`

// guardCreate runs the create guard. Without one, a job that may be a web
// job (any job naming a tool: the organization's tool facts are not read
// here) is refused when its tenant has a path exclusion that may apply, or
// when that cannot be read: its web scope cannot be built here (fail
// closed).
func (r *CommandRepository) guardCreate(ctx context.Context, cmd *command.Command) error {
	if r.guard != nil {
		return r.guard.GuardCreate(ctx, cmd)
	}
	if _, ok := command.WebJobOf(cmd, command.AnyTool); !ok {
		return nil
	}
	var has bool
	if err := r.db.QueryRowContext(ctx, tenantHasPathRuleSQL, cmd.TenantID.String()).Scan(&has); err != nil {
		return fmt.Errorf("%w: %w", command.ErrWebScopeUnwired, err)
	}
	if has {
		return command.ErrWebScopeUnwired
	}
	return nil
}
