package filterspec

import (
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Visibility of the containers that group assets (asset groups, business
// units, business services) follows the reader's data scope
// (research/233 D4): a restricted reader sees a container only when one of
// its assets is in their scope, or when a scope rule of a team they belong
// to names the asset group. Anything else is absent from lists, totals and
// search, and a read by id answers 404. Names, descriptions and owners of
// these containers describe the organization, so a member restricted to
// some assets must not learn the containers that hold none of them.
//
// Each helper returns a predicate over the container row for a restricted
// scope, numbered at $first (the user id) and $first+1 (the tenant id), and
// those two arguments: the same pair ScopeSQL binds, so a caller that
// already bound the scope arguments for its counts reuses them. Callers
// apply it only when scope.Restricted(): an owner, or an administrator or
// full-data reader, sees every container.

// AssetGroupVisibleSQL is "the asset group groupExpr is visible to the
// reader": a live member of the group is in their scope, or an active
// asset_group_match scope rule of an active team they are a current member
// of names the group (an empty group granted by a rule stays visible to
// that team).
func AssetGroupVisibleSQL(groupExpr string, scope *shared.DataScope, first int) (string, []any) {
	inScope, args := ScopeSQL("vis_m.asset_id", scope, first)
	return fmt.Sprintf(`(EXISTS (
		SELECT 1 FROM asset_group_members vis_m
		JOIN assets vis_a ON vis_a.id = vis_m.asset_id AND vis_a.tenant_id = $%[2]d AND vis_a.deleted_at IS NULL
		WHERE vis_m.asset_group_id = %[1]s AND %[3]s
	) OR EXISTS (
		SELECT 1 FROM group_asset_scope_rules vis_r
		JOIN groups vis_g ON vis_g.id = vis_r.group_id AND vis_g.tenant_id = vis_r.tenant_id AND vis_g.is_active = TRUE
		JOIN group_members vis_gm ON vis_gm.group_id = vis_g.id AND vis_gm.user_id = $%[4]d
			AND (vis_gm.expires_at IS NULL OR vis_gm.expires_at > now())
		WHERE vis_r.tenant_id = $%[2]d AND vis_r.is_active = TRUE
			AND vis_r.rule_type = 'asset_group_match'
			AND %[1]s = ANY(vis_r.match_asset_group_ids)
	))`, groupExpr, first+1, inScope, first), args
}

// BusinessUnitVisibleSQL is "the business unit unitExpr is visible to the
// reader": the unit, or a unit below it in the hierarchy, holds a live asset
// in their scope. The ancestors of a visible unit are visible, so the tree
// a reader sees is always connected. UNION (not UNION ALL) ends the walk on
// a cycle.
func BusinessUnitVisibleSQL(unitExpr string, scope *shared.DataScope, first int) (string, []any) {
	inScope, args := ScopeSQL("vis_ua.asset_id", scope, first)
	return fmt.Sprintf(`%[1]s IN (
		WITH RECURSIVE vis_units(id) AS (
			SELECT vis_ua.business_unit_id
			FROM business_unit_assets vis_ua
			JOIN assets vis_a ON vis_a.id = vis_ua.asset_id AND vis_a.tenant_id = $%[2]d AND vis_a.deleted_at IS NULL
			WHERE vis_ua.tenant_id = $%[2]d AND %[3]s
			UNION
			SELECT vis_p.parent_id
			FROM business_units vis_p
			JOIN vis_units ON vis_p.id = vis_units.id
			WHERE vis_p.tenant_id = $%[2]d AND vis_p.parent_id IS NOT NULL
		)
		SELECT id FROM vis_units
	)`, unitExpr, first+1, inScope), args
}

// BusinessServiceVisibleSQL is "the business service serviceExpr is visible
// to the reader": it links a live asset in their scope.
func BusinessServiceVisibleSQL(serviceExpr string, scope *shared.DataScope, first int) (string, []any) {
	inScope, args := ScopeSQL("vis_sa.asset_id", scope, first)
	return fmt.Sprintf(`EXISTS (
		SELECT 1 FROM business_service_assets vis_sa
		JOIN assets vis_a ON vis_a.id = vis_sa.asset_id AND vis_a.tenant_id = $%[2]d AND vis_a.deleted_at IS NULL
		WHERE vis_sa.service_id = %[1]s AND vis_sa.tenant_id = $%[2]d AND %[3]s
	)`, serviceExpr, first+1, inScope), args
}
