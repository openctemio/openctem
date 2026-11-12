package postgres

// UsableOwnerExists is the one SQL definition of "this organization has an
// owner who can act": a member whose owner role is in force, whose membership
// is active, and whose account is active and not erased. A membership alone is
// not enough: an administrator who blocks an account (users.status
// 'suspended') or an erased account leaves an owner membership that nobody
// can use, and the organization then needs recovery.
//
// tenantIDExpr is the SQL expression for the organization's id (a column such
// as "t.id" or a placeholder such as "$1"). The fragment uses its own aliases,
// so it nests in any query.
func UsableOwnerExists(tenantIDExpr string) string {
	return `EXISTS (SELECT 1 ` + usableOwnerFrom(tenantIDExpr) + `)`
}

// UsableOwnerCount is the matching count of usable owners, from the same
// definition (a query that takes the organization id as tenantIDExpr).
func UsableOwnerCount(tenantIDExpr string) string {
	return `SELECT COUNT(DISTINCT uom.user_id) ` + usableOwnerFrom(tenantIDExpr)
}

func usableOwnerFrom(tenantIDExpr string) string {
	return `FROM tenant_members uom
		JOIN users uou ON uou.id = uom.user_id
		JOIN v_user_effective_role uover ON uover.user_id = uom.user_id AND uover.tenant_id = uom.tenant_id
		WHERE uom.tenant_id = ` + tenantIDExpr + ` AND uover.role = 'owner'
		  AND COALESCE(uom.status, 'active') = 'active'
		  AND uou.status = 'active' AND uou.erased_at IS NULL`
}
