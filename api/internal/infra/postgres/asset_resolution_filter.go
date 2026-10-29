package postgres

// The assets list filter on whether a host name resolves.

// assetResolutionCondition returns the WHERE condition for a resolution
// filter value, or "" for none. The subquery is pinned to the asset's tenant,
// so another tenant's state never matches.
func assetResolutionCondition(value string) string {
	switch value {
	case "not_resolving", "resolving":
		return `EXISTS (SELECT 1 FROM asset_resolution ar
			WHERE ar.tenant_id = a.tenant_id AND ar.asset_id = a.id AND ar.state = '` + value + `')`
	}
	return ""
}
