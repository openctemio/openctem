package asset

// The address range condition shared by every range filter: the assets ip
// filter (pkg/domain/assetlist), the findings asset_ip filter
// (pkg/domain/vulnerability), smart asset group rules and the legacy list
// filter in_cidr (internal/infra/postgres). One implementation, so a group
// rule and the list filter always agree (docs/architecture/asset-addresses.md).
//
// An asset is inside a range when its name or any address it has is: the
// name of an ip_address asset or of a host named by an address, and for
// hosts and network devices every address recorded in their properties
// (ip_addresses, private_ip, public_ip). The table asset_ip_addresses holds
// them, kept by triggers on assets.

// AssetIDsInRangesSQL is a subquery of the ids of the tenant's assets with
// an address inside one of the ranges. tenant and every range are SQL
// expressions (placeholders); a range is an inet (an address or a CIDR
// range). Each range is one btree range scan on idx_asset_ip_addresses_range
// (tenant_id, addr): stored addresses are full-mask, so the first and the
// last address of the range bound it exactly.
func AssetIDsInRangesSQL(tenant string, ranges ...string) string {
	if len(ranges) == 0 {
		return "SELECT NULL::uuid WHERE FALSE"
	}
	conds := ""
	for i, r := range ranges {
		if i > 0 {
			conds += " OR "
		}
		conds += "x.addr BETWEEN host(network(" + r + "))::inet AND host(broadcast(" + r + "))::inet"
	}
	return "SELECT x.asset_id FROM asset_ip_addresses x WHERE x.tenant_id = " + tenant + " AND (" + conds + ")"
}

// AssetInRangesSQL is "the asset id in column col has an address inside one
// of the ranges": a semi join the planner sizes from the address table's
// statistics. A wide range walks the list's sort index and probes the
// primary key (tenant_id, asset_id, addr) per row, stopping at the page; a
// narrow one reads its few ids from the range index first. Several values
// ORed by the filter compiler become hashed subplans. An array of ids
// (= ANY(ARRAY(...))) is not used: the planner cannot size it, and on a wide
// range it built every matching row before the page was cut
// (docs/architecture/asset-addresses.md, "Query shape").
func AssetInRangesSQL(col, tenant string, ranges ...string) string {
	return col + " IN (" + AssetIDsInRangesSQL(tenant, ranges...) + ")"
}
