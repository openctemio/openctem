package asset

// PrimarySQL is the predicate "the asset is a primary asset" for an assets
// alias a (docs/architecture/exposure-taxonomy.md, "Primary assets"): one of
// the organization's root domains, the names its external attack surface is
// discovered from. That is a domain asset named exactly like the root of a
// permanent, active domain scope entry ("example.com" or "*.example.com")
// or like a verified domain. Both subqueries carry the asset's tenant.
func PrimarySQL(a string) string {
	return `(` + a + `.asset_type = 'domain' AND (
		EXISTS (SELECT 1 FROM scope_targets pst
		         WHERE pst.tenant_id = ` + a + `.tenant_id AND pst.status = 'active' AND pst.expires_at IS NULL
		           AND pst.target_type IN ('domain', 'subdomain')
		           AND rtrim(regexp_replace(lower(pst.pattern), '^\*\*?\.', ''), '.') = lower(` + a + `.name))
		OR EXISTS (SELECT 1 FROM verified_domains pvd
		            WHERE pvd.tenant_id = ` + a + `.tenant_id AND pvd.status = 'verified'
		              AND lower(pvd.domain) = lower(` + a + `.name))))`
}
