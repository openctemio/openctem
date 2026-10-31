package postgres

// Scope status of an inventory asset, in SQL, for list filters (research/124,
// RFC-054 §15): which assets the organization's scope covers, which no entry
// covers (passive only), which it excluded or marked not its own, and which
// are internal (governed by scan zones, not by internet scope).
//
// The match mirrors the scope coverage count (scope_coverage_repository.go)
// and pkg/domain/scope on the asset's host (the name, or the host of a URL or
// host:port). It is a filter: the active-scan gate (easm.ActiveGate) stays
// the authority on what a scan may reach, and the list shows the gate's own
// answer per row. Every subquery is pinned to the asset's tenant.

import (
	"context"
	"fmt"
	"strings"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Scope statuses of the asset list filter (?scope_status=).
const (
	ScopeStatusInScope    = "in_scope"
	ScopeStatusNotCovered = "not_covered"
	ScopeStatusExcluded   = "excluded"
	ScopeStatusInternal   = "internal"
)

// ValidScopeStatus reports whether s is a scope status filter value.
func ValidScopeStatus(s string) bool {
	switch s {
	case ScopeStatusInScope, ScopeStatusNotCovered, ScopeStatusExcluded, ScopeStatusInternal:
		return true
	}
	return false
}

// assetHostSQL is the lower-case host an asset name names (asset.HostOf),
// for an assets alias.
func assetHostSQL(a string) string {
	return strings.ReplaceAll(`lower(rtrim(trim(both '[]' from CASE
			WHEN A.name ~ '://' THEN substring(A.name from '://(?:[^@/]*@)?(\[[^\]]+\]|[^/:?#]+)')
			WHEN A.name ~ '^\[[^\]]+\]' THEN substring(A.name from '^(\[[^\]]+\])')
			WHEN A.name ~ ':[0-9]{1,5}[:/](tcp|udp|sctp)$' THEN regexp_replace(A.name, ':[0-9]{1,5}[:/](tcp|udp|sctp)$', '')
			WHEN A.name ~ '^[^:/]+:[0-9]+$' THEN split_part(A.name, ':', 1)
			ELSE A.name END), '.'))`, "A.", a+".")
}

// scopePatternMatchSQL is "the pattern p of kind covers the host h (ip i,
// lower-case name n)": domain kinds by name and wildcard, address kinds by
// containment or a-b range, any other kind by the scope wildcard on the
// whole name. Every argument is a column reference, never user input.
func scopePatternMatchSQL(kind, pattern, h, i, n string) string {
	p := "lower(rtrim(trim(" + pattern + "), '.'))"
	wild := "(" + p + " LIKE '*.%' OR " + p + " LIKE '**.%')"
	root := "regexp_replace(" + p + ", '^\\*\\*?\\.', '')"
	net := "CASE WHEN pg_input_is_valid(" + p + ", 'inet') THEN " + p + "::inet END"
	lo := "CASE WHEN " + p + " ~ '^[^-]+-[^-]+$' AND pg_input_is_valid(trim(split_part(" + p + ", '-', 1)), 'inet') AND pg_input_is_valid(trim(split_part(" + p + ", '-', 2)), 'inet') THEN trim(split_part(" + p + ", '-', 1))::inet END"
	hi := "CASE WHEN " + p + " ~ '^[^-]+-[^-]+$' AND pg_input_is_valid(trim(split_part(" + p + ", '-', 1)), 'inet') AND pg_input_is_valid(trim(split_part(" + p + ", '-', 2)), 'inet') THEN trim(split_part(" + p + ", '-', 2))::inet END"
	return fmt.Sprintf(`(
		(%[1]s IN ('domain', 'subdomain', 'email_domain')
			AND ((NOT %[2]s AND %[4]s = %[3]s)
			  OR (%[2]s AND (%[4]s = %[3]s OR right(%[4]s, length(%[3]s) + 1) = '.' || %[3]s))))
		OR (%[1]s IN ('ip_address', 'cidr', 'ip_range') AND %[5]s IS NOT NULL AND (
			(%[6]s) IS NOT NULL AND %[5]s <<= (%[6]s)
			OR ((%[7]s) IS NOT NULL AND (%[8]s) IS NOT NULL AND %[5]s >= (%[7]s) AND %[5]s <= (%[8]s))))
		OR (%[1]s NOT IN ('domain', 'subdomain', 'email_domain', 'ip_address', 'cidr', 'ip_range') AND (
			%[9]s = %[10]s
			OR (%[10]s LIKE '%%/*' AND (%[9]s = left(%[10]s, -2) OR left(%[9]s, length(%[10]s) - 1) = left(%[10]s, -1)))
			OR (%[10]s NOT LIKE '%%/*' AND array_length(string_to_array(%[10]s, '*'), 1) = 2
			    AND left(%[9]s, length(split_part(%[10]s, '*', 1))) = split_part(%[10]s, '*', 1)
			    AND right(%[9]s, length(split_part(%[10]s, '*', 2))) = split_part(%[10]s, '*', 2)))))`,
		kind, wild, root, h, i, net, lo, hi, n, p)
}

// scopeInternetTypes are the asset types the internet scope governs (the
// scope coverage count's set); every other type is internal here.
const scopeInternetTypes = `('domain', 'subdomain', 'ip_address', 'service', 'application')`

// assetScopeStatusSQL is the scope status of an assets alias (ScopeStatus*
// values): excluded when an active, approved, unexpired exclusion matches
// or the organization marked the asset not its own; internal for a type the
// internet scope does not govern or a private or internal name; in_scope
// when an active, unexpired scope entry covers it; not_covered otherwise.
func assetScopeStatusSQL(a string) string {
	h, i, n := "sh.host", "sh.ip", "lower("+a+".name)"
	return `(SELECT CASE
		WHEN EXISTS (SELECT 1 FROM asset_attributions srj
		             WHERE srj.asset_id = ` + a + `.id AND srj.tenant_id = ` + a + `.tenant_id AND srj.state = 'rejected')
		  OR EXISTS (SELECT 1 FROM scope_exclusions se
		             WHERE se.tenant_id = ` + a + `.tenant_id AND se.status = 'active' AND se.approved_at IS NOT NULL
		               AND (se.expires_at IS NULL OR se.expires_at > now())
		               AND se.exclusion_type NOT IN ('finding_type', 'scanner', 'path')
		               AND ` + scopePatternMatchSQL("se.exclusion_type", "se.pattern", h, i, n) + `)
		  THEN 'excluded'
		WHEN ` + a + `.asset_type NOT IN ` + scopeInternetTypes + `
		  OR (` + i + ` IS NOT NULL AND ` + i + ` <<= ANY (ARRAY['10.0.0.0/8','172.16.0.0/12','192.168.0.0/16','127.0.0.0/8','169.254.0.0/16',
		                     '100.64.0.0/10','0.0.0.0/8','::1/128','fc00::/7','fe80::/10']::inet[]))
		  OR ` + h + ` = 'localhost' OR ` + h + ` LIKE '%.localhost' OR ` + h + ` LIKE '%.local'
		  OR ` + h + ` LIKE '%.internal' OR ` + h + ` LIKE '%.lan'
		  THEN 'internal'
		WHEN EXISTS (SELECT 1 FROM scope_targets st
		             WHERE st.tenant_id = ` + a + `.tenant_id AND st.status = 'active'
		               AND (st.expires_at IS NULL OR st.expires_at > now())
		               AND st.ports = '' AND st.protocol = ''
		               AND ` + scopePatternMatchSQL("st.target_type", "st.pattern", h, i, n) + `)
		  THEN 'in_scope'
		ELSE 'not_covered' END
	FROM (SELECT hh.host, CASE WHEN pg_input_is_valid(hh.host, 'inet') THEN hh.host::inet END AS ip
	      FROM (SELECT ` + assetHostSQL(a) + ` AS host) hh) sh)`
}

// assetMonitoringStateSQL is the monitoring state of an assets alias
// (asset.MonitoringStateOf in SQL; the precedence is the same). scanned is
// a SQL boolean expression (a bound placeholder): the tenant scans assets no
// scope entry covers. Every subquery is pinned to the asset's tenant.
func assetMonitoringStateSQL(a, scanned string) string {
	h, i, n := "sh.host", "sh.ip", "lower("+a+".name)"
	excl := func(kinds string) string {
		return `EXISTS (SELECT 1 FROM scope_exclusions se
		             WHERE se.tenant_id = ` + a + `.tenant_id AND se.status = 'active' AND se.approved_at IS NOT NULL
		               AND (se.expires_at IS NULL OR se.expires_at > now())
		               AND se.exclusion_type NOT IN ('finding_type', 'scanner', 'path')
		               AND se.kind IN ` + kinds + `
		               AND ` + scopePatternMatchSQL("se.exclusion_type", "se.pattern", h, i, n) + `)`
	}
	return `(SELECT CASE
		WHEN att.state = 'rejected' OR ` + excl("('not_ours')") + ` THEN 'irrelevant'
		WHEN ` + excl("('do_not_scan', 'retired')") + ` THEN 'out_of_scope'
		WHEN ` + a + `.status IN ('inactive', 'archived') THEN 'inactive'
		WHEN att.state = 'needs_review' THEN 'pending_decision'
		WHEN att.state = 'candidate' OR (att.state = 'discovered' AND att.confidence < ` +
		fmt.Sprint(asset.MonitoringConfirmThreshold) + `) THEN 'unvalidated'
		WHEN att.state = 'monitor_only' THEN 'not_monitored'
		WHEN NOT (` + scanned + `) AND ` + assetScopeStatusSQL(a) + ` = 'not_covered' THEN 'not_monitored'
		ELSE 'monitored' END
	FROM (SELECT hh.host, CASE WHEN pg_input_is_valid(hh.host, 'inet') THEN hh.host::inet END AS ip
	      FROM (SELECT ` + assetHostSQL(a) + ` AS host) hh) sh
	LEFT JOIN LATERAL (SELECT x.state, x.confidence FROM asset_attributions x
	                   WHERE x.asset_id = ` + a + `.id AND x.tenant_id = ` + a + `.tenant_id) att ON true)`
}

// MonitoringStates returns the derived monitoring state of each of the
// tenant's assets among ids (at most a list page), by id. An id that is not
// the tenant's live asset is absent.
func (r *AssetRepository) MonitoringStates(ctx context.Context, tenantID shared.ID, ids []string, unclassifiedScanned bool) (map[string]string, error) {
	out := make(map[string]string, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := r.db.QueryContext(ctx, `SELECT a.id, `+assetMonitoringStateSQL("a", "$3::boolean")+`
		FROM assets a WHERE a.tenant_id = $1 AND a.id = ANY($2::uuid[]) AND a.deleted_at IS NULL`,
		tenantID.String(), pq.Array(ids), unclassifiedScanned)
	if err != nil {
		return nil, fmt.Errorf("asset monitoring states: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var id, state string
		if err := rows.Scan(&id, &state); err != nil {
			return nil, fmt.Errorf("scan asset monitoring state: %w", err)
		}
		out[id] = state
	}
	return out, rows.Err()
}
