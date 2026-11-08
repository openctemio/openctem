// Package assetlist is the asset inventory's list filter: the field registry
// of GET /assets and its document endpoint, and the SQL of the derived asset
// states the filters and other reads share (scope status, monitoring state,
// freshness, coverage, expiry, program system tags). The SQL is constant text
// over an assets alias; values are always bound by the caller or by
// pkg/filterspec. Design: docs/architecture/list-query-contract.md and
// docs/architecture/query-language.md ("Short form").
package assetlist

import (
	"fmt"
	"strings"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/assetfreshness"
	"github.com/openctemio/openctem/api/pkg/domain/coverage"
	"github.com/openctemio/openctem/api/pkg/domain/dashboard"
	"github.com/openctemio/openctem/api/pkg/filterspec"
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

// HostSQL is the lower-case host an asset name names (asset.HostOf),
// for an assets alias.
func HostSQL(a string) string {
	return strings.ReplaceAll(`lower(rtrim(trim(both '[]' from CASE
			WHEN A.name ~ '://' THEN substring(A.name from '://(?:[^@/]*@)?(\[[^\]]+\]|[^/:?#]+)')
			WHEN A.name ~ '^\[[^\]]+\]' THEN substring(A.name from '^(\[[^\]]+\])')
			WHEN A.name ~ ':[0-9]{1,5}[:/](tcp|udp|sctp)$' THEN regexp_replace(A.name, ':[0-9]{1,5}[:/](tcp|udp|sctp)$', '')
			WHEN A.name ~ '^[^:/]+:[0-9]+$' THEN split_part(A.name, ':', 1)
			ELSE A.name END), '.'))`, "A.", a+".")
}

// ScopePatternMatchSQL is "the pattern p of kind covers the host h (ip i,
// lower-case name n)": domain kinds by name and wildcard, address kinds by
// containment or a-b range, any other kind by the scope wildcard on the
// whole name. Every argument is a column reference, never user input.
func ScopePatternMatchSQL(kind, pattern, h, i, n string) string {
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

// ScopeStatusSQL is the scope status of an assets alias (ScopeStatus*
// values): excluded when an active, approved, unexpired exclusion matches
// or the organization marked the asset not its own; internal for a type the
// internet scope does not govern or a private or internal name; in_scope
// when an active, unexpired scope entry covers it; not_covered otherwise.
func ScopeStatusSQL(a string) string {
	h, i, n := "sh.host", "sh.ip", "lower("+a+".name)"
	return `(SELECT CASE
		WHEN EXISTS (SELECT 1 FROM asset_attributions srj
		             WHERE srj.asset_id = ` + a + `.id AND srj.tenant_id = ` + a + `.tenant_id AND srj.state = 'rejected')
		  OR EXISTS (SELECT 1 FROM scope_exclusions se
		             WHERE se.tenant_id = ` + a + `.tenant_id AND se.status = 'active' AND se.approved_at IS NOT NULL
		               AND (se.expires_at IS NULL OR se.expires_at > now())
		               AND se.exclusion_type NOT IN ('finding_type', 'scanner', 'path')
		               AND ` + ScopePatternMatchSQL("se.exclusion_type", "se.pattern", h, i, n) + `)
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
		               AND ` + ScopePatternMatchSQL("st.target_type", "st.pattern", h, i, n) + `)
		  THEN 'in_scope'
		ELSE 'not_covered' END
	FROM (SELECT hh.host, CASE WHEN pg_input_is_valid(hh.host, 'inet') THEN hh.host::inet END AS ip
	      FROM (SELECT ` + HostSQL(a) + ` AS host) hh) sh)`
}

// MonitoringStateSQL is the monitoring state of an assets alias
// (asset.MonitoringStateOf in SQL; the precedence is the same). scanned is
// a SQL boolean expression (a bound placeholder): the tenant scans assets no
// scope entry covers. Every subquery is pinned to the asset's tenant.
func MonitoringStateSQL(a, scanned string) string {
	h, i, n := "sh.host", "sh.ip", "lower("+a+".name)"
	excl := func(kinds string) string {
		return `EXISTS (SELECT 1 FROM scope_exclusions se
		             WHERE se.tenant_id = ` + a + `.tenant_id AND se.status = 'active' AND se.approved_at IS NOT NULL
		               AND (se.expires_at IS NULL OR se.expires_at > now())
		               AND se.exclusion_type NOT IN ('finding_type', 'scanner', 'path')
		               AND se.kind IN ` + kinds + `
		               AND ` + ScopePatternMatchSQL("se.exclusion_type", "se.pattern", h, i, n) + `)`
	}
	return `(SELECT CASE
		WHEN att.state = 'rejected' OR ` + excl("('not_ours')") + ` THEN 'irrelevant'
		WHEN ` + excl("('do_not_scan', 'retired')") + ` THEN 'out_of_scope'
		WHEN ` + a + `.status IN ('inactive', 'archived') THEN 'inactive'
		WHEN att.state = 'needs_review' THEN 'pending_decision'
		WHEN att.state = 'candidate' OR (att.state = 'discovered' AND att.confidence < ` +
		fmt.Sprint(asset.MonitoringConfirmThreshold) + `) THEN 'unvalidated'
		WHEN att.state = 'monitor_only' THEN 'not_monitored'
		WHEN NOT (` + scanned + `) AND ` + ScopeStatusSQL(a) + ` = 'not_covered' THEN 'not_monitored'
		ELSE 'monitored' END
	FROM (SELECT hh.host, CASE WHEN pg_input_is_valid(hh.host, 'inet') THEN hh.host::inet END AS ip
	      FROM (SELECT ` + HostSQL(a) + ` AS host) hh) sh
	LEFT JOIN LATERAL (SELECT x.state, x.confidence FROM asset_attributions x
	                   WHERE x.asset_id = ` + a + `.id AND x.tenant_id = ` + a + `.tenant_id) att ON true)`
}

// freshnessImportantSQL is the SQL form of assetfreshness.Importance.Important.
var freshnessImportantSQL = `(a.criticality IN ('critical', 'high') OR ` + asset.InternetFacingSQL("a") + `)`

// FreshnessSQL returns the WHERE condition for a freshness filter
// value, or "" for none. Every subquery is pinned to the asset's tenant.
func FreshnessSQL(value string) string {
	switch value {
	case assetfreshness.FilterStale:
		return freshnessStaleSQL()
	case assetfreshness.FilterNever:
		return freshnessNeverSQL()
	}
	return ""
}

func freshnessTTLCase(imp assetfreshness.Importance) string {
	var b strings.Builder
	b.WriteString("CASE af.class")
	for _, s := range assetfreshness.Specs() {
		fmt.Fprintf(&b, " WHEN '%s' THEN interval '%d seconds'", s.Class, int64(s.TTL(imp)/time.Second))
	}
	b.WriteString(" END")
	return b.String()
}

// freshnessStaleSQL: some observed class is past its TTL.
func freshnessStaleSQL() string {
	return fmt.Sprintf(`EXISTS (SELECT 1 FROM asset_attribute_freshness af
		WHERE af.tenant_id = a.tenant_id AND af.asset_id = a.id
		  AND af.observed_at < now() - CASE WHEN %s THEN %s ELSE %s END)`,
		freshnessImportantSQL,
		freshnessTTLCase(assetfreshness.Importance{InternetFacing: true}),
		freshnessTTLCase(assetfreshness.Importance{}))
}

// freshnessNeverSQL: a passive class that applies to the asset's type has
// no observation.
func freshnessNeverSQL() string {
	byType := map[string][]string{}
	var order []string
	for _, s := range assetfreshness.Specs() {
		if !s.Passive {
			continue
		}
		for _, t := range s.Types {
			if _, ok := byType[string(t)]; !ok {
				order = append(order, string(t))
			}
			byType[string(t)] = append(byType[string(t)], string(s.Class))
		}
	}
	parts := make([]string, 0, len(order))
	for _, t := range order {
		classes := make([]string, 0, len(byType[t]))
		for _, c := range byType[t] {
			classes = append(classes, fmt.Sprintf(`NOT EXISTS (SELECT 1 FROM asset_attribute_freshness af
				WHERE af.tenant_id = a.tenant_id AND af.asset_id = a.id AND af.class = '%s')`, c))
		}
		parts = append(parts, fmt.Sprintf("(a.asset_type = '%s' AND (%s))", t, strings.Join(classes, " OR ")))
	}
	return "(" + strings.Join(parts, " OR ") + ")"
}

// ResolutionSQL returns the WHERE condition for a resolution
// filter value, or "" for none. The subquery is pinned to the asset's tenant,
// so another tenant's state never matches.
func ResolutionSQL(value string) string {
	switch value {
	case "not_resolving", "resolving":
		return `EXISTS (SELECT 1 FROM asset_resolution ar
			WHERE ar.tenant_id = a.tenant_id AND ar.asset_id = a.id AND ar.state = '` + value + `')`
	}
	return ""
}

// ExpirySQL is an asset's expiry as a timestamptz: the first of its
// properties of format expiry (a certificate's not_after, a domain's
// expires_at) that parses as a timestamp, else NULL. A malformed value reads
// as NULL instead of failing the query. The keys come from the registry, so a
// new expiry property is filtered with no change here.
var ExpirySQL = BuildExpirySQL(asset.ExpiryPropertyKeys())

func BuildExpirySQL(keys []string) string {
	if len(keys) == 0 {
		return "NULL::timestamptz"
	}
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		v := "(a.properties ->> " + pq.QuoteLiteral(k) + ")"
		parts = append(parts, "CASE WHEN pg_input_is_valid("+v+", 'timestamptz') THEN "+v+"::timestamptz END")
	}
	if len(parts) == 1 {
		return parts[0]
	}
	return "COALESCE(" + strings.Join(parts, ", ") + ")"
}

// CoverageTrackedSQL / CoverageCoveredFmt are the ledger predicates for one
// asset (alias a): tracked = the ledger has a capability that applies to it;
// covered = a capability succeeded since {since} AND every capability that
// applies to it succeeded since then. One working probe never makes an asset
// covered while its vulnerability check failed, timed out, was paused or was
// never run: that gap stays visible. Rows refused by scope policy
// ('blocked') and the platform's own DNS checks are not part of the
// requirement; per-vantage rows are read by their own views. The asset list
// filter coverage=covered|uncovered uses the same predicates, so the
// Discovery figure equals the list it opens.
const (
	CoverageTrackedSQL = `EXISTS (SELECT 1 FROM asset_coverage act
		WHERE act.tenant_id = a.tenant_id AND act.asset_id = a.id AND act.state <> 'not_applicable')`
	CoverageCoveredFmt = `(EXISTS (SELECT 1 FROM asset_coverage acs
		WHERE acs.tenant_id = a.tenant_id AND acs.asset_id = a.id AND acs.state <> 'not_applicable'
		AND acs.last_success_at >= %[1]s)
		AND NOT EXISTS (SELECT 1 FROM asset_coverage acg
		WHERE acg.tenant_id = a.tenant_id AND acg.asset_id = a.id AND acg.vantage = ''
		AND acg.state NOT IN ('not_applicable', 'blocked') AND acg.capability NOT LIKE 'dns.%%'
		AND (acg.last_success_at IS NULL OR acg.last_success_at < %[1]s)))`
)

// CoverageCondition is the asset list predicate for coverage=covered or
// uncovered (alias a), with since as the bound placeholder. Unknown values
// give "".
func CoverageCondition(value, sincePlaceholder string) string {
	covered := fmt.Sprintf(CoverageCoveredFmt, sincePlaceholder)
	switch value {
	case "covered":
		return covered
	case "uncovered":
		return CoverageTrackedSQL + " AND NOT " + covered
	}
	return ""
}

// Coverage causes: why an uncovered asset is uncovered, one cause per asset
// (docs/architecture/dashboards.md, "Discovery coverage by cause"). The
// cause is read from the ledger rows of the asset that have no success in
// the coverage window, by precedence: what the platform must fix first
// (no eligible sensor took the check, a platform-side failure such as a
// stalled run, a tool error or the sensor's egress, network or proxy), then
// a paused pair, then what the organization owns (the target did not
// answer, or an edge or rate limit answered for it), then never run, then
// overdue (it ran before but not within the window). Rows refused by scope
// policy ('blocked') and rows outside the requirement (per-vantage rows,
// the platform's DNS checks) only name the cause when nothing else does.
// The asset list filter coverage_cause uses the same expression, so a cause
// row of the widget equals the list it opens.
// sqlList is a list of constant strings as SQL literals (outcome names of
// the coverage package, never input).
func sqlList(vals []string) string {
	out := make([]string, len(vals))
	for i, v := range vals {
		out[i] = pq.QuoteLiteral(v)
	}
	return strings.Join(out, ", ")
}

// CoverageCauseExpr is the cause of one asset (alias a) with since as the
// bound placeholder of the coverage window start.
func CoverageCauseExpr(since string) string {
	causes := dashboard.CoverageCauses()
	return `COALESCE((ARRAY[` + sqlList(causes) + `])[(SELECT MIN(CASE
		WHEN acc.state = 'blocked' THEN 7
		WHEN acc.vantage <> '' OR acc.capability LIKE 'dns.%' THEN 8
		WHEN acc.state = 'paused' THEN 3
		WHEN acc.last_outcome = ` + pq.QuoteLiteral(coverage.OutcomeNotDispatched) + ` THEN 1
		WHEN acc.platform_fail_streak > 0 OR acc.last_outcome IN (` + sqlList(coverage.PlatformSideOutcomes()) + `) THEN 2
		WHEN acc.last_outcome IN (` + sqlList(coverage.ObservedFailureOutcomes()) + `) THEN 4
		WHEN acc.last_attempt_at IS NULL THEN 5
		ELSE 6 END)
		FROM asset_coverage acc WHERE acc.tenant_id = a.tenant_id AND acc.asset_id = a.id
		AND acc.state <> 'not_applicable' AND (acc.last_success_at IS NULL OR acc.last_success_at < ` + since + `))], ` +
		pq.QuoteLiteral(dashboard.CoverageCauseOther) + `)`
}

// CoverageCauseCondition is the asset list predicate for coverage_cause
// (alias a): uncovered, with this cause. since and cause are bound
// placeholders. Unknown causes give "".
func CoverageCauseCondition(cause, since, causeArg string) string {
	if !dashboard.IsCoverageCause(cause) {
		return ""
	}
	return CoverageCondition("uncovered", since) + " AND " + CoverageCauseExpr(since) + " = " + causeArg
}

// ProgramLinkTagsSQL is the FROM clause that yields, as column t, the system
// tags each program link (l, its program p) gives its asset; t is NULL for
// a tag that does not apply. Stored system_tags are its union over every
// link; a non-owner's view and filter use only the links whose program is
// not hidden from them (filterspec.ProgramHiddenSQL).
const ProgramLinkTagsSQL = `asset_program_links l
	JOIN bounty_programs p ON p.tenant_id = l.tenant_id AND p.id = l.program_id
	CROSS JOIN LATERAL (SELECT
		COALESCE(NULLIF(regexp_replace(lower(p.platform), '[^a-z0-9-]+', '-', 'g'), ''), 'self') AS plat,
		regexp_replace(lower(COALESCE(NULLIF(p.handle, ''), p.name)), '[^a-z0-9-]+', '-', 'g') AS slug) s
	CROSS JOIN LATERAL unnest(ARRAY[
		'bug-bounty',
		'source:' || replace(l.source, '_', '-'),
		'platform:' || s.plat,
		'program:' || s.plat || ':' || s.slug,
		CASE WHEN p.status = 'pending_attestation' THEN 'program-unattested' END]) AS t`

// VisibleProgramLinkSQL is the condition "asset assetExpr of tenant
// tenantExpr has a program link not hidden from user userExpr" (extra
// narrows the links further, e.g. "AND t = ANY($3)"; it may use t, l, p).
func VisibleProgramLinkSQL(assetExpr, tenantExpr, userExpr, extra string) string {
	return `EXISTS (SELECT 1 FROM ` + ProgramLinkTagsSQL + `
		WHERE l.tenant_id = ` + tenantExpr + `
		  AND l.asset_id = ` + assetExpr + ` AND t IS NOT NULL ` + extra + `
		  AND NOT ` + filterspec.ProgramHiddenSQL("p", userExpr) + `)`
}

// HasAnyTagSQL is the condition "asset a carries a tag of array arr"
// (a SQL text[] expression), counting the system tags; with viewerArg (a
// uuid placeholder) only the system tags of programs not hidden from that
// user count.
func HasAnyTagSQL(arr, viewerArg string) string {
	if viewerArg == "" {
		return fmt.Sprintf("(a.tags && %s OR a.system_tags && %s)", arr, arr)
	}
	return fmt.Sprintf("(a.tags && %s OR (a.system_tags && %s AND %s))", arr, arr,
		VisibleProgramLinkSQL("a.id", "a.tenant_id", viewerArg, "AND t = ANY("+arr+")"))
}

// HasTagSQL is the condition "asset a carries tag tag" (a SQL text
// expression), with the same system tag rule as HasAnyTagSQL.
func HasTagSQL(tag, viewerArg string) string {
	if viewerArg == "" {
		return fmt.Sprintf("(%s = ANY(a.tags) OR %s = ANY(a.system_tags))", tag, tag)
	}
	return fmt.Sprintf("(%s = ANY(a.tags) OR (%s = ANY(a.system_tags) AND %s))", tag, tag,
		VisibleProgramLinkSQL("a.id", "a.tenant_id", viewerArg, "AND t = "+tag))
}
