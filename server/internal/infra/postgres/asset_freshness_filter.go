package postgres

// The inventory's freshness filter (docs/architecture/asset-freshness.md).
// The SQL is generated from the class table, so it always agrees with the
// freshness the asset page shows.

import (
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/asset"

	"github.com/openctemio/openctem/api/pkg/domain/assetfreshness"
)

// freshnessImportantSQL is the SQL form of assetfreshness.Importance.Important.
var freshnessImportantSQL = `(a.criticality IN ('critical', 'high') OR ` + asset.InternetFacingSQL("a") + `)`

// assetFreshnessCondition returns the WHERE condition for a freshness filter
// value, or "" for none. Every subquery is pinned to the asset's tenant.
func assetFreshnessCondition(value string) string {
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
