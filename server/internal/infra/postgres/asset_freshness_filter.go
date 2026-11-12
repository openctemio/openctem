package postgres

import "github.com/openctemio/openctem/server/pkg/domain/assetlist"

// The inventory's freshness filter (docs/architecture/asset-freshness.md).
// The SQL is generated from the class table, so it always agrees with the
// freshness the asset page shows.

// assetFreshnessCondition is assetlist.FreshnessSQL (alias a).
func assetFreshnessCondition(value string) string { return assetlist.FreshnessSQL(value) }
