package postgres

import (
	"strings"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
)

// expirySQL is an asset's expiry as a timestamptz: the first of its
// properties of format expiry (a certificate's not_after, a domain's
// expires_at) that parses as a timestamp, else NULL. A malformed value reads
// as NULL instead of failing the query. The keys come from the registry, so a
// new expiry property is filtered with no change here.
var expirySQL = buildExpirySQL(asset.ExpiryPropertyKeys())

func buildExpirySQL(keys []string) string {
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
