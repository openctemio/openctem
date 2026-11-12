package postgres

import (
	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// The identity-explanation columns of the findings table: the recipe that
// keyed the finding and the NAMES of its key's fields (never values). See
// docs/architecture/deduplication.md, "Why a finding is one".
//
// Order matters: findingIdentityColumnsSQL and findingIdentityArgs list the
// columns in the same order.
const findingIdentityColumnsSQL = `identity_algo, identity_fields`

// findingIdentityColumnCount is the number of columns in findingIdentityColumnsSQL.
const findingIdentityColumnCount = 2

func findingIdentityArgs(f *vulnerability.Finding) []any {
	return identityRecipeArgs(f.IdentityAlgo(), f.IdentityFields())
}

// identityRecipeArgs is the (identity_algo, identity_fields) argument pair:
// NULL, NULL for an unknown recipe.
func identityRecipeArgs(algo string, fields []string) []any {
	if algo == "" || !vulnerability.ValidIdentityAlgo(algo) || len(fields) > vulnerability.MaxIdentityFields {
		return []any{nil, nil}
	}
	if len(fields) == 0 {
		return []any{algo, nil}
	}
	return []any{algo, pq.Array(fields)}
}

// identityKeyRecipeArgs is identityRecipeArgs for a stored identity tuple.
func identityKeyRecipeArgs(raw []byte) []any {
	algo, fields, ok := vulnerability.IdentityRecipeOf(raw)
	if !ok {
		return []any{nil, nil}
	}
	return identityRecipeArgs(algo, fields)
}

// findingIdentityConflictSQL is the ON CONFLICT ... DO UPDATE part. A
// re-sighting never changes the stored key, so the stored recipe stays; a
// row keyed before recipes were recorded takes the incoming one, but only
// when the incoming row was keyed by the same recipe version (a version-1
// sighting translated onto a version-2 finding's key must not label it).
func findingIdentityConflictSQL() string {
	return `,
			identity_fields = CASE WHEN findings.identity_algo IS NULL
				AND findings.fingerprint_version = EXCLUDED.fingerprint_version
				THEN EXCLUDED.identity_fields ELSE findings.identity_fields END,
			identity_algo = CASE WHEN findings.identity_algo IS NULL
				AND findings.fingerprint_version = EXCLUDED.fingerprint_version
				THEN EXCLUDED.identity_algo ELSE findings.identity_algo END`
}

// findingIdentityPlaceholders is ", $first, …" for the identity columns of
// a hand-numbered single-row INSERT.
func findingIdentityPlaceholders(first int) string {
	out := ""
	for i := 0; i < findingIdentityColumnCount; i++ {
		out += ", " + placeholder(first+i)
	}
	return out
}
