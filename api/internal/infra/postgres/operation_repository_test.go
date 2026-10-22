package postgres

import (
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/operation"
)

// The SQL stale interval and the domain constant describe the same rule.
func TestOperationStaleSQLMatches(t *testing.T) {
	if operation.StaleAfter.Minutes() != 5 || operationStaleSQL != "interval '5 minutes'" {
		t.Fatalf("operation.StaleAfter = %v, SQL %s: keep them equal", operation.StaleAfter, operationStaleSQL)
	}
}
