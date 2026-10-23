package postgres

import (
	"errors"
	"fmt"
	"testing"

	"github.com/lib/pq"
	"github.com/lib/pq/pqerror"
)

// PostgreSQL 16 and 17 report a RESTRICT foreign key that refuses a delete as
// 23503; PostgreSQL 18 reports 23001 (restrict_violation). Both mean "a row
// still references this one", and callers map both the same way.
func TestIsForeignKeyViolation_BothSQLStates(t *testing.T) {
	for _, code := range []string{"23503", "23001"} {
		err := fmt.Errorf("delete: %w", &pq.Error{Code: pqerror.Code(code)})
		if !isForeignKeyViolation(err) {
			t.Errorf("SQLSTATE %s is not recognized as a foreign-key violation", code)
		}
	}
	for _, code := range []string{"23505", "23514", "23502"} {
		if isForeignKeyViolation(&pq.Error{Code: pqerror.Code(code)}) {
			t.Errorf("SQLSTATE %s must not count as a foreign-key violation", code)
		}
	}
	if isForeignKeyViolation(errors.New("plain")) {
		t.Error("a non-pq error is not a foreign-key violation")
	}
}
