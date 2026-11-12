package postgres

import (
	"errors"
	"testing"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// A statement timeout (query_canceled) on a findings read is the typed
// ErrFindingQueryTimeout; any other database error is left as it is.
func TestFindingTimeout_MapsQueryCanceled(t *testing.T) {
	canceled := &pq.Error{Code: "57014", Message: "canceling statement due to statement timeout"}
	if err := findingTimeout(canceled); !errors.Is(err, vulnerability.ErrFindingQueryTimeout) || !errors.As(err, new(*pq.Error)) {
		t.Fatalf("query_canceled = %v, want ErrFindingQueryTimeout wrapping the pq error", err)
	}
	other := &pq.Error{Code: "42P01"}
	if err := findingTimeout(other); errors.Is(err, vulnerability.ErrFindingQueryTimeout) {
		t.Fatalf("undefined_table mapped to a timeout: %v", err)
	}
	if findingTimeout(nil) != nil {
		t.Fatal("nil error changed")
	}
}
