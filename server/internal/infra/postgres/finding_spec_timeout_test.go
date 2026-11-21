package postgres

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/lib/pq"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/openctemio/openctem/server/pkg/domain/asset"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/vulnerability"
)

// A statement timeout (query_canceled) on a findings read is the typed
// ErrFindingQueryTimeout (a shared.ErrQueryTimeout, so every handler can
// answer 503); the driver text is dropped. Any other database error is left
// as it is.
func TestFindingTimeout_MapsQueryCanceled(t *testing.T) {
	ctx := context.Background()
	canceled := &pq.Error{Code: "57014", Message: "canceling statement due to statement timeout"}
	err := findingTimeout(ctx, fmt.Errorf("count: %w", canceled))
	if !errors.Is(err, vulnerability.ErrFindingQueryTimeout) || !errors.Is(err, shared.ErrQueryTimeout) {
		t.Fatalf("query_canceled = %v, want ErrFindingQueryTimeout", err)
	}
	if errors.As(err, new(*pq.Error)) {
		t.Fatal("the driver error must not reach the caller")
	}
	other := &pq.Error{Code: "42P01"}
	if err := findingTimeout(ctx, other); errors.Is(err, vulnerability.ErrFindingQueryTimeout) {
		t.Fatalf("undefined_table mapped to a timeout: %v", err)
	}
	if findingTimeout(ctx, nil) != nil {
		t.Fatal("nil error changed")
	}
}

// Every mapped timeout is counted under its read's name.
func TestReadTimeout_CountsByRead(t *testing.T) {
	ctx := context.Background()
	before := testutil.ToFloat64(readTimeouts.WithLabelValues(readAssets))
	canceled := &pq.Error{Code: "57014"}
	if err := assetTimeout(ctx, canceled); !errors.Is(err, asset.ErrQueryTimeout) || !errors.Is(err, shared.ErrQueryTimeout) {
		t.Fatalf("asset timeout = %v", err)
	}
	if got := testutil.ToFloat64(readTimeouts.WithLabelValues(readAssets)) - before; got != 1 {
		t.Fatalf("counted %v timeouts, want 1", got)
	}
	_ = assetTimeout(ctx, errors.New("other"))
	if got := testutil.ToFloat64(readTimeouts.WithLabelValues(readAssets)) - before; got != 1 {
		t.Fatalf("a non-timeout error was counted (%v)", got)
	}
}
