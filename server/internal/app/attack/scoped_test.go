package attack

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/datascope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// A caller-facing attack-surface read refuses when the data-scope enforcer is
// not wired, instead of returning the organization's full result.
func TestCallerReads_UnwiredEnforcer_FailClosed(t *testing.T) {
	svc := NewSurfaceService(nil, nil, logger.NewNop())
	if _, err := svc.AttackPathScoresForCaller(context.Background(), shared.NewID()); !errors.Is(err, datascope.ErrNotConfigured) {
		t.Fatalf("AttackPathScoresForCaller err = %v, want datascope.ErrNotConfigured", err)
	}
	if _, err := svc.ExposureChainsForCaller(context.Background(), shared.NewID()); !errors.Is(err, datascope.ErrNotConfigured) {
		t.Fatalf("ExposureChainsForCaller err = %v, want datascope.ErrNotConfigured", err)
	}
}
