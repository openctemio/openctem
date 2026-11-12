package sla

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	sladom "github.com/openctemio/openctem/api/pkg/domain/sla"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// failingSLARepo fails every policy read with a non-not-found error, as a
// dropped database connection does.
type failingSLARepo struct{ sladom.Repository }

var errPolicyDB = errors.New("connection reset")

func (failingSLARepo) GetByAsset(context.Context, shared.ID, shared.ID) (*sladom.Policy, error) {
	return nil, errPolicyDB
}

func (failingSLARepo) GetTenantDefault(context.Context, shared.ID) (*sladom.Policy, error) {
	return nil, errPolicyDB
}

// A policy that cannot be read must not turn into the platform defaults:
// deadlines only tighten, so a default deadline or KEV cap written on a
// transient error would stick for good. No policy configured still gives
// the defaults.
func TestSLA_PolicyReadErrorIsNotTheDefaultPolicy(t *testing.T) {
	ctx := context.Background()
	tenant, asset := shared.NewID().String(), shared.NewID().String()
	now := time.Now()

	svc := NewService(failingSLARepo{}, logger.NewNop())
	if _, err := svc.CalculateSLADeadlineForPriority(ctx, tenant, asset, "P1", vulnerability.SeverityHigh, now); !errors.Is(err, errPolicyDB) {
		t.Fatalf("deadline on a failed policy read: err = %v, want the read error", err)
	}
	if _, err := svc.CalculateSLADeadlineForPriority(ctx, tenant, "", "P1", vulnerability.SeverityHigh, now); !errors.Is(err, errPolicyDB) {
		t.Fatalf("tenant deadline on a failed policy read: err = %v, want the read error", err)
	}
	if _, err := svc.KEVCapDays(ctx, tenant, asset); !errors.Is(err, errPolicyDB) {
		t.Fatalf("KEV cap on a failed policy read: err = %v, want the read error", err)
	}
	if cap := NewApplier(svc).singleKEVCap(ctx, tenant)(asset); cap != 0 {
		t.Fatalf("applier KEV cap on a failed read = %d, want 0 (no cap this pass)", cap)
	}

	none := NewService(&memSLARepo{}, logger.NewNop())
	d, err := none.CalculateSLADeadlineForPriority(ctx, tenant, asset, "P1", vulnerability.SeverityHigh, now)
	if err != nil || d.IsZero() {
		t.Fatalf("no policy configured: deadline = %v, err = %v, want the platform default", d, err)
	}
	if days, err := none.KEVCapDays(ctx, tenant, asset); err != nil || days != sladom.DefaultKEVCapDays {
		t.Fatalf("no policy configured: KEV cap = %d, err = %v, want %d", days, err, sladom.DefaultKEVCapDays)
	}
}
