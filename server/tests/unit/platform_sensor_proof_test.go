package unit

// The platform setting "Require a verified domain before platform sensors
// scan a target" (RFC-054 §8.1): default off, fail-closed reads, versioned
// writes by a platform administrator with a reason, and a critical audit row.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/scanpolicy"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/scangov"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// memProofRepo is memPolicyRepo with the proof setting.
type memProofRepo struct {
	memPolicyRepo
	required *bool
	pVersion int
	pFail    bool
}

func (r *memProofRepo) GetProofRequired(context.Context) (bool, int, error) {
	if r.pFail {
		return false, 0, errors.New("db down")
	}
	if r.required == nil {
		return false, 0, scanpolicy.ErrNotFound
	}
	return *r.required, r.pVersion, nil
}

func (r *memProofRepo) SetProofRequired(_ context.Context, v bool, expected int, _ string, _ time.Time) (int, error) {
	if expected != r.pVersion {
		return 0, scanpolicy.ErrVersionConflict
	}
	r.required, r.pVersion = &v, r.pVersion+1
	return r.pVersion, nil
}

func TestPlatformSensorProofSetting(t *testing.T) {
	ctx := context.Background()
	repo := &memProofRepo{memPolicyRepo: memPolicyRepo{override: map[shared.ID]*scangov.PlatformPolicy{}}}
	audit := &adminAuditLog{}
	svc := scanpolicy.NewService(repo, audit, nil, nil, nil, logger.NewNop())
	actor, _ := admin.NewAdminUser("root@platform.test", "Root", admin.AdminRoleSuperAdmin, nil)

	// Nothing stored: off (the scope entry is the authorization).
	if v, ver, err := svc.ProofSetting(ctx); err != nil || v || ver != 0 {
		t.Fatalf("default: %v %d %v", v, ver, err)
	}
	if svc.PlatformProofRequired(ctx) {
		t.Fatal("default must be off")
	}
	if _, err := svc.UpdateProof(ctx, true, 0, scanpolicy.Change{Actor: actor}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("no reason: %v", err)
	}
	if _, err := svc.UpdateProof(ctx, true, 0, scanpolicy.Change{Reason: "x"}); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("no administrator: %v", err)
	}
	v, err := svc.UpdateProof(ctx, true, 0, scanpolicy.Change{Actor: actor, Reason: "public cloud"})
	if err != nil || v != 1 {
		t.Fatalf("turn on: %d %v", v, err)
	}
	if !svc.PlatformProofRequired(ctx) {
		t.Fatal("on after the change")
	}
	if _, err := svc.UpdateProof(ctx, false, 0, scanpolicy.Change{Actor: actor, Reason: "stale"}); !errors.Is(err, scanpolicy.ErrVersionConflict) {
		t.Fatalf("stale version: %v", err)
	}
	if len(audit.entries) != 1 || audit.entries[0].Action != scanpolicy.ActionProofChanged || audit.entries[0].Severity != admin.SeverityCritical {
		t.Fatalf("audit: %+v", audit.entries)
	}

	// An unreadable setting answers "required" (fail closed); a fresh
	// service has no cached value.
	repo.pFail = true
	fresh := scanpolicy.NewService(repo, audit, nil, nil, nil, logger.NewNop())
	if !fresh.PlatformProofRequired(ctx) {
		t.Fatal("an unreadable setting must require proof")
	}

	// A store without the proof methods is a wiring error: fail closed.
	plain := scanpolicy.NewService(&memPolicyRepo{override: map[shared.ID]*scangov.PlatformPolicy{}}, nil, nil, nil, nil, logger.NewNop())
	if !plain.PlatformProofRequired(ctx) {
		t.Fatal("no proof store must require proof")
	}
}
