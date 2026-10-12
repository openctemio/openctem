package adminconsole

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/totp"
)

func TestStepUp(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	// No authenticator enrolled yet: a step-up is impossible, not a wrong code.
	if err := h.svc.StepUp(ctx, h.admin, "123456", "test", client); !errors.Is(err, admin.ErrStepUpUnavailable) {
		t.Fatalf("before enrollment: %v, want ErrStepUpUnavailable", err)
	}

	secret, _ := h.enroll(t)
	signIn, _ := totp.Code(secret, h.clock)

	// The code that opened the session is spent.
	if err := h.svc.StepUp(ctx, h.admin, signIn, "test", client); !errors.Is(err, admin.ErrInvalidMFACode) {
		t.Fatalf("sign-in code reused: %v, want ErrInvalidMFACode", err)
	}
	if err := h.svc.StepUp(ctx, h.admin, "000000", "test", client); !errors.Is(err, admin.ErrInvalidMFACode) {
		t.Fatalf("wrong code: %v, want ErrInvalidMFACode", err)
	}
	if !h.audit.has(ActionStepUpFailed) {
		t.Fatalf("failed step-ups must be audited: %v", h.audit.actions)
	}
	if h.admin.FailedLoginCount() != 2 {
		t.Fatalf("failed step-ups count toward lockout: %d, want 2", h.admin.FailedLoginCount())
	}

	// A fresh code works once.
	h.clock = h.clock.Add(totp.Period)
	fresh, _ := totp.Code(secret, h.clock)
	if err := h.svc.StepUp(ctx, h.admin, fresh, "audit chain rebaseline", client); err != nil {
		t.Fatalf("fresh code: %v", err)
	}
	if !h.audit.has(ActionStepUp) {
		t.Fatalf("a step-up must be audited: %v", h.audit.actions)
	}
	if err := h.svc.StepUp(ctx, h.admin, fresh, "audit chain rebaseline", client); !errors.Is(err, admin.ErrInvalidMFACode) {
		t.Fatalf("replayed step-up code: %v, want ErrInvalidMFACode", err)
	}
	h.clock = h.clock.Add(time.Hour)
	stale, _ := totp.Code(secret, h.clock.Add(-10*time.Minute))
	if err := h.svc.StepUp(ctx, h.admin, stale, "test", client); !errors.Is(err, admin.ErrInvalidMFACode) {
		t.Fatalf("stale code: %v, want ErrInvalidMFACode", err)
	}
}
