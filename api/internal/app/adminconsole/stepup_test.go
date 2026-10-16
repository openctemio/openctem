package adminconsole

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
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

// A protected action (route-level step-up) needs a fresh code unless the same
// session confirmed one within the step-up window; another session, a pending
// session or an expired window never passes without a code.
func TestConfirmProtectedWindow(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	secret, token := h.enroll(t)
	_, sess, err := h.svc.AuthenticateSession(ctx, token)
	if err != nil {
		t.Fatalf("session: %v", err)
	}

	if err := h.svc.ConfirmProtected(ctx, h.admin, sess, "", "admin.provision", client); !errors.Is(err, admin.ErrStepUpRequired) {
		t.Fatalf("no code, no window: %v, want ErrStepUpRequired", err)
	}
	if err := h.svc.ConfirmProtected(ctx, h.admin, sess, "000000", "admin.provision", client); !errors.Is(err, admin.ErrInvalidMFACode) {
		t.Fatalf("wrong code: %v, want ErrInvalidMFACode", err)
	}

	h.clock = h.clock.Add(totp.Period)
	fresh, _ := totp.Code(secret, h.clock)
	if err := h.svc.ConfirmProtected(ctx, h.admin, sess, fresh, "admin.provision", client); err != nil {
		t.Fatalf("fresh code: %v", err)
	}
	_, sess, _ = h.svc.AuthenticateSession(ctx, token)
	if sess.StepUpAt == nil {
		t.Fatal("a confirmed step-up must open the session's window")
	}

	// Inside the window: no code needed.
	h.clock = h.clock.Add(admin.StepUpWindow - time.Second)
	if err := h.svc.ConfirmProtected(ctx, h.admin, sess, "", "admin.role_change", client); err != nil {
		t.Fatalf("inside the window: %v", err)
	}
	// Another administrator never rides this session's window.
	other := admin.Reconstitute(shared.NewID(), "x@acme.io", "X", admin.AdminRoleSuperAdmin, true,
		nil, nil, "", 0, nil, nil, "", h.clock, nil, h.clock)
	if err := h.svc.ConfirmProtected(ctx, other, sess, "", "admin.role_change", client); !errors.Is(err, admin.ErrStepUpRequired) {
		t.Fatalf("another admin on this session: %v, want ErrStepUpRequired", err)
	}
	// A pending session never passes.
	pending := *sess
	pending.MFAVerified = false
	if err := h.svc.ConfirmProtected(ctx, h.admin, &pending, "", "admin.role_change", client); !errors.Is(err, admin.ErrStepUpRequired) {
		t.Fatalf("pending session: %v, want ErrStepUpRequired", err)
	}
	// After the window: a code again.
	h.clock = h.clock.Add(2 * time.Second)
	if err := h.svc.ConfirmProtected(ctx, h.admin, sess, "", "admin.role_change", client); !errors.Is(err, admin.ErrStepUpRequired) {
		t.Fatalf("after the window: %v, want ErrStepUpRequired", err)
	}
}
