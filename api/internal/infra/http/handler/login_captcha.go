package handler

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// A CAPTCHA after repeated failed sign-ins (docs/rfcs/RFC-104): when the
// deployment has Turnstile keys, a client address with LoginCaptchaAfter
// failed password sign-ins in LoginFailureWindow must pass the CAPTCHA before
// the next attempt is looked at. Counted per client address, never per
// account, so the answer says nothing about which accounts exist.

// LoginCaptchaAfter is the number of failures after which the CAPTCHA is
// required.
const LoginCaptchaAfter = 3

// LoginFailureWindow is how long failures are remembered.
const LoginFailureWindow = 15 * time.Minute

// CodeCaptchaRequired asks the client to show the CAPTCHA and retry.
const CodeCaptchaRequired apierror.Code = "CAPTCHA_REQUIRED"

// LoginFailureCounter counts failed sign-ins per client address.
type LoginFailureCounter interface {
	Failures(ctx context.Context, key string) (int, error)
	Record(ctx context.Context, key string) error
	Reset(ctx context.Context, key string) error
}

// SetLoginFailureCounter wires the failed-sign-in counter (Redis across
// replicas in production).
func (h *LocalAuthHandler) SetLoginFailureCounter(c LoginFailureCounter) { h.loginFailures = c }

// loginNeedsCaptcha reports whether this attempt must pass the CAPTCHA first.
// A counter error does not lock anyone out (the per-address rate limit and
// the account lockout still apply).
func (h *LocalAuthHandler) loginNeedsCaptcha(r *http.Request, ip string) bool {
	return captchaNeeded(r.Context(), h.captcha, h.loginFailures, ip, h.logger)
}

// captchaNeeded is the shared rule behind the tenant and console sign-ins.
func captchaNeeded(ctx context.Context, c Captcha, f LoginFailureCounter, key string, log *logger.Logger) bool {
	if c == nil || f == nil || key == "" {
		return false
	}
	n, err := f.Failures(ctx, key)
	if err != nil {
		log.Warn("failed sign-in counter unreadable; no CAPTCHA asked", "error", err)
		return false
	}
	return n >= LoginCaptchaAfter
}

// memoryLoginFailures is the in-process counter (one replica, or no Redis).
type memoryLoginFailures struct {
	mu   sync.Mutex
	hits map[string][]time.Time
	now  func() time.Time
}

// NewMemoryLoginFailures creates an in-process failed sign-in counter.
func NewMemoryLoginFailures() LoginFailureCounter {
	return &memoryLoginFailures{hits: map[string][]time.Time{}, now: time.Now}
}

func (m *memoryLoginFailures) prune(key string) []time.Time {
	cut := m.now().Add(-LoginFailureWindow)
	kept := m.hits[key][:0]
	for _, t := range m.hits[key] {
		if t.After(cut) {
			kept = append(kept, t)
		}
	}
	if len(kept) == 0 {
		delete(m.hits, key)
		return nil
	}
	m.hits[key] = kept
	return kept
}

func (m *memoryLoginFailures) Failures(_ context.Context, key string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.prune(key)), nil
}

func (m *memoryLoginFailures) Record(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.hits) > 100000 {
		m.hits = map[string][]time.Time{} // bound memory under a flood
	}
	m.hits[key] = append(m.prune(key), m.now())
	return nil
}

func (m *memoryLoginFailures) Reset(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.hits, key)
	return nil
}
