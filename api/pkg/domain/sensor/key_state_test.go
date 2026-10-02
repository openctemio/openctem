package sensor

import (
	"testing"
	"time"
)

func tp(t time.Time) *time.Time { return &t }

// After a self-renewal under rotation overlap the working key lives in
// sensor_api_keys, while the inline columns keep the bootstrap key, which
// renewal retires with a short grace. Reading key state from the inline
// columns made every renewed sensor report "API key expired" (critical,
// Degraded) while it was heartbeating with a key valid for months.
func TestKeyState_PrefersActiveRotatingKey(t *testing.T) {
	s := daemon(ago(20 * time.Second))
	s.InlineKeyPrefix = "rda_8704094e"
	s.InlineKeyExpiresAt = tp(testNow.Add(-7 * time.Hour)) // retired bootstrap key
	s.ActiveKey = &ActiveKey{Prefix: "rda_62a48cee", ExpiresAt: tp(testNow.Add(90 * 24 * time.Hour)), LastUsedAt: ago(20 * time.Second)}

	ks := s.KeyState()
	if ks.Prefix != "rda_62a48cee" || ks.ExpiresAt == nil || !ks.ExpiresAt.Equal(*s.ActiveKey.ExpiresAt) || !ks.Rotating {
		t.Fatalf("KeyState = %+v, want the active rotating key", ks)
	}

	a := s.AssessHealth(testNow, testPolicy())
	if hasCode(a.Reasons, ReasonKeyExpired) || hasCode(a.Reasons, ReasonKeyExpiring) || a.State != StateOnline {
		t.Fatalf("renewed sensor: state=%q reasons=%v, want online with no key warning", a.State, codes(a.Reasons))
	}
}

func TestKeyState_FallsBackToInlineKey(t *testing.T) {
	s := daemon(ago(5 * time.Second))
	s.InlineKeyPrefix = "rda_inline01"
	ks := s.KeyState()
	if ks.Prefix != "rda_inline01" || ks.ExpiresAt != nil || ks.Rotating {
		t.Fatalf("KeyState = %+v, want the never-expiring inline key", ks)
	}
}

func TestKeyState_ExpiredActiveKeyIsReported(t *testing.T) {
	s := daemon(ago(2 * time.Hour))
	s.InlineKeyExpiresAt = tp(testNow.Add(-60 * 24 * time.Hour))
	s.ActiveKey = &ActiveKey{Prefix: "rda_old", ExpiresAt: tp(testNow.Add(-time.Hour))}
	a := s.AssessHealth(testNow, testPolicy())
	if !hasCode(a.Reasons, ReasonKeyExpired) {
		t.Fatalf("a sensor whose only key has expired must report key_expired; reasons=%v", codes(a.Reasons))
	}
}

func TestKeyState_ExpiringActiveKeyWarns(t *testing.T) {
	s := daemon(ago(5 * time.Second))
	s.ActiveKey = &ActiveKey{Prefix: "rda_soon", ExpiresAt: tp(testNow.Add(2 * 24 * time.Hour))}
	if a := s.AssessHealth(testNow, testPolicy()); !hasCode(a.Reasons, ReasonKeyExpiring) {
		t.Fatalf("reasons=%v, want key_expiring", codes(a.Reasons))
	}
}
