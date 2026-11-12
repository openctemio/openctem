package scopenames

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestSettingsDefaults(t *testing.T) {
	var s Settings
	if !s.RuleOn() || s.MaxDays() != DefaultMaxExceptionDays {
		t.Fatalf("nothing stored must keep the rule on with the default longest exception: %+v", s)
	}
	off := false
	s = Settings{GovernmentRule: &off, MaxExceptionDays: 30}
	if s.RuleOn() || s.MaxDays() != 30 {
		t.Fatalf("stored values: %+v", s)
	}
}

func TestNormalizeNames(t *testing.T) {
	got, err := normalizeNames([]string{" *.Internal.Example.com. ", "internal.example.com", "", "a.example.org"})
	if err != nil || !slices.Equal(got, []string{"a.example.org", "internal.example.com"}) {
		t.Fatalf("normalizeNames = %v, %v", got, err)
	}
	for _, bad := range [][]string{{"localhost"}, {"a b.example.com"}, {"203.0.113.0/24"}, {"user@example.com"}} {
		if _, err := normalizeNames(bad); !errors.Is(err, ErrNames) {
			t.Errorf("%v: %v, want BLOCKED_NAMES_INVALID", bad, err)
		}
	}
	many := make([]string, MaxNames+1)
	for i := range many {
		many[i] = "x.example.com"
	}
	if _, err := normalizeNames(many); !errors.Is(err, ErrNames) {
		t.Fatalf("more than %d names: %v", MaxNames, err)
	}
}

func TestCheckRefAndState(t *testing.T) {
	if _, err := checkRef("  "); !errors.Is(err, ErrReference) {
		t.Fatalf("blank reference: %v", err)
	}
	if _, err := checkRef("line\nbreak"); !errors.Is(err, ErrReference) {
		t.Fatalf("control character: %v", err)
	}
	if _, err := checkRef(strings.Repeat("r", MaxRefRunes+1)); !errors.Is(err, ErrReference) {
		t.Fatalf("too long: %v", err)
	}
	now := time.Now()
	e := Exception{ExpiresAt: now.Add(time.Hour)}
	if e.State(now) != StateActive || e.State(now.Add(time.Hour)) != StateExpired {
		t.Fatal("expiry state")
	}
	e.RevokedAt = &now
	if e.State(now) != StateRevoked {
		t.Fatal("revoked state")
	}
}
