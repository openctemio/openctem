package logger

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestSanitizeValue_StripsForgingCharacters(t *testing.T) {
	// A forged line break is the whole point of the rule: the text handler emits
	// plain lines, so a raw CR/LF in an attacker-controlled value would let the
	// caller inject a second, fake log entry.
	got := SanitizeValue("/api/v1/x\nlevel=ERROR msg=\"forged entry\"")
	if strings.ContainsAny(got, "\r\n") {
		t.Fatalf("CR/LF survived sanitization: %q", got)
	}
	if !strings.HasPrefix(got, "/api/v1/x") {
		t.Errorf("legitimate prefix was mangled: %q", got)
	}
}

func TestSanitizeValue_StripsControlCharsAndBounds(t *testing.T) {
	if got := SanitizeValue("a\x00b\x1fc"); got != "abc" {
		t.Errorf("control chars not stripped: %q", got)
	}
	long := strings.Repeat("x", 500)
	if got := SanitizeValue(long); len(got) != 128 {
		t.Errorf("length bound not applied: got %d, want 128", len(got))
	}
}

func TestSanitizeValue_LeavesCleanValueIntact(t *testing.T) {
	const in = "/api/v1/findings"
	if got := SanitizeValue(in); got != in {
		t.Errorf("clean value altered: %q -> %q", in, got)
	}
}

func TestSanitizeError_StripsForgingCharacters(t *testing.T) {
	err := errors.New("parse report: unexpected token\nlevel=ERROR msg=\"forged\"\r")
	got := SanitizeError(err)
	if strings.ContainsAny(got, "\r\n") {
		t.Fatalf("CR/LF survived sanitization: %q", got)
	}
	if !strings.HasPrefix(got, "parse report: unexpected token") {
		t.Errorf("error text was mangled: %q", got)
	}
}

func TestSanitizeError_WrappedChainAndBounds(t *testing.T) {
	inner := errors.New("name \"x\ny\" rejected")
	got := SanitizeError(fmt.Errorf("create asset: %w", inner))
	if got != "create asset: name \"x y\" rejected" {
		t.Errorf("unexpected sanitized chain: %q", got)
	}
	if got := SanitizeError(errors.New(strings.Repeat("e", 4000))); len(got) != 1024 {
		t.Errorf("length bound not applied: got %d, want 1024", len(got))
	}
}

func TestSanitizeError_Nil(t *testing.T) {
	if got := SanitizeError(nil); got != "" {
		t.Errorf("nil error should render empty, got %q", got)
	}
}
