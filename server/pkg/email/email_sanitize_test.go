package email

import "testing"

// SanitizeHeaderValue is the single point of defence against email-
// header CRLF injection (CodeQL rule go/email-content-injection,
// CWE-93). These tests pin the behaviour so a future refactor can't
// silently drop the strip-or-swap logic.

func TestSanitizeHeaderValue_StripsCR(t *testing.T) {
	got := SanitizeHeaderValue("hello\rworld")
	if got == "hello\rworld" || got == "helloworld" {
		t.Errorf("expected CR to be replaced with space, got %q", got)
	}
	// Must not leak the CR.
	for _, r := range got {
		if r == '\r' {
			t.Errorf("CR survived sanitisation: %q", got)
		}
	}
}

func TestSanitizeHeaderValue_StripsLF(t *testing.T) {
	got := SanitizeHeaderValue("hello\nworld")
	for _, r := range got {
		if r == '\n' {
			t.Errorf("LF survived sanitisation: %q", got)
		}
	}
}

func TestSanitizeHeaderValue_StripsCRLFSequence(t *testing.T) {
	// The actual attack vector: "Victim\r\nBcc: attacker@evil.com"
	// must NOT yield a valid header injection.
	got := SanitizeHeaderValue("Victim\r\nBcc: attacker@evil.com")
	for _, r := range got {
		if r == '\r' || r == '\n' {
			t.Fatalf("attack string still contains CR/LF after sanitisation: %q", got)
		}
	}
}

func TestSanitizeHeaderValue_PreservesBenignContent(t *testing.T) {
	// A legitimate subject with weird but safe punctuation must be
	// unchanged. Over-sanitising would mangle real user content.
	cases := []string{
		"Re: [P1] finding about auth bypass",
		"[CRITICAL] 3x findings on prod-api",
		"user@example.com",
		"Weekly summary — 2026-04-22",
		"", // empty safe
	}
	for _, in := range cases {
		if got := SanitizeHeaderValue(in); got != in {
			t.Errorf("benign %q was modified to %q", in, got)
		}
	}
}

func TestSanitizeHeaderValue_ReplacesWithSpace(t *testing.T) {
	// We chose to replace CR/LF with a single space (not delete).
	// Delete would join words across broken lines into gibberish
	// like "linefoo\r\nbar" -> "linefoobar". Replace-with-space
	// keeps the token boundary visible so the mail reader can still
	// show the content sensibly.
	if got := SanitizeHeaderValue("a\rb"); got != "a b" {
		t.Errorf("expected 'a b', got %q", got)
	}
	if got := SanitizeHeaderValue("x\r\ny"); got != "x  y" {
		t.Errorf("expected 'x  y' (2 spaces from \\r and \\n), got %q", got)
	}
}
