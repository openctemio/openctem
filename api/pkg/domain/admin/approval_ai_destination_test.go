package admin

import (
	"strings"
	"testing"
)

func TestPlatformAIDestinationTarget(t *testing.T) {
	target := PlatformAIDestinationTarget("openai_compatible", "https://llm.example.com/v1", true, "0123456789abcdef")
	if !ApprovalPlatformAIDestination.IsValid() || !ApprovalPlatformAIDestination.ValidTarget(target) {
		t.Fatalf("own target must validate: %s", target)
	}
	for _, bad := range []string{"", "{}", `{"provider":"claude"}`, `{"provider":"claude","base_url":"","allow_private":false,"key_fp":"x","extra":1}`,
		`{"provider":"claude", "base_url":"", "allow_private":false, "key_fp":"x"}`, strings.Repeat("a", 400)} {
		if ApprovalPlatformAIDestination.ValidTarget(bad) {
			t.Fatalf("%q must not validate", bad)
		}
	}
	long := PlatformAIDestinationTarget("openai_compatible", "https://"+strings.Repeat("a", 400)+".example.com", false, "k")
	if !strings.HasPrefix(long, "sha256:") || !ApprovalPlatformAIDestination.ValidTarget(long) {
		t.Fatalf("long target must be the hash form: %s", long)
	}
	if got := PlatformAIDestinationLabel(target); got != "openai_compatible at llm.example.com, private network allowed, key ending cdef" {
		t.Fatalf("label = %q", got)
	}
	if PlatformAIDestinationLabel(long) != "" {
		t.Fatal("hash form has no label")
	}
}

func TestPlatformEmailRelayTarget(t *testing.T) {
	target := PlatformEmailRelayTarget("SMTP.Example.com", 587, true)
	if target != `{"host":"smtp.example.com","port":587,"security":"starttls"}` {
		t.Fatalf("target = %s", target)
	}
	if !ApprovalPlatformEmailRelay.IsValid() || !ApprovalPlatformEmailRelay.ValidTarget(target) {
		t.Fatal("own target must validate")
	}
	for _, bad := range []string{"", "{}", `{"host":"x","port":0,"security":"none"}`, `{"host":"x","port":25,"security":"tls"}`,
		`{"host":"X","port":25,"security":"none"}`, `{"host":"x","port":25,"security":"none","extra":1}`} {
		if ApprovalPlatformEmailRelay.ValidTarget(bad) {
			t.Fatalf("%q must not validate", bad)
		}
	}
	if got := PlatformEmailRelayLabel(target); got != "smtp.example.com port 587 with STARTTLS" {
		t.Fatalf("label = %q", got)
	}
	if got := PlatformEmailRelayLabel(PlatformEmailRelayTarget("m.example.com", 25, false)); got != "m.example.com port 25 without encryption" {
		t.Fatalf("label = %q", got)
	}
}
