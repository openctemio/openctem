package ingestjob

import (
	"testing"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

func TestNewJob_HashesPayloadAndDefaults(t *testing.T) {
	j := NewJob(shared.NewID(), nil, "scan-1", "trivy", []byte("hello"))
	if j.Status() != StatusPending {
		t.Fatalf("status = %s, want pending", j.Status())
	}
	if j.MaxAttempts() != DefaultMaxAttempts {
		t.Fatalf("max attempts = %d, want %d", j.MaxAttempts(), DefaultMaxAttempts)
	}
	if len(j.PayloadSHA()) != 32 {
		t.Fatalf("payload sha length = %d, want 32 (sha256)", len(j.PayloadSHA()))
	}
	// Same payload → same hash (idempotency key component).
	j2 := NewJob(j.TenantID(), nil, "scan-1", "trivy", []byte("hello"))
	if string(j.PayloadSHA()) != string(j2.PayloadSHA()) {
		t.Fatal("identical payloads produced different hashes")
	}
}

func TestBackoff_ExponentialCapped(t *testing.T) {
	if got := Backoff(1); got != 30*time.Second {
		t.Fatalf("Backoff(1) = %s, want 30s", got)
	}
	if got := Backoff(2); got != 60*time.Second {
		t.Fatalf("Backoff(2) = %s, want 60s", got)
	}
	if got := Backoff(100); got != 10*time.Minute {
		t.Fatalf("Backoff(100) = %s, want capped 10m", got)
	}
}

func TestStatus_IsTerminal(t *testing.T) {
	for _, s := range []Status{StatusCompleted, StatusDead} {
		if !s.IsTerminal() {
			t.Fatalf("%s should be terminal", s)
		}
	}
	for _, s := range []Status{StatusPending, StatusProcessing, StatusFailed} {
		if s.IsTerminal() {
			t.Fatalf("%s should not be terminal", s)
		}
	}
}
