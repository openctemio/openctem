package aitriage

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

// A provider timeout is transient (retried), never reported as a used-up
// provider quota: the timeout texts contain "exceeded" too.
func TestCategorizeError_TimeoutIsNotQuota(t *testing.T) {
	for name, err := range map[string]error{
		"deadline":       fmt.Errorf("request failed after retries: %w", context.DeadlineExceeded),
		"client timeout": errors.New(`Post "https://api.example.test/v1": context deadline exceeded (Client.Timeout exceeded while awaiting headers)`),
	} {
		got := categorizeError(err)
		if got != FailTimeout {
			t.Errorf("%s: %q, want %q", name, got, FailTimeout)
		}
		if !transientFailures[got] {
			t.Errorf("%s: %q is not retried", name, got)
		}
	}
	if got := categorizeError(errors.New("insufficient_quota: you exceeded your current quota")); got != FailQuota {
		t.Errorf("quota: %q, want %q", got, FailQuota)
	}
}
