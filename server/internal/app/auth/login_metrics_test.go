package auth

import (
	"errors"
	"fmt"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/openctemio/openctem/api/internal/metrics"
)

// A refused sign-in is counted under its reason only (never the email or
// IP); a successful one is not counted.
func TestRecordLoginFailureCountsByReason(t *testing.T) {
	cases := []struct {
		err    error
		reason string
	}{
		{ErrInvalidCredentials, "invalid_credentials"},
		{fmt.Errorf("wrapped: %w", ErrAccountLocked), "locked"},
		{ErrAccountSuspended, "suspended"},
		{errors.New("db down"), "other"},
	}
	for _, c := range cases {
		before := testutil.ToFloat64(metrics.LoginFailuresTotal.WithLabelValues(c.reason))
		recordLoginFailure(c.err)
		if got := testutil.ToFloat64(metrics.LoginFailuresTotal.WithLabelValues(c.reason)) - before; got != 1 {
			t.Errorf("%v: %s counted %v times, want 1", c.err, c.reason, got)
		}
	}

	sum := func() (n float64) {
		for _, c := range cases {
			n += testutil.ToFloat64(metrics.LoginFailuresTotal.WithLabelValues(c.reason))
		}
		return n
	}
	before := sum()
	recordLoginFailure(nil)
	if sum() != before {
		t.Errorf("a successful sign-in was counted as a failure")
	}
}
