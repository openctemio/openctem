package handler

import (
	"testing"

	"github.com/openctemio/openctem/api/internal/app/ingestqueue"
	"github.com/openctemio/openctem/api/pkg/domain/ingestreceipt"
)

// An upload receipt with no queue job is answered as applied only when the
// receipt itself finished; an unfinished one has nothing to read.
func TestResultStatusWithoutJob(t *testing.T) {
	cases := []struct {
		status string
		want   ingestqueue.Status
		ok     bool
	}{
		{ingestreceipt.StatusCompleted, ingestqueue.StatusApplied, true},
		{ingestreceipt.StatusFailed, ingestqueue.StatusFailed, true},
		{ingestreceipt.StatusQueued, "", false},
		{ingestreceipt.StatusProcessing, "", false},
		{"", "", false},
	}
	for _, tc := range cases {
		got, ok := resultStatusWithoutJob(&ingestreceipt.Receipt{Status: tc.status})
		if got != tc.want || ok != tc.ok {
			t.Errorf("status %q: got %q,%v want %q,%v", tc.status, got, ok, tc.want, tc.ok)
		}
	}
}
