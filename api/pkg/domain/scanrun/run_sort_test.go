package scanrun

import (
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestParseRunListSort(t *testing.T) {
	for raw, want := range map[string]string{
		"":                "created_at DESC, id DESC",
		"-created_at":     "created_at DESC, id DESC",
		"created_at":      "created_at ASC, id DESC",
		"-started_at":     "started_at DESC NULLS LAST, id DESC",
		"completed_at":    "completed_at ASC NULLS LAST, id DESC",
		"-total_findings": "total_findings DESC, id DESC",
	} {
		s, err := ParseRunListSort(raw)
		if err != nil {
			t.Fatalf("%q: %v", raw, err)
		}
		if s.OrderBy() != want {
			t.Errorf("%q → %q, want %q", raw, s.OrderBy(), want)
		}
	}
}

func TestParseRunListSort_RefusesUnknownAndInjection(t *testing.T) {
	for _, raw := range []string{
		"status", "tenant_id", "created_at,started_at", "--created_at",
		"created_at; DROP TABLE scan_runs", "(SELECT 1)", "created_at DESC",
	} {
		if s, err := ParseRunListSort(raw); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("%q accepted (%q) or wrong error %v", raw, s.OrderBy(), err)
		}
	}
}
