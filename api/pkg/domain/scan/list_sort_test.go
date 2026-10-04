package scan

import (
	"errors"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestParseListSort_Whitelist(t *testing.T) {
	cases := []struct {
		raw   string
		field string
		desc  bool
		order string
	}{
		{"", "name", false, "name ASC, id ASC"},
		{"name", "name", false, "name ASC, id ASC"},
		{"-name", "name", true, "name DESC, id ASC"},
		{"-last_run_at", "last_run_at", true, "last_run_at DESC NULLS LAST, id ASC"},
		{"next_run_at", "next_run_at", false, "next_run_at ASC NULLS LAST, id ASC"},
		{"-created_at", "created_at", true, "created_at DESC, id ASC"},
		{" total_runs ", "total_runs", false, "total_runs ASC, id ASC"},
	}
	for _, tc := range cases {
		got, err := ParseListSort(tc.raw)
		if err != nil {
			t.Fatalf("ParseListSort(%q): %v", tc.raw, err)
		}
		if got.Field() != tc.field || got.Desc() != tc.desc || got.OrderBy() != tc.order {
			t.Errorf("ParseListSort(%q) = %s desc=%v %q; want %s desc=%v %q",
				tc.raw, got.Field(), got.Desc(), got.OrderBy(), tc.field, tc.desc, tc.order)
		}
	}
}

// Anything outside the whitelist is refused with a validation error, and no
// byte of the request ever appears in the ORDER BY text.
func TestParseListSort_RefusesUnknownAndInjection(t *testing.T) {
	for _, raw := range []string{
		"status", "success_rate", "id", "--name", "name,created_at",
		"name; DROP TABLE scans", "name DESC", "(SELECT 1)", "tenant_id", "NAME",
	} {
		got, err := ParseListSort(raw)
		if err == nil {
			t.Errorf("ParseListSort(%q) accepted: %q", raw, got.OrderBy())
			continue
		}
		if !errors.Is(err, shared.ErrValidation) {
			t.Errorf("ParseListSort(%q) error %v is not a validation error", raw, err)
		}
		if strings.Contains(err.Error(), "DROP") || strings.Contains(err.Error(), "SELECT") {
			t.Errorf("ParseListSort(%q) echoes the raw value in its error: %v", raw, err)
		}
	}
}

func TestListSort_EveryFieldHasAConstantOrder(t *testing.T) {
	for _, f := range ListSortFields() {
		for _, raw := range []string{f, "-" + f} {
			s, err := ParseListSort(raw)
			if err != nil {
				t.Fatalf("%q: %v", raw, err)
			}
			if !strings.HasPrefix(s.OrderBy(), f+" ") || !strings.HasSuffix(s.OrderBy(), ", id ASC") {
				t.Errorf("%q → %q", raw, s.OrderBy())
			}
		}
	}
}
