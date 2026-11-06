package main

import (
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/internal/config"
)

func TestConsoleTablesVerdict(t *testing.T) {
	boom := errors.New("boom")
	for _, tc := range []struct {
		name       string
		plane      string
		production bool
		writes     bool
		err        error
		refuse     bool
	}{
		{"tenant production, role writes admin_users", config.PlaneTenant, true, true, nil, true},
		{"tenant production, check failed", config.PlaneTenant, true, false, boom, true},
		{"tenant production, read-only role", config.PlaneTenant, true, false, nil, false},
		{"tenant development, role writes", config.PlaneTenant, false, true, nil, false},
		{"all-in-one production, role writes (warning only)", config.PlaneAll, true, true, nil, false},
		{"admin plane production, role writes", config.PlaneAdmin, true, true, nil, false},
	} {
		if got := consoleTablesVerdict(tc.plane, tc.production, tc.writes, tc.err) != nil; got != tc.refuse {
			t.Errorf("%s: refuse=%v, want %v", tc.name, got, tc.refuse)
		}
	}
}
