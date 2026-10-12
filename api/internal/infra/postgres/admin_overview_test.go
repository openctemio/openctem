package postgres

import (
	"testing"

	"github.com/openctemio/openctem/api/internal/app/adminconsole"
)

// The overview counts break-glass sign-ins by the action the console writes.
func TestAdminOverviewBreakGlassActionMatchesConsole(t *testing.T) {
	if adminOverviewBreakGlassAction != adminconsole.ActionBreakGlassSignIn {
		t.Fatalf("overview counts %q, the console writes %q", adminOverviewBreakGlassAction, adminconsole.ActionBreakGlassSignIn)
	}
}
