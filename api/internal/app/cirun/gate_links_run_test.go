package cirun

import (
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A verdict links to the run on the CI/CD page itself, not to a retired path
// that only a redirect keeps alive.
func TestRunPathOpensTheRunOnTheCICDPage(t *testing.T) {
	id := shared.NewID()
	if got, want := RunPath(id), "/ci-cd?view=runs&run="+id.String(); got != want {
		t.Fatalf("RunPath = %q, want %q", got, want)
	}
}
