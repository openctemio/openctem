package handler

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	cirunapp "github.com/openctemio/openctem/api/internal/app/cirun"
)

// A refused old runner is told exactly which line to change, in each form a
// pipeline pins openctemio/ci.
func TestRunnerOutdatedMessageNamesThePin(t *testing.T) {
	err := fmt.Errorf("exchange: %w", &cirunapp.RunnerOutdatedError{Version: "v0.2.0", Min: "v0.3.0", Pin: "v0.3.0"})
	if !errors.Is(err, cirunapp.ErrRunnerOutdated) {
		t.Fatal("RunnerOutdatedError is not ErrRunnerOutdated")
	}
	msg := runnerOutdatedMessage(err)
	for _, want := range []string{
		"openctem-ci v0.2.0",
		"older than v0.3.0",
		"uses: openctemio/ci/.github/workflows/scan.yml@v0.3.0",
		"openctemio/ci@v0.3.0",
		"https://raw.githubusercontent.com/openctemio/ci/v0.3.0/gitlab/templates/all.yml",
		"ghcr.io/openctemio/ci:v0.3.0",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("message lacks %q: %s", want, msg)
		}
	}
	if strings.Contains(msg, "sensor") {
		t.Errorf("the CI runner is not a sensor: %s", msg)
	}
	if got := runnerOutdatedMessage(cirunapp.ErrRunnerOutdated); !strings.Contains(got, "pin the current openctemio/ci release") {
		t.Errorf("bare error message = %s", got)
	}
}
