package handler

import (
	"errors"
	"net/http"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// writeStepUpError answers a service's step-up refusal (*shared.StepUpError)
// the way RequireRecentAuth does, so the web client shows its
// re-authentication dialog and retries. It reports whether it wrote one.
func writeStepUpError(w http.ResponseWriter, err error) bool {
	var stepUp *shared.StepUpError
	if !errors.As(err, &stepUp) {
		return false
	}
	middleware.WriteStepUpError(w, stepUp)
	return true
}
