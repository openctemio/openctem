package handler

import (
	"net/http"

	authapp "github.com/openctemio/openctem/api/internal/app/auth"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
)

// writeStepUpError answers a service's step-up refusal (from
// middleware.RecentAuthGate) the way RequireRecentAuth does, so the web client
// shows its re-authentication dialog and retries. It reports whether it wrote
// one.
func writeStepUpError(w http.ResponseWriter, err error) bool {
	return middleware.WriteStepUpError(w, err, authapp.StepUpWindow)
}
