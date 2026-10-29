package routes

import (
	"net/http"
	"testing"

	infrahttp "github.com/openctemio/openctem/api/internal/infra/http"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
)

// The router refuses to mount a prefix twice (it panicked at start, so the
// whole API failed to boot). Registering the AI agent routes must not mount
// any prefix twice, with or without the rate limiter.
func TestRegisterAIAnalysisRoutes_MountsEachPrefixOnce(t *testing.T) {
	pass := func(next http.Handler) http.Handler { return next }
	router := infrahttp.NewChiRouter()
	registerAIAnalysisRoutes(router, &handler.AIAnalysisHandler{}, pass, nil, pass, nil)
}
