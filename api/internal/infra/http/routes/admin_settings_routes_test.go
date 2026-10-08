package routes

import (
	"testing"

	infrahttp "github.com/openctemio/openctem/api/internal/infra/http"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// The console setting routes register without a duplicate mount: chi panics
// when one prefix is mounted twice, which would stop the server at start-up.
func TestAdminSettingsRoutesRegister(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("registering the admin routes panicked: %v", r)
		}
	}()
	router := infrahttp.NewChiRouter()
	registerAdminRoutes(router, Handlers{
		AdminAuthMiddleware: middleware.NewAdminAuthMiddleware(nil, logger.NewNop()),
		AdminSignup:         handler.NewAdminSignupHandler(nil, nil, logger.NewNop()),
		AccessRequest:       handler.NewAccessRequestHandler(nil, logger.NewNop()),
	}, nil, nil)
}
