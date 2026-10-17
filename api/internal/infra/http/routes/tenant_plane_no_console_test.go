package routes

import (
	"net/http"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/config"
	infrahttp "github.com/openctemio/openctem/api/internal/infra/http"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// A process on the tenant plane must hold no console route at all (not a
// route that answers 404 or 401: none registered), whatever handlers it was
// given. The walk finds a registered route by its pattern, so a console route
// added under another gate or prefix helper is caught too.
func TestTenantPlaneRegistersNoConsoleRoute(t *testing.T) {
	adminPaths := func(plane string) []string {
		cfg := &config.Config{}
		cfg.Auth.Provider = config.AuthProviderLocal
		cfg.AdminPlane.Plane = plane
		router := infrahttp.NewChiRouter()
		Register(router, Handlers{
			AdminAuthMiddleware: middleware.NewAdminAuthMiddleware(fixedAdminSessions{}, logger.NewNop()),
			AdminSupport:        handler.NewAdminSupportHandler(nil, logger.NewNop()),
		}, cfg, logger.NewNop(), AuthConfig{Provider: config.AuthProviderLocal}, nil, nil, nil, nil, nil)
		var found []string
		if err := router.Walk(func(method, path string, _ http.Handler) error {
			if strings.Contains(path, "/api/v1/admin") {
				found = append(found, method+" "+path)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return found
	}
	if got := adminPaths(config.PlaneAll); len(got) == 0 {
		t.Fatal("control: plane all registers no console route, so the walk proves nothing")
	}
	if got := adminPaths(config.PlaneTenant); len(got) != 0 {
		t.Fatalf("tenant plane registers console routes: %v", got)
	}
}
