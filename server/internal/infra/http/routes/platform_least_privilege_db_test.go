package routes

import (
	"net/http"
	"testing"

	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A caller who can read sensors (viewer, member, scan operator) does not read
// quarantined sensor results (raw asset values and finding titles) or a
// sensor's configuration report, and a non-administrator cannot write the
// credential store that admin-only template sources consume.
func TestPlatformLeastPrivilege_RoutesRefuseNonAdmins(t *testing.T) {
	h := newDSHarness(t)
	auth := Middleware(h.dsAuth)
	registerSensorManagementRoutes(h.router, &handler.SensorHandler{}, nil, &handler.SensorResultHandler{}, auth, nil)
	registerSecretStoreRoutes(h.router, &handler.SecretStoreHandler{}, auth, nil)

	id := shared.NewID().String()
	for _, tc := range []struct{ method, path, perms string }{
		{"GET", "/api/v1/sensors/quarantined-results", permission.SensorsRead.String()},
		{"GET", "/api/v1/sensors/quarantined-results/" + id, permission.SensorsRead.String()},
		{"GET", "/api/v1/sensors/" + id + "/config-report", permission.SensorsRead.String()},
		{"POST", "/api/v1/secret-store/", permission.SecretStoreWrite.String()},
		{"PUT", "/api/v1/secret-store/" + id, permission.SecretStoreWrite.String()},
		{"POST", "/api/v1/secret-store/" + id + "/rotate", permission.SecretStoreWrite.String()},
	} {
		if code, _ := h.doPerms(h.memberA, tc.perms, tc.method, tc.path); code != http.StatusForbidden {
			t.Errorf("%s %s with %s = %d, want 403", tc.method, tc.path, tc.perms, code)
		}
	}
}
