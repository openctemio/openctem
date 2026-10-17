package routes

// GET /api/v1/admin/system over the real route registration (RFC-114): every
// console role reads it (the read-only role included, no step-up), an
// organization user's token and an anonymous caller cannot, and the body holds
// no path, secret or tenant content.

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/adminconsole"
	"github.com/openctemio/openctem/api/internal/app/systemstatus"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
)

func newSystemHarness(t *testing.T, secretDir string) *chainHarness {
	t.Helper()
	return newChainHarness(t, func(hs *Handlers, db *postgres.DB, _ *adminconsole.Service) {
		c := systemstatus.New(systemstatus.Config{StoragePaths: []systemstatus.NamedPath{{Name: "data", Value: secretDir}}},
			systemstatus.Deps{
				PingDB:       db.DB.PingContext,
				DatabaseSize: func(ctx context.Context) (int64, error) { return 4096, nil },
				RunningVer:   func() (string, string) { return "v0.0.0-test", "dev" },
			})
		hs.AdminSystem = handler.NewAdminSystemHandler(c.Collect)
	})
}

func TestAdminSystemRoute(t *testing.T) {
	secretDir := t.TempDir()
	h := newSystemHarness(t, secretDir)
	org := h.organization(0)

	for name, hdr := range map[string]string{"anonymous": "", "tenant owner": "Bearer " + h.tenantToken(org, "owner")} {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, h.srv.URL+"/api/v1/admin/system", nil)
		if hdr != "" {
			req.Header.Set("Authorization", hdr)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusForbidden {
			t.Fatalf("%s: %d, want 401/403", name, resp.StatusCode)
		}
	}

	for _, role := range []admin.AdminRole{admin.AdminRoleReadonly, admin.AdminRoleOpsAdmin, admin.AdminRoleSuperAdmin} {
		// One harness per role: the console's verify step is rate limited.
		c := newSystemHarness(t, secretDir).newAdmin(role)
		c.verify()
		code, body := c.do(http.MethodGet, "/api/v1/admin/system", nil, false)
		if code != http.StatusOK {
			t.Fatalf("%s: %d %s", role, code, body)
		}
		var got systemstatus.Snapshot
		if err := json.Unmarshal([]byte(body), &got); err != nil {
			t.Fatal(err)
		}
		if len(got.Storage.Volumes) != 1 || got.Storage.Volumes[0].Name != "data" || !got.Storage.DatabaseOK || got.Version.Running != "v0.0.0-test" {
			t.Fatalf("%s: snapshot = %+v", role, got)
		}
		if strings.Contains(body, secretDir) {
			t.Fatalf("%s: a file path leaked: %s", role, body)
		}
		// Read-only: no write verb is routed.
		if code, _ := c.do(http.MethodPost, "/api/v1/admin/system", nil, false); code == http.StatusOK || code == http.StatusCreated {
			t.Fatalf("%s: POST accepted: %d", role, code)
		}
	}
}
