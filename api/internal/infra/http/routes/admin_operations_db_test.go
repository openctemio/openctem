package routes

// GET /api/v1/admin/operations over the real route registration: every
// console role reads it (database reachable, schema read, controllers
// listed), an organization user's token cannot.

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/adminconsole"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func TestAdminOperationsRoute(t *testing.T) {
	h := newChainHarness(t, func(hs *Handlers, db *postgres.DB, _ *adminconsole.Service) {
		hs.AdminOperations = handler.NewAdminOperationsHandler(db.DB,
			func(ctx context.Context) (postgres.OpsSnapshot, error) { return postgres.ReadOpsSnapshot(ctx, db.DB) },
			nil, nil, 0, "", logger.NewNop())
	})
	org := h.organization(0)
	tok := h.tenantToken(org, "owner")
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, h.srv.URL+"/api/v1/admin/operations", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("tenant token: %d, want 401", resp.StatusCode)
	}

	c := h.newAdmin(admin.AdminRoleReadonly)
	c.verify()
	code, body := c.do(http.MethodGet, "/api/v1/admin/operations", nil, false)
	if code != http.StatusOK {
		t.Fatalf("operations: %d %s", code, body)
	}
	var got handler.AdminOperationsResponse
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatal(err)
	}
	if !got.Database.OK || !got.Schema.Known || got.Schema.Applied == 0 || got.Redis.Configured {
		t.Fatalf("operations = %+v", got)
	}
}
