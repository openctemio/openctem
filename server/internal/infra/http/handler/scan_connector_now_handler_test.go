package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	scansvc "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/internal/app/tenablesc"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Requests that never reach the service: a bad body or asset list is 400.
func TestConnectorScanNow_RequestValidation(t *testing.T) {
	h := &ScanHandler{logger: logger.NewNop()}
	many := make([]string, 51)
	for i := range many {
		many[i] = `"` + shared.NewID().String() + `"`
	}
	for name, tc := range map[string]struct {
		id, body string
	}{
		"bad integration id": {"nope", `{"asset_ids":["` + shared.NewID().String() + `"]}`},
		"bad body":           {shared.NewID().String(), `{`},
		"no assets":          {shared.NewID().String(), `{"asset_ids":[]}`},
		"too many assets":    {shared.NewID().String(), `{"asset_ids":[` + strings.Join(many, ",") + `]}`},
		"asset not a uuid":   {shared.NewID().String(), `{"asset_ids":["x"]}`},
	} {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/v1/integrations/"+tc.id+"/scans/run", strings.NewReader(tc.body))
			req.SetPathValue("id", tc.id)
			ctx := context.WithValue(req.Context(), middleware.TenantIDKey, shared.NewID().String())
			ctx = context.WithValue(ctx, middleware.UserIDKey, shared.NewID().String())
			rec := httptest.NewRecorder()
			h.ConnectorScanNow(rec, req.WithContext(ctx))
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status %d, want 400: %s", rec.Code, rec.Body.String())
			}
		})
	}
}

// The service's refusals map to 404 (integration or asset), 409 (the
// connector cannot run it now) and 400 (configuration).
func TestConnectorScanNow_ErrorMapping(t *testing.T) {
	h := &ScanHandler{logger: logger.NewNop()}
	for name, tc := range map[string]struct {
		err  error
		want int
		code string
	}{
		"asset out of scope":     {scansvc.ErrConnectorAssetsNotFound, http.StatusNotFound, ""},
		"integration not found":  {fmt.Errorf("load: %w", shared.ErrNotFound), http.StatusNotFound, ""},
		"sensor unavailable":     {tenablesc.ErrSensorUnavailable, http.StatusConflict, "CONNECTOR_SENSOR_UNAVAILABLE"},
		"integration disabled":   {tenablesc.ErrDisabled, http.StatusConflict, "INTEGRATION_DISABLED"},
		"connector not wired":    {scansvc.ErrConnectorScansUnavailable, http.StatusConflict, "TOOL_NOT_SCANNER"},
		"no coverage config":     {tenablesc.ErrOnDemandNeedsCoverageConfig, http.StatusBadRequest, ""},
		"scan name already used": {scansvc.ErrOnDemandScanNameTaken, http.StatusConflict, "ON_DEMAND_SCAN_NAME_TAKEN"},
	} {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.connectorScanNowError(rec, tc.err)
			if rec.Code != tc.want {
				t.Fatalf("status %d, want %d: %s", rec.Code, tc.want, rec.Body.String())
			}
			if tc.code != "" {
				var body struct {
					Code string `json:"code"`
				}
				_ = json.Unmarshal(rec.Body.Bytes(), &body)
				if body.Code != tc.code {
					t.Fatalf("code %q, want %q", body.Code, tc.code)
				}
			}
		})
	}
}
