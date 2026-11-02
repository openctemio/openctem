package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type memMCPSettings struct{ s tenant.MCPSettings }

func (m *memMCPSettings) GetMCPSettings(context.Context, string) (*tenant.MCPSettings, error) {
	c := m.s
	return &c, nil
}

func (m *memMCPSettings) UpdateMCPSettings(_ context.Context, _ string, s tenant.MCPSettings, _ auditapp.AuditContext) (*tenant.MCPSettings, error) {
	m.s = s
	return &s, nil
}

// The terminal sign-in switch: a PUT that names it sets it; a PUT from a
// page that does not know it keeps what is stored (it never turns a switched
// off flow back on).
func TestMCPSettingsDeviceFlowSwitch(t *testing.T) {
	store := &memMCPSettings{}
	h := NewMCPSettingsHandler(store, nil, logger.NewNop())
	put := func(body string) {
		t.Helper()
		rec := httptest.NewRecorder()
		h.Update(rec, httptest.NewRequest(http.MethodPut, "/api/v1/mcp-access/settings", strings.NewReader(body)))
		if rec.Code != http.StatusOK {
			t.Fatalf("PUT %s: %d %s", body, rec.Code, rec.Body.String())
		}
	}
	put(`{"enabled":true,"device_flow_allowed":false}`)
	if !store.s.DeviceFlowDisabled {
		t.Fatal("device_flow_allowed=false not stored")
	}
	put(`{"enabled":true,"any_client":true}`)
	if !store.s.DeviceFlowDisabled || !store.s.AnyClient {
		t.Fatalf("a PUT without the field changed it: %+v", store.s)
	}
	put(`{"enabled":true,"device_flow_allowed":true}`)
	if store.s.DeviceFlowDisabled {
		t.Fatal("device_flow_allowed=true not stored")
	}
	if !h.response(store.s).DeviceFlowAllowed {
		t.Fatal("response does not report the flow allowed")
	}
}
