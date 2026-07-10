package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// fakeFindingReader records the tenant it was called with so tests can assert
// the tool passed the authenticated tenant (never a caller-supplied one).
type fakeFindingReader struct {
	gotTenant string
}

func (f *fakeFindingReader) ListFindings(_ context.Context, in app.ListFindingsInput) (pagination.Result[*vulnerability.Finding], error) {
	f.gotTenant = in.TenantID
	return pagination.NewResult([]*vulnerability.Finding{}, 0, pagination.Pagination{Page: 1, PerPage: 25}), nil
}
func (f *fakeFindingReader) GetFindingWithScope(_ context.Context, _, _, _ string, _ bool) (*vulnerability.Finding, error) {
	return nil, nil
}
func (f *fakeFindingReader) GetFindingStats(_ context.Context, _ string) (*vulnerability.FindingStats, error) {
	return &vulnerability.FindingStats{}, nil
}
func (f *fakeFindingReader) ListActiveCVEs(_ context.Context, _ app.ListActiveCVEsInput) (pagination.Result[vulnerability.ActiveCVE], error) {
	return pagination.NewResult([]vulnerability.ActiveCVE{}, 0, pagination.Pagination{Page: 1, PerPage: 25}), nil
}

type rpcResp struct {
	JSONRPC string          `json:"jsonrpc"`
	Result  json.RawMessage `json:"result"`
	Error   *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func newTestMCP(fr mcpFindingReader) *MCPHandler {
	return NewMCPHandler(fr, nil, nil, nil, nil, nil, logger.NewNop())
}

// allReadScopes is the set of permissions a fully-scoped MCP key would carry.
var allReadScopes = []string{"findings:read", "assets:read", "compliance:frameworks:read"}

// doRPC POSTs with the given tenant + full read scopes in context (as APIKeyAuth
// would set for a fully-scoped key). Use doRPCScoped to vary the scopes.
func doRPC(t *testing.T, h *MCPHandler, tenant, body string) (int, rpcResp) {
	return doRPCScoped(t, h, tenant, "user-1", allReadScopes, body)
}

// doRPCScoped seeds tenant + acting user + permission scopes exactly as
// APIKeyAuth would, so tests can exercise scope enforcement.
func doRPCScoped(t *testing.T, h *MCPHandler, tenant, user string, scopes []string, body string) (int, rpcResp) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/mcp", bytes.NewBufferString(body))
	ctx := req.Context()
	if tenant != "" {
		ctx = context.WithValue(ctx, middleware.TenantIDKey, tenant)
	}
	if user != "" {
		ctx = context.WithValue(ctx, middleware.UserIDKey, user)
	}
	ctx = context.WithValue(ctx, middleware.PermissionsKey, scopes)
	ctx = context.WithValue(ctx, middleware.IsAdminKey, false)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var resp rpcResp
	if rec.Body.Len() > 0 {
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	}
	return rec.Code, resp
}

func TestMCP_Initialize(t *testing.T) {
	h := newTestMCP(&fakeFindingReader{})
	_, resp := doRPC(t, h, "tenant-a", `{"jsonrpc":"2.0","id":1,"method":"initialize"}`)
	if resp.Error != nil {
		t.Fatalf("initialize errored: %+v", resp.Error)
	}
	var r struct {
		ProtocolVersion string         `json:"protocolVersion"`
		Capabilities    map[string]any `json:"capabilities"`
		ServerInfo      map[string]any `json:"serverInfo"`
	}
	if err := json.Unmarshal(resp.Result, &r); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if r.ProtocolVersion == "" {
		t.Error("missing protocolVersion")
	}
	if _, ok := r.Capabilities["tools"]; !ok {
		t.Error("missing tools capability")
	}
	if r.ServerInfo["name"] == "" {
		t.Error("missing serverInfo.name")
	}
}

func TestMCP_ToolsListSchemasAreValid(t *testing.T) {
	h := newTestMCP(&fakeFindingReader{})
	_, resp := doRPC(t, h, "tenant-a", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	if resp.Error != nil {
		t.Fatalf("tools/list errored: %+v", resp.Error)
	}
	var r struct {
		Tools []struct {
			Name        string          `json:"name"`
			Description string          `json:"description"`
			InputSchema json.RawMessage `json:"inputSchema"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(resp.Result, &r); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(r.Tools) < 9 {
		t.Fatalf("expected >=9 tools, got %d", len(r.Tools))
	}
	for _, tool := range r.Tools {
		if tool.Name == "" || tool.Description == "" {
			t.Errorf("tool missing name/description: %+v", tool)
		}
		var schema map[string]any
		if err := json.Unmarshal(tool.InputSchema, &schema); err != nil {
			t.Errorf("tool %s inputSchema is not valid JSON: %v", tool.Name, err)
		}
		if schema["type"] != "object" {
			t.Errorf("tool %s inputSchema.type must be object, got %v", tool.Name, schema["type"])
		}
	}
}

func TestMCP_UnknownMethod(t *testing.T) {
	h := newTestMCP(&fakeFindingReader{})
	_, resp := doRPC(t, h, "tenant-a", `{"jsonrpc":"2.0","id":1,"method":"does/not/exist"}`)
	if resp.Error == nil || resp.Error.Code != rpcMethodNotFound {
		t.Fatalf("expected method-not-found error, got %+v", resp.Error)
	}
}

func TestMCP_MissingTenantRejected(t *testing.T) {
	h := newTestMCP(&fakeFindingReader{})
	code, _ := doRPC(t, h, "", `{"jsonrpc":"2.0","id":1,"method":"initialize"}`)
	if code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without tenant context, got %d", code)
	}
}

// The critical isolation property: a tool is scoped to the tenant from context
// (the authenticated key), NOT anything a caller could put in the arguments.
func TestMCP_ToolCallScopedToContextTenant(t *testing.T) {
	fr := &fakeFindingReader{}
	h := newTestMCP(fr)

	// The caller even tries to smuggle a different tenant in the arguments.
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_findings","arguments":{"tenant_id":"tenant-EVIL","limit":5}}}`
	_, resp := doRPC(t, h, "tenant-GOOD", body)
	if resp.Error != nil {
		t.Fatalf("tool call errored: %+v", resp.Error)
	}
	if fr.gotTenant != "tenant-GOOD" {
		t.Fatalf("tool must use the context tenant, got %q", fr.gotTenant)
	}
}

// A key WITHOUT the tool's required scope must be denied — scopes are enforced,
// not decorative. This is the least-privilege guarantee.
func TestMCP_ToolRequiresScope(t *testing.T) {
	fr := &fakeFindingReader{}
	h := newTestMCP(fr)

	// Key carries only assets:read, but calls a findings tool.
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_findings","arguments":{}}}`
	_, resp := doRPCScoped(t, h, "tenant-a", "user-1", []string{"assets:read"}, body)

	var r struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
		IsError bool `json:"isError"`
	}
	if err := json.Unmarshal(resp.Result, &r); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !r.IsError {
		t.Fatal("expected a permission-denied error result")
	}
	if fr.gotTenant != "" {
		t.Fatal("the tool must not run when the key lacks its scope")
	}
}

func TestMCP_UnknownToolIsError(t *testing.T) {
	h := newTestMCP(&fakeFindingReader{})
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"drop_tables","arguments":{}}}`
	_, resp := doRPC(t, h, "tenant-a", body)
	if resp.Error == nil {
		t.Fatal("expected an error for an unknown tool")
	}
}
