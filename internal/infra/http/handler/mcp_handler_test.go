package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/openctemio/api/internal/app"
	auditapp "github.com/openctemio/api/internal/app/audit"
	"github.com/openctemio/api/internal/infra/http/middleware"
	auditdom "github.com/openctemio/api/pkg/domain/audit"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// fakeFindingReader records the tenant it was called with so tests can assert
// the tool passed the authenticated tenant (never a caller-supplied one).
type fakeFindingReader struct {
	gotTenant    string
	gotScopeUser string
	gotIsAdmin   bool
	// scopeErr, when set, is returned by the scoped read paths so tests can
	// simulate a data-scope/pentest-membership denial.
	scopeErr error
}

func (f *fakeFindingReader) ListFindings(_ context.Context, in app.ListFindingsInput) (pagination.Result[*vulnerability.Finding], error) {
	f.gotTenant = in.TenantID
	return pagination.NewResult([]*vulnerability.Finding{}, 0, pagination.Pagination{Page: 1, PerPage: 25}), nil
}
func (f *fakeFindingReader) GetFindingWithScope(_ context.Context, tenantID, _, actingUserID string, _ bool) (*vulnerability.Finding, error) {
	f.gotTenant = tenantID
	f.gotScopeUser = actingUserID
	if f.scopeErr != nil {
		return nil, f.scopeErr
	}
	return nil, nil
}
func (f *fakeFindingReader) GetFindingStatsWithScope(_ context.Context, in app.GetFindingStatsInput) (*vulnerability.FindingStats, error) {
	f.gotTenant = in.TenantID
	f.gotScopeUser = in.ActingUserID
	f.gotIsAdmin = in.IsAdmin
	if f.scopeErr != nil {
		return nil, f.scopeErr
	}
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

// LOW-1: tools/list must advertise only tools the key's scopes allow, so a
// narrow key never even sees a tool it could not call.
func TestMCP_ToolsListFilteredByScope(t *testing.T) {
	h := newTestMCP(&fakeFindingReader{})
	// Key carries only findings:read.
	_, resp := doRPCScoped(t, h, "tenant-a", "user-1", []string{"findings:read"},
		`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	if resp.Error != nil {
		t.Fatalf("tools/list errored: %+v", resp.Error)
	}
	var r struct {
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(resp.Result, &r); err != nil {
		t.Fatalf("decode: %v", err)
	}
	seen := make(map[string]bool, len(r.Tools))
	for _, tool := range r.Tools {
		seen[tool.Name] = true
	}
	// findings:read tools must appear.
	for _, want := range []string{"list_findings", "get_finding", "finding_stats", "explain_finding_priority"} {
		if !seen[want] {
			t.Errorf("expected %q to be listed for a findings:read key", want)
		}
	}
	// assets:read / compliance tools must be filtered out.
	for _, hidden := range []string{"list_assets", "get_exposure_chains", "compliance_posture"} {
		if seen[hidden] {
			t.Errorf("tool %q must NOT be listed for a key lacking its scope", hidden)
		}
	}
}

// MED-2: every tools/call emits exactly one audit event (mcp.tool_called), for
// both success and error outcomes, attributed to the tenant.
func TestMCP_ToolCallEmitsAuditEvent(t *testing.T) {
	fr := &fakeFindingReader{}
	repo := &fakeAuditRepo{}
	h := newTestMCP(fr)
	h.SetAuditService(auditapp.NewAuditService(repo, logger.NewNop()))

	tenant := "018f5a1e-0000-7000-8000-000000000001" // valid UUID so tenant is stamped
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_findings","arguments":{"severity":"high","search":"secret"}}}`
	_, resp := doRPCScoped(t, h, tenant, "user-1", allReadScopes, body)
	if resp.Error != nil {
		t.Fatalf("tool call errored: %+v", resp.Error)
	}
	if len(repo.logs) != 1 {
		t.Fatalf("expected exactly 1 audit event, got %d", len(repo.logs))
	}
	got := repo.logs[0]
	if got.Action() != auditdom.ActionMCPToolCalled {
		t.Errorf("expected action %q, got %q", auditdom.ActionMCPToolCalled, got.Action())
	}
	if got.ResourceID() != "list_findings" {
		t.Errorf("expected resource id = tool name, got %q", got.ResourceID())
	}
	if got.Result() != auditdom.ResultSuccess {
		t.Errorf("expected success result, got %q", got.Result())
	}
	// Sanitized args: the enum filter is kept, the free-text search is redacted.
	args, _ := got.Metadata()["args"].(map[string]any)
	if args == nil {
		t.Fatalf("expected args metadata, got %v", got.Metadata()["args"])
	}
	if args["severity"] != "high" {
		t.Errorf("expected severity kept in audit args, got %v", args["severity"])
	}
	if args["search"] != "<redacted>" {
		t.Errorf("expected free-text search REDACTED in audit args, got %v", args["search"])
	}
}

// MED-1: a data-scope-restricted / non-pentest-member key must be denied
// explain_finding_priority AND finding_stats via the scoped path — never the
// admin-wide read.
func TestMCP_ScopeDeniesExplainAndStats(t *testing.T) {
	denied := errors.New("finding not found")

	t.Run("explain_finding_priority", func(t *testing.T) {
		fr := &fakeFindingReader{scopeErr: denied}
		h := newTestMCP(fr)
		body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"explain_finding_priority","arguments":{"id":"018f5a1e-0000-7000-8000-0000000000aa"}}}`
		_, resp := doRPCScoped(t, h, "018f5a1e-0000-7000-8000-000000000001", "user-1", allReadScopes, body)
		var r struct {
			IsError bool `json:"isError"`
		}
		if err := json.Unmarshal(resp.Result, &r); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if !r.IsError {
			t.Fatal("expected explain to be denied for an out-of-scope finding")
		}
		if fr.gotScopeUser != "user-1" {
			t.Errorf("expected scoped read to use acting user, got %q", fr.gotScopeUser)
		}
	})

	t.Run("finding_stats", func(t *testing.T) {
		fr := &fakeFindingReader{scopeErr: denied}
		h := newTestMCP(fr)
		body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"finding_stats","arguments":{}}}`
		_, resp := doRPCScoped(t, h, "018f5a1e-0000-7000-8000-000000000001", "user-1", allReadScopes, body)
		var r struct {
			IsError bool `json:"isError"`
		}
		if err := json.Unmarshal(resp.Result, &r); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if !r.IsError {
			t.Fatal("expected finding_stats to error when the scoped read is denied")
		}
		if fr.gotIsAdmin {
			t.Error("finding_stats must call the scoped path with IsAdmin=false")
		}
		if fr.gotScopeUser != "user-1" {
			t.Errorf("expected scoped stats to use acting user, got %q", fr.gotScopeUser)
		}
	})
}

// fakeAuditRepo is a minimal in-memory audit repository for asserting that the
// MCP handler emits audit events. Only Create is exercised.
type fakeAuditRepo struct {
	logs []*auditdom.AuditLog
}

func (m *fakeAuditRepo) Create(_ context.Context, log *auditdom.AuditLog) error {
	m.logs = append(m.logs, log)
	return nil
}
func (m *fakeAuditRepo) CreateBatch(_ context.Context, logs []*auditdom.AuditLog) error {
	m.logs = append(m.logs, logs...)
	return nil
}
func (m *fakeAuditRepo) GetByID(_ context.Context, _ shared.ID) (*auditdom.AuditLog, error) {
	return nil, nil
}
func (m *fakeAuditRepo) GetByTenantAndID(_ context.Context, _, _ shared.ID) (*auditdom.AuditLog, error) {
	return nil, nil
}
func (m *fakeAuditRepo) List(_ context.Context, _ auditdom.Filter, _ pagination.Pagination) (pagination.Result[*auditdom.AuditLog], error) {
	return pagination.Result[*auditdom.AuditLog]{}, nil
}
func (m *fakeAuditRepo) Count(_ context.Context, _ auditdom.Filter) (int64, error) { return 0, nil }
func (m *fakeAuditRepo) DeleteOlderThan(_ context.Context, _ time.Time) (int64, error) {
	return 0, nil
}
func (m *fakeAuditRepo) DeleteOlderThanForTenant(_ context.Context, _ shared.ID, _ time.Time) (int64, error) {
	return 0, nil
}
func (m *fakeAuditRepo) GetLatestByResource(_ context.Context, _ shared.ID, _ auditdom.ResourceType, _ string) (*auditdom.AuditLog, error) {
	return nil, nil
}
func (m *fakeAuditRepo) ListByActor(_ context.Context, _ shared.ID, _ pagination.Pagination) (pagination.Result[*auditdom.AuditLog], error) {
	return pagination.Result[*auditdom.AuditLog]{}, nil
}
func (m *fakeAuditRepo) ListByResource(_ context.Context, _ shared.ID, _ auditdom.ResourceType, _ string, _ pagination.Pagination) (pagination.Result[*auditdom.AuditLog], error) {
	return pagination.Result[*auditdom.AuditLog]{}, nil
}
func (m *fakeAuditRepo) CountByAction(_ context.Context, _ *shared.ID, _ auditdom.Action, _ time.Time) (int64, error) {
	return 0, nil
}
func (m *fakeAuditRepo) LatestChainHash(_ context.Context, _ shared.ID) (string, error) {
	return "", nil
}
func (m *fakeAuditRepo) AppendChainEntry(_ context.Context, _ auditdom.ChainEntry) error {
	return nil
}
func (m *fakeAuditRepo) ListChainEntries(_ context.Context, _ shared.ID, _ int) ([]auditdom.ChainEntry, error) {
	return nil, nil
}
func (m *fakeAuditRepo) UpdateChainEntryHashes(_ context.Context, _ shared.ID, _, _ string) error {
	return nil
}
