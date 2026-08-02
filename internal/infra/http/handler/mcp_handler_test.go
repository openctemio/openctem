package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/api/internal/app"
	auditapp "github.com/openctemio/api/internal/app/audit"
	"github.com/openctemio/api/internal/infra/http/middleware"
	auditdom "github.com/openctemio/api/pkg/domain/audit"
	pentestdom "github.com/openctemio/api/pkg/domain/pentest"
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
	// finding, when set, is returned by GetFindingWithScope so tests can exercise
	// rich-DTO projection (e.g. evidence redaction).
	finding *vulnerability.Finding
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
	return f.finding, nil
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
	return NewMCPHandler(fr, nil, nil, nil, nil, nil, nil, logger.NewNop())
}

// newTestMCPWithPentest wires a fake pentest reader for the report-writing tools
// and prompts.
func newTestMCPWithPentest(fr mcpFindingReader, pr mcpPentestReader) *MCPHandler {
	return NewMCPHandler(fr, nil, nil, nil, nil, nil, pr, logger.NewNop())
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

// --- pentest report-writing tools + prompts ----------------------------------

// fakePentestReader records the tenant/user it was called with and returns
// canned campaign/finding/retest/template data.
type fakePentestReader struct {
	gotTenant  string
	gotUser    string
	gotIsAdmin bool
	accessErr  error // returned by CheckCampaignAccess
	campaign   *pentestdom.Campaign
	stats      *pentestdom.CampaignStats
	findings   []*vulnerability.Finding
	retests    []*pentestdom.Retest
	templates  []*pentestdom.Template
	members    []*pentestdom.CampaignMember
}

func (p *fakePentestReader) CheckCampaignAccess(_ context.Context, tenantID, _, userID string, isAdmin bool) error {
	p.gotTenant = tenantID
	p.gotUser = userID
	p.gotIsAdmin = isAdmin
	return p.accessErr
}
func (p *fakePentestReader) GetCampaign(_ context.Context, tenantID, _ string) (*pentestdom.Campaign, error) {
	p.gotTenant = tenantID
	return p.campaign, nil
}
func (p *fakePentestReader) ListCampaignMembers(_ context.Context, tenantID, _ string) ([]*pentestdom.CampaignMember, error) {
	p.gotTenant = tenantID
	return p.members, nil
}
func (p *fakePentestReader) GetCampaignStats(_ context.Context, tenantID, _ string) (*pentestdom.CampaignStats, error) {
	p.gotTenant = tenantID
	if p.stats == nil {
		return &pentestdom.CampaignStats{}, nil
	}
	return p.stats, nil
}
func (p *fakePentestReader) ListAllPentestFindings(_ context.Context, tenantID, _, viewerUserID, _ string, isAdmin bool, page pagination.Pagination) (pagination.Result[*vulnerability.Finding], error) {
	p.gotTenant = tenantID
	p.gotUser = viewerUserID
	p.gotIsAdmin = isAdmin
	return pagination.NewResult(p.findings, int64(len(p.findings)), page), nil
}
func (p *fakePentestReader) ListCampaignRetests(_ context.Context, tenantID, _ string) ([]*pentestdom.Retest, error) {
	p.gotTenant = tenantID
	return p.retests, nil
}
func (p *fakePentestReader) ListTemplates(_ context.Context, tenantID string, _ pentestdom.TemplateFilter, page pagination.Pagination) (pagination.Result[*pentestdom.Template], error) {
	p.gotTenant = tenantID
	return pagination.NewResult(p.templates, int64(len(p.templates)), page), nil
}

// makePentestFinding builds a source='pentest' finding carrying rich fields plus
// raw evidence/PoC/request-response blobs in source_metadata — so tests can
// assert those raw blobs are NEVER projected into the MCP DTO.
func makePentestFinding(t *testing.T) *vulnerability.Finding {
	t.Helper()
	f, err := vulnerability.NewFinding(shared.NewID(), shared.NewID(),
		vulnerability.FindingSourcePentest, "pentest-manual", vulnerability.SeverityHigh, "SQLi in login")
	if err != nil {
		t.Fatalf("new finding: %v", err)
	}
	f.SetTitle("SQL Injection in login form")
	f.SetSourceMetadata(map[string]any{
		"steps_to_reproduce":   []any{"step one", "step two"},
		"business_impact":      "full DB compromise",
		"technical_impact":     "auth bypass",
		"remediation_guidance": "use parameterized queries",
		"owasp_category":       "A03:2021",
		"mitre_technique_id":   "T1190",
		"cvss_version":         "3.1",
		"reference_urls":       []any{"https://example.com/ref"},
		"affected_assets":      []any{"login.example.com"},
		// Sensitive raw blobs that must NOT leak through MCP:
		"poc_code":          "SUPER_SECRET_POC_PAYLOAD' OR '1'='1",
		"evidence":          []any{map[string]any{"blob": "RAW_EVIDENCE_BLOB_DO_NOT_LEAK"}},
		"request_responses": []any{map[string]any{"request": "RAW_CAPTURE_DO_NOT_LEAK"}},
	})
	return f
}

func newTestCampaign(t *testing.T) *pentestdom.Campaign {
	t.Helper()
	c, err := pentestdom.NewCampaign(shared.NewID(), "__test campaign",
		pentestdom.CampaignType("black_box"), pentestdom.CampaignPriority("high"))
	if err != nil {
		t.Fatalf("new campaign: %v", err)
	}
	return c
}

const testTenantUUID = "018f5a1e-0000-7000-8000-000000000001"

// get_campaign must use the CONTEXT tenant, never a tenant smuggled in args.
func TestMCP_GetCampaign_ScopedToContextTenant(t *testing.T) {
	pr := &fakePentestReader{campaign: newTestCampaign(t)}
	h := newTestMCPWithPentest(&fakeFindingReader{}, pr)

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_campaign","arguments":{"tenant_id":"tenant-EVIL","id":"018f5a1e-0000-7000-8000-0000000000cc"}}}`
	_, resp := doRPCScoped(t, h, "tenant-GOOD", "user-1", []string{"pentest:campaigns:read"}, body)
	if resp.Error != nil {
		t.Fatalf("get_campaign errored: %+v", resp.Error)
	}
	if pr.gotTenant != "tenant-GOOD" {
		t.Fatalf("tool must use the context tenant, got %q", pr.gotTenant)
	}
	if pr.gotIsAdmin {
		t.Error("MCP campaign read must run with IsAdmin=false")
	}
	if pr.gotUser != "user-1" {
		t.Errorf("membership gate must use the acting user, got %q", pr.gotUser)
	}
}

// A non-member key (CheckCampaignAccess denies) gets an error result.
func TestMCP_GetCampaign_NonMemberDenied(t *testing.T) {
	pr := &fakePentestReader{campaign: newTestCampaign(t), accessErr: errors.New("not a campaign member")}
	h := newTestMCPWithPentest(&fakeFindingReader{}, pr)
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_campaign","arguments":{"id":"018f5a1e-0000-7000-8000-0000000000cc"}}}`
	_, resp := doRPCScoped(t, h, testTenantUUID, "user-1", []string{"pentest:campaigns:read"}, body)
	var r struct {
		IsError bool `json:"isError"`
	}
	if err := json.Unmarshal(resp.Result, &r); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !r.IsError {
		t.Fatal("expected a denial error for a non-member key")
	}
}

// list_campaign_findings must pass the context tenant + acting user (membership
// filter), never an args-smuggled tenant, and never IsAdmin.
func TestMCP_ListCampaignFindings_ScopedToContextTenant(t *testing.T) {
	pr := &fakePentestReader{findings: []*vulnerability.Finding{makePentestFinding(t)}}
	h := newTestMCPWithPentest(&fakeFindingReader{}, pr)
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_campaign_findings","arguments":{"tenant_id":"tenant-EVIL","campaign_id":"018f5a1e-0000-7000-8000-0000000000cc"}}}`
	_, resp := doRPCScoped(t, h, "tenant-GOOD", "user-1", []string{"pentest:findings:read"}, body)
	if resp.Error != nil {
		t.Fatalf("list_campaign_findings errored: %+v", resp.Error)
	}
	if pr.gotTenant != "tenant-GOOD" {
		t.Fatalf("tool must use the context tenant, got %q", pr.gotTenant)
	}
	if pr.gotUser != "user-1" {
		t.Errorf("membership subquery must use acting user, got %q", pr.gotUser)
	}
	if pr.gotIsAdmin {
		t.Error("MCP finding list must run with IsAdmin=false")
	}
}

// A user-less key must be denied campaign findings (fail-closed): otherwise the
// membership subquery would be skipped and leak the whole campaign.
func TestMCP_ListCampaignFindings_UserlessKeyDenied(t *testing.T) {
	pr := &fakePentestReader{findings: []*vulnerability.Finding{makePentestFinding(t)}}
	h := newTestMCPWithPentest(&fakeFindingReader{}, pr)
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_campaign_findings","arguments":{"campaign_id":"018f5a1e-0000-7000-8000-0000000000cc"}}}`
	// empty user simulates a key minted without an owning user.
	_, resp := doRPCScoped(t, h, testTenantUUID, "", []string{"pentest:findings:read"}, body)
	var r struct {
		IsError bool `json:"isError"`
	}
	if err := json.Unmarshal(resp.Result, &r); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !r.IsError {
		t.Fatal("expected a user-less key to be denied campaign findings")
	}
	if pr.gotTenant != "" {
		t.Fatal("the finding list must not run for a user-less key")
	}
}

// get_pentest_finding must return rich fields but NEVER raw evidence/PoC/
// request-response blobs — only counts + has_poc.
func TestMCP_GetPentestFinding_RedactsEvidence(t *testing.T) {
	fr := &fakeFindingReader{finding: makePentestFinding(t)}
	pr := &fakePentestReader{}
	h := newTestMCPWithPentest(fr, pr)
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_pentest_finding","arguments":{"id":"018f5a1e-0000-7000-8000-0000000000aa"}}}`
	_, resp := doRPCScoped(t, h, testTenantUUID, "user-1", []string{"pentest:findings:read"}, body)
	if resp.Error != nil {
		t.Fatalf("get_pentest_finding errored: %+v", resp.Error)
	}
	var r struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
		IsError bool `json:"isError"`
	}
	if err := json.Unmarshal(resp.Result, &r); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.IsError || len(r.Content) == 0 {
		t.Fatalf("expected a finding result, got %+v", r)
	}
	text := r.Content[0].Text
	// Raw blobs must never appear.
	for _, secret := range []string{"SUPER_SECRET_POC_PAYLOAD", "RAW_EVIDENCE_BLOB_DO_NOT_LEAK", "RAW_CAPTURE_DO_NOT_LEAK"} {
		if strings.Contains(text, secret) {
			t.Fatalf("raw blob leaked into MCP result: %q found in %s", secret, text)
		}
	}
	// But the redacted metadata must be present.
	var dto mcpPentestFindingDTO
	if err := json.Unmarshal([]byte(text), &dto); err != nil {
		t.Fatalf("decode finding dto: %v", err)
	}
	if dto.HasPoC == nil || !*dto.HasPoC {
		t.Error("expected has_poc=true (poc_code present but redacted)")
	}
	if dto.EvidenceCount == nil || *dto.EvidenceCount != 1 {
		t.Errorf("expected evidence_count=1, got %v", dto.EvidenceCount)
	}
	if dto.RequestResponseCount == nil || *dto.RequestResponseCount != 1 {
		t.Errorf("expected request_response_count=1, got %v", dto.RequestResponseCount)
	}
	if dto.BusinessImpact != "full DB compromise" {
		t.Errorf("expected rich business_impact, got %q", dto.BusinessImpact)
	}
	if fr.gotScopeUser != "user-1" {
		t.Errorf("scoped read must use acting user, got %q", fr.gotScopeUser)
	}
}

// Each new pentest tool must emit an audit event.
func TestMCP_PentestToolAuditLogged(t *testing.T) {
	cases := []struct {
		tool  string
		args  string
		scope string
	}{
		{"get_campaign", `{"id":"018f5a1e-0000-7000-8000-0000000000cc"}`, "pentest:campaigns:read"},
		{"list_campaign_findings", `{"campaign_id":"018f5a1e-0000-7000-8000-0000000000cc"}`, "pentest:findings:read"},
		{"list_retests", `{"campaign_id":"018f5a1e-0000-7000-8000-0000000000cc"}`, "pentest:retests:read"},
		{"list_finding_templates", `{}`, "pentest:templates:read"},
		{"campaign_report_stats", `{"campaign_id":"018f5a1e-0000-7000-8000-0000000000cc"}`, "pentest:campaigns:read"},
	}
	for _, tc := range cases {
		t.Run(tc.tool, func(t *testing.T) {
			pr := &fakePentestReader{campaign: newTestCampaign(t)}
			repo := &fakeAuditRepo{}
			h := newTestMCPWithPentest(&fakeFindingReader{}, pr)
			h.SetAuditService(auditapp.NewAuditService(repo, logger.NewNop()))
			body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + tc.tool + `","arguments":` + tc.args + `}}`
			_, resp := doRPCScoped(t, h, testTenantUUID, "user-1", []string{tc.scope}, body)
			if resp.Error != nil {
				t.Fatalf("%s errored: %+v", tc.tool, resp.Error)
			}
			if len(repo.logs) != 1 {
				t.Fatalf("expected 1 audit event for %s, got %d", tc.tool, len(repo.logs))
			}
			if repo.logs[0].Action() != auditdom.ActionMCPToolCalled {
				t.Errorf("expected mcp.tool_called, got %q", repo.logs[0].Action())
			}
			if repo.logs[0].ResourceID() != tc.tool {
				t.Errorf("expected resource id %q, got %q", tc.tool, repo.logs[0].ResourceID())
			}
		})
	}
}

// initialize must advertise the prompts capability.
func TestMCP_InitializeAdvertisesPrompts(t *testing.T) {
	h := newTestMCPWithPentest(&fakeFindingReader{}, &fakePentestReader{})
	_, resp := doRPC(t, h, "tenant-a", `{"jsonrpc":"2.0","id":1,"method":"initialize"}`)
	if resp.Error != nil {
		t.Fatalf("initialize errored: %+v", resp.Error)
	}
	var r struct {
		Capabilities map[string]any `json:"capabilities"`
	}
	if err := json.Unmarshal(resp.Result, &r); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, ok := r.Capabilities["prompts"]; !ok {
		t.Error("initialize must advertise the prompts capability")
	}
}

// prompts/list returns the report-writing prompts (scope-filtered).
func TestMCP_PromptsList(t *testing.T) {
	h := newTestMCPWithPentest(&fakeFindingReader{}, &fakePentestReader{})
	_, resp := doRPCScoped(t, h, testTenantUUID, "user-1",
		[]string{"pentest:campaigns:read", "pentest:findings:read"},
		`{"jsonrpc":"2.0","id":1,"method":"prompts/list"}`)
	if resp.Error != nil {
		t.Fatalf("prompts/list errored: %+v", resp.Error)
	}
	var r struct {
		Prompts []struct {
			Name      string `json:"name"`
			Arguments []struct {
				Name     string `json:"name"`
				Required bool   `json:"required"`
			} `json:"arguments"`
		} `json:"prompts"`
	}
	if err := json.Unmarshal(resp.Result, &r); err != nil {
		t.Fatalf("decode: %v", err)
	}
	seen := make(map[string]bool, len(r.Prompts))
	for _, p := range r.Prompts {
		seen[p.Name] = true
	}
	for _, want := range []string{"exec_summary", "finding_writeup", "remediation_guidance", "attack_narrative"} {
		if !seen[want] {
			t.Errorf("expected prompt %q to be listed", want)
		}
	}
}

// prompts/list is scope-filtered: a key without pentest scopes sees no prompts.
func TestMCP_PromptsListFilteredByScope(t *testing.T) {
	h := newTestMCPWithPentest(&fakeFindingReader{}, &fakePentestReader{})
	_, resp := doRPCScoped(t, h, testTenantUUID, "user-1", []string{"findings:read"},
		`{"jsonrpc":"2.0","id":1,"method":"prompts/list"}`)
	var r struct {
		Prompts []struct {
			Name string `json:"name"`
		} `json:"prompts"`
	}
	if err := json.Unmarshal(resp.Result, &r); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(r.Prompts) != 0 {
		t.Errorf("expected no prompts for a key lacking pentest scopes, got %d", len(r.Prompts))
	}
}

// prompts/get exec_summary returns role-tagged messages injecting campaign
// context, and audits the read.
func TestMCP_PromptsGet_ExecSummary(t *testing.T) {
	pr := &fakePentestReader{campaign: newTestCampaign(t), stats: &pentestdom.CampaignStats{TotalFindings: 5, CriticalFindings: 1}}
	repo := &fakeAuditRepo{}
	h := newTestMCPWithPentest(&fakeFindingReader{}, pr)
	h.SetAuditService(auditapp.NewAuditService(repo, logger.NewNop()))
	body := `{"jsonrpc":"2.0","id":1,"method":"prompts/get","params":{"name":"exec_summary","arguments":{"campaign_id":"018f5a1e-0000-7000-8000-0000000000cc"}}}`
	_, resp := doRPCScoped(t, h, testTenantUUID, "user-1", []string{"pentest:campaigns:read"}, body)
	if resp.Error != nil {
		t.Fatalf("prompts/get errored: %+v", resp.Error)
	}
	var r struct {
		Messages []struct {
			Role    string `json:"role"`
			Content struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(resp.Result, &r); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(r.Messages) < 2 {
		t.Fatalf("expected an instruction + data message, got %d", len(r.Messages))
	}
	// The data message must carry the injected campaign context.
	joined := r.Messages[0].Content.Text + "\n" + r.Messages[1].Content.Text
	if !strings.Contains(joined, "__test campaign") {
		t.Error("expected injected campaign context in prompt messages")
	}
	if !strings.Contains(joined, "untrusted data") {
		t.Error("expected the prompt-injection guard wording in the data message")
	}
	if pr.gotUser != "user-1" || pr.gotTenant != testTenantUUID {
		t.Errorf("prompt read must be tenant+membership scoped, got tenant=%q user=%q", pr.gotTenant, pr.gotUser)
	}
	if len(repo.logs) != 1 || repo.logs[0].Action() != auditdom.ActionMCPPromptGotten {
		t.Fatalf("expected 1 mcp.prompt_gotten audit event, got %+v", repo.logs)
	}
}

// prompts/get must deny a key lacking the prompt's scope.
func TestMCP_PromptsGet_RequiresScope(t *testing.T) {
	pr := &fakePentestReader{campaign: newTestCampaign(t)}
	h := newTestMCPWithPentest(&fakeFindingReader{}, pr)
	body := `{"jsonrpc":"2.0","id":1,"method":"prompts/get","params":{"name":"exec_summary","arguments":{"campaign_id":"018f5a1e-0000-7000-8000-0000000000cc"}}}`
	_, resp := doRPCScoped(t, h, testTenantUUID, "user-1", []string{"findings:read"}, body)
	if resp.Error == nil {
		t.Fatal("expected a permission error when the key lacks the prompt scope")
	}
	if pr.gotTenant != "" {
		t.Error("the prompt data read must not run when the key lacks its scope")
	}
}
