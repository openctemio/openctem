package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/findinglifecycle"
	"github.com/openctemio/openctem/api/pkg/filterspec"

	assetapp "github.com/openctemio/openctem/api/internal/app/asset"
	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/compliance"
	findingapp "github.com/openctemio/openctem/api/internal/app/finding"
	mcpoauthapp "github.com/openctemio/openctem/api/internal/app/mcpoauth"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	assetdom "github.com/openctemio/openctem/api/pkg/domain/asset"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	pentestdom "github.com/openctemio/openctem/api/pkg/domain/pentest"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/pagination"
	"github.com/openctemio/openctem/api/pkg/report"
)

// fakeFindingReader records the tenant it was called with so tests can assert
// the tool passed the authenticated tenant (never a caller-supplied one).
type fakeFindingReader struct {
	gotTenant    string
	gotScopeUser string
	gotIsAdmin   bool
	// The vulnerabilities list call of list_active_cves.
	gotCVECaller findingapp.FilterCaller
	// The findings stats call of finding_stats.
	gotStatsCaller findingapp.FilterCaller
	gotCVESpec     *filterspec.Spec
	gotCVEOpts     vulnerability.CVEListOptions
	// scopeErr, when set, is returned by the scoped read paths so tests can
	// simulate a data-scope/pentest-membership denial.
	scopeErr error
	// finding, when set, is returned by GetFindingWithScope so tests can exercise
	// rich-DTO projection (e.g. evidence redaction).
	finding *vulnerability.Finding
}

func (f *fakeFindingReader) ListFindings(_ context.Context, in findingapp.ListFindingsInput) (pagination.Result[*vulnerability.Finding], error) {
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
func (f *fakeFindingReader) GetFindingStatsBySpec(_ context.Context, c findingapp.FilterCaller, _ *filterspec.Spec) (*vulnerability.FindingStats, error) {
	f.gotTenant, f.gotScopeUser, f.gotIsAdmin = c.TenantID, c.UserID, c.IsAdmin
	f.gotStatsCaller = c
	if f.scopeErr != nil {
		return nil, f.scopeErr
	}
	return &vulnerability.FindingStats{}, nil
}
func (f *fakeFindingReader) ListFindingTransitions(_ context.Context, tenantID, _, actorID string, perms findingapp.TransitionPermissions) ([]findinglifecycle.Decision, vulnerability.FindingStatus, error) {
	f.gotTenant, f.gotScopeUser = tenantID, actorID
	if f.scopeErr != nil {
		return nil, "", f.scopeErr
	}
	d := vulnerability.EvaluateTransition(vulnerability.TransitionFacts{Status: vulnerability.FindingStatusConfirmed},
		vulnerability.TransitionActor{Kind: vulnerability.TransitionActorPerson, CanStatus: perms.Status}, vulnerability.FindingStatusInProgress)
	return []findinglifecycle.Decision{{TransitionDecision: d}}, vulnerability.FindingStatusConfirmed, nil
}
func (f *fakeFindingReader) ListCVEExposures(_ context.Context, c findingapp.FilterCaller, spec *filterspec.Spec, opts vulnerability.CVEListOptions) (*vulnerability.CVEList, error) {
	f.gotTenant, f.gotScopeUser, f.gotIsAdmin = c.TenantID, c.UserID, c.IsAdmin
	f.gotCVECaller, f.gotCVESpec, f.gotCVEOpts = c, spec, opts
	if f.scopeErr != nil {
		return nil, f.scopeErr
	}
	return &vulnerability.CVEList{Data: []vulnerability.CVEListItem{}}, nil
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

func (m *fakeAuditRepo) GetSystemByID(_ context.Context, id shared.ID) (*auditdom.AuditLog, error) {
	return nil, auditdom.AuditLogNotFoundError(id)
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
func (m *fakeAuditRepo) ListByActor(_ context.Context, _ shared.ID, _ shared.ID, _ pagination.Pagination) (pagination.Result[*auditdom.AuditLog], error) {
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
func (m *fakeAuditRepo) ListChainEntries(_ context.Context, _ shared.ID, _ int64, _ int) ([]auditdom.ChainEntry, error) {
	return nil, nil
}
func (m *fakeAuditRepo) ApplyChainRebaseline(_ context.Context, _ auditdom.ChainRebaseline) error {
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
	role       pentestdom.CampaignRole // the acting user's campaign role; empty means lead
	gotQuery   compliance.PentestFindingQuery
	// memberCampaigns are the acting user's campaigns (ListMemberCampaigns).
	memberCampaigns []compliance.MemberCampaign
	gotCampaigns    []compliance.MemberCampaignQuery
}

func (p *fakePentestReader) ListMemberCampaigns(_ context.Context, q compliance.MemberCampaignQuery) (pagination.Result[compliance.MemberCampaign], error) {
	p.gotTenant, p.gotUser = q.TenantID, q.UserID
	p.gotCampaigns = append(p.gotCampaigns, q)
	start := min((q.Page.Page-1)*q.Page.PerPage, len(p.memberCampaigns))
	end := min(start+q.Page.PerPage, len(p.memberCampaigns))
	return pagination.NewResult(p.memberCampaigns[start:end], int64(len(p.memberCampaigns)), q.Page), nil
}

func (p *fakePentestReader) GetUserCampaignRole(_ context.Context, _, _, _ string) (pentestdom.CampaignRole, error) {
	if p.role == "" {
		return pentestdom.CampaignRoleLead, nil
	}
	return p.role, nil
}

func (p *fakePentestReader) CheckCampaignAccess(_ context.Context, tenantID, _, userID string, isAdmin bool) error {
	p.gotTenant = tenantID
	p.gotUser = userID
	p.gotIsAdmin = isAdmin
	return p.accessErr
}
func (p *fakePentestReader) GetCampaign(_ context.Context, tenantID, _ string) (*pentestdom.Campaign, error) {
	p.gotTenant = tenantID
	if p.campaign == nil {
		// A campaign at the default TLP (amber), AI assistants on.
		c, _ := pentestdom.NewCampaign(shared.NewID(), "__default campaign")
		return c, nil
	}
	return p.campaign, nil
}
func (p *fakePentestReader) ListCampaignMembers(_ context.Context, tenantID, _ string) ([]*pentestdom.CampaignMember, error) {
	p.gotTenant = tenantID
	return p.members, nil
}
func (p *fakePentestReader) GetCampaignStats(_ context.Context, tenantID, _ string, _ bool) (*pentestdom.CampaignStats, error) {
	p.gotTenant = tenantID
	if p.stats == nil {
		return &pentestdom.CampaignStats{}, nil
	}
	return p.stats, nil
}

// QueryCampaignFindings simulates the SQL: the client rule, the filters,
// then the page.
func (p *fakePentestReader) QueryCampaignFindings(_ context.Context, q compliance.PentestFindingQuery) (pagination.Result[*vulnerability.Finding], error) {
	p.gotTenant = q.TenantID
	p.gotUser = q.ViewerUserID
	p.gotQuery = q
	rows := make([]*vulnerability.Finding, 0, len(p.findings))
	for _, f := range p.findings {
		if q.PublishedOnly && !pentestdom.CampaignRoleClient.CanSeeFindingStatus(string(f.Status())) {
			continue
		}
		if len(q.Severities) > 0 && !slices.Contains(q.Severities, string(f.Severity())) {
			continue
		}
		if len(q.Statuses) > 0 && !slices.Contains(q.Statuses, string(f.Status())) {
			continue
		}
		if q.Search != "" && !strings.Contains(strings.ToLower(f.Title()), strings.ToLower(q.Search)) {
			continue
		}
		rows = append(rows, f)
	}
	start := min((q.Page.Page-1)*q.Page.PerPage, len(rows))
	end := min(start+q.Page.PerPage, len(rows))
	return pagination.NewResult(rows[start:end], int64(len(rows)), q.Page), nil
}

// ReportFindings simulates the report selection: no drafts, findings under
// review, false positives or duplicates.
func (p *fakePentestReader) ReportFindings(_ context.Context, tenantID, _ string) ([]*vulnerability.Finding, report.StatsData, error) {
	p.gotTenant = tenantID
	var out []*vulnerability.Finding
	var st report.StatsData
	for _, f := range p.findings {
		switch f.Status() {
		case vulnerability.FindingStatusDraft, vulnerability.FindingStatusInReview,
			vulnerability.FindingStatusFalsePositive, vulnerability.FindingStatusDuplicate:
			continue
		}
		out = append(out, f)
		st.Total++
		switch f.Severity() {
		case vulnerability.SeverityCritical:
			st.Critical++
		case vulnerability.SeverityHigh:
			st.High++
		}
	}
	return out, st, nil
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
	cid := shared.NewID()
	f.SetPentestCampaignID(&cid)
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
	c, err := pentestdom.NewCampaign(shared.NewID(), "__test campaign")
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
	var env struct {
		Notice string               `json:"notice"`
		Data   mcpPentestFindingDTO `json:"untrusted_data"`
	}
	if err := json.Unmarshal([]byte(text), &env); err != nil {
		t.Fatalf("decode finding dto: %v", err)
	}
	if env.Notice == "" {
		t.Error("a finding's text must come with the untrusted-data notice")
	}
	dto := env.Data
	if dto.HasPoC == nil || !*dto.HasPoC {
		t.Error("expected has_poc=true (poc_code present but redacted)")
	}
	if dto.EvidenceCount == nil || *dto.EvidenceCount != 1 {
		t.Errorf("expected evidence_count=1, got %v", dto.EvidenceCount)
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

// A campaign client reaches MCP with their own identity: like the console,
// they see published findings only. Drafts and in-review findings stay hidden
// in the list, in a direct read, in retests and in the report counts.
func mcpToolText(t *testing.T, resp rpcResp) (string, bool) {
	t.Helper()
	var r struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
		IsError bool `json:"isError"`
	}
	if err := json.Unmarshal(resp.Result, &r); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(r.Content) == 0 {
		return "", r.IsError
	}
	return r.Content[0].Text, r.IsError
}

func clientVisibilityFixture(t *testing.T) (*vulnerability.Finding, *vulnerability.Finding) {
	t.Helper()
	draft := makePentestFinding(t)
	draft.SetTitle("DRAFT_NOT_FOR_CLIENT")
	draft.StartAsDraft()
	cid := shared.NewID()
	draft.SetPentestCampaignID(&cid)
	published := makePentestFinding(t)
	published.SetTitle("PUBLISHED_FOR_CLIENT")
	published.SetPentestCampaignID(&cid)
	return draft, published
}

func TestMCP_ListCampaignFindings_ClientSeesPublishedOnly(t *testing.T) {
	draft, published := clientVisibilityFixture(t)
	for _, tc := range []struct {
		role      pentestdom.CampaignRole
		wantDraft bool
	}{{pentestdom.CampaignRoleClient, false}, {pentestdom.CampaignRoleTester, true}, {pentestdom.CampaignRoleObserver, true}} {
		pr := &fakePentestReader{findings: []*vulnerability.Finding{draft, published}, role: tc.role}
		h := newTestMCPWithPentest(&fakeFindingReader{}, pr)
		body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_campaign_findings","arguments":{"campaign_id":"018f5a1e-0000-7000-8000-0000000000cc"}}}`
		_, resp := doRPCScoped(t, h, testTenantUUID, "user-1", []string{"pentest:findings:read"}, body)
		text, _ := mcpToolText(t, resp)
		if got := strings.Contains(text, "DRAFT_NOT_FOR_CLIENT"); got != tc.wantDraft {
			t.Errorf("%s: draft visible = %v, want %v", tc.role, got, tc.wantDraft)
		}
		if !strings.Contains(text, "PUBLISHED_FOR_CLIENT") {
			t.Errorf("%s: published finding missing", tc.role)
		}
	}
}

func TestMCP_GetPentestFinding_ClientCannotReadDraft(t *testing.T) {
	draft, _ := clientVisibilityFixture(t)
	pr := &fakePentestReader{role: pentestdom.CampaignRoleClient}
	h := newTestMCPWithPentest(&fakeFindingReader{finding: draft}, pr)
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_pentest_finding","arguments":{"id":"018f5a1e-0000-7000-8000-0000000000aa"}}}`
	_, resp := doRPCScoped(t, h, testTenantUUID, "user-1", []string{"pentest:findings:read"}, body)
	text, isErr := mcpToolText(t, resp)
	if strings.Contains(text, "DRAFT_NOT_FOR_CLIENT") || (resp.Error == nil && !isErr) {
		t.Fatalf("a client read a draft through MCP: %s", text)
	}
}

func TestMCP_CampaignReportStats_ClientCountsPublishedOnly(t *testing.T) {
	draft, published := clientVisibilityFixture(t)
	pr := &fakePentestReader{
		findings: []*vulnerability.Finding{draft, published},
		stats:    &pentestdom.CampaignStats{TotalFindings: 2, HighFindings: 2, DraftCount: 1},
		role:     pentestdom.CampaignRoleClient,
	}
	h := newTestMCPWithPentest(&fakeFindingReader{}, pr)
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"campaign_report_stats","arguments":{"campaign_id":"018f5a1e-0000-7000-8000-0000000000cc"}}}`
	_, resp := doRPCScoped(t, h, testTenantUUID, "user-1", []string{"pentest:campaigns:read"}, body)
	text, _ := mcpToolText(t, resp)
	var st pentestdom.CampaignStats
	if err := json.Unmarshal([]byte(text), &st); err != nil {
		t.Fatalf("decode stats: %v (%s)", err, text)
	}
	if st.TotalFindings != 1 || st.HighFindings != 1 || st.DraftCount != 0 {
		t.Fatalf("client stats must count published findings only, got %+v", st)
	}
}

// list_active_cves runs the vulnerabilities list as the key's owner: never an
// administrator, open findings only, the args mapped onto the list's params,
// and a bad severity refused instead of widening the list.
func TestMCP_ListActiveCVEs_RunsTheListAsTheKeyOwner(t *testing.T) {
	fr := &fakeFindingReader{}
	h := newTestMCP(fr)
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_active_cves","arguments":{"kev_only":true,"min_epss":0.2,"severity":"High","limit":5}}}`
	_, resp := doRPCScoped(t, h, "018f5a1e-0000-7000-8000-000000000001", "user-1", allReadScopes, body)
	var r struct {
		IsError bool `json:"isError"`
	}
	if err := json.Unmarshal(resp.Result, &r); err != nil || r.IsError {
		t.Fatalf("list_active_cves failed: %v %s", err, resp.Result)
	}
	c := fr.gotCVECaller
	if c.TenantID != "018f5a1e-0000-7000-8000-000000000001" || c.UserID != "user-1" || c.IsAdmin {
		t.Errorf("caller %+v: want the key's tenant and owner, never an administrator", c)
	}
	o := fr.gotCVEOpts
	if o.Sort.Key != vulnerability.CVEListSortRisk || o.KEV == nil || !*o.KEV || o.EPSSGte == nil || *o.EPSSGte != 0.2 || o.PerPage != 5 || o.Page != 1 {
		t.Errorf("options %+v: want kev, epss_gte 0.2, page 1 of 5", o)
	}
	fields := map[string]string{}
	for _, l := range fr.gotCVESpec.Leaves() {
		if len(l.Values) > 0 {
			fields[l.Field] = strings.ToLower(fmt.Sprint(l.Values[0]))
		}
	}
	if fields["state"] != "open" || fields["severity"] != "high" {
		t.Errorf("findings filter %v: want state open and severity high", fields)
	}

	for _, bad := range []string{`{"severity":"x' OR 1=1"}`, `{"min_epss":2}`} {
		fr := &fakeFindingReader{}
		body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_active_cves","arguments":` + bad + `}}`
		_, resp := doRPCScoped(t, newTestMCP(fr), "018f5a1e-0000-7000-8000-000000000001", "user-1", allReadScopes, body)
		var r struct {
			IsError bool `json:"isError"`
		}
		if err := json.Unmarshal(resp.Result, &r); err != nil || !r.IsError || fr.gotCVESpec != nil {
			t.Errorf("args %s: want a refusal before any read", bad)
		}
	}
}

// fakeTotalAssets answers the asset list with a fixed total, as the real
// service does for a caller whose data scope covers that many assets; an
// administrator-view count (the person's full-data console view) answers
// org.
type fakeTotalAssets struct{ total, org int64 }

func (a fakeTotalAssets) ListAssets(_ context.Context, in assetapp.ListAssetsInput) (pagination.Result[*assetdom.Asset], error) {
	n := a.total
	if in.IsAdmin {
		n = a.org
	}
	return pagination.NewResult([]*assetdom.Asset{}, n, pagination.Pagination{Page: 1, PerPage: 1}), nil
}
func (a fakeTotalAssets) GetAsset(context.Context, string, string) (*assetdom.Asset, error) {
	return nil, shared.ErrNotFound
}

// fakeRoles answers HoldsFullDataRole.
type fakeRoles struct{ full bool }

func (r fakeRoles) HoldsFullDataRole(context.Context, shared.ID, string) (bool, error) {
	return r.full, nil
}

// doRPCAs is doRPCScoped for a connection authenticated as provider (an
// oct_ key or an MCP OAuth token), with fullData the OAuth grant's
// "read all organization data" consent.
func doRPCAs(t *testing.T, h *MCPHandler, provider string, fullData bool, scopes []string, body string) rpcResp {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/mcp", bytes.NewBufferString(body))
	ctx := context.WithValue(req.Context(), middleware.TenantIDKey, "018f5a1e-0000-7000-8000-000000000001")
	ctx = context.WithValue(ctx, middleware.UserIDKey, "018f5a1e-0000-7000-8000-0000000000aa")
	ctx = context.WithValue(ctx, middleware.PermissionsKey, scopes)
	ctx = context.WithValue(ctx, middleware.IsAdminKey, false)
	ctx = context.WithValue(ctx, middleware.AuthProviderKey, provider)
	if provider == middleware.AuthProviderMCPOAuth {
		ctx = context.WithValue(ctx, middleware.MCPPrincipalKey, &mcpoauthapp.Principal{FullData: fullData})
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req.WithContext(ctx))
	var resp rpcResp
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Error != nil {
		t.Fatalf("error: %+v", resp.Error)
	}
	return resp
}

// Every asset and finding tool explains a partial view in one line: a
// person whose role reads everything in the console is told how many of
// the organization's assets the connection sees; anyone else is told only
// that their scope covers nothing, never the organization's size. A
// connection allowed to read all organization data gets no notice.
func TestMCP_ScopeNotice(t *testing.T) {
	tools := []string{"list_assets", "list_findings", "finding_stats", "list_active_cves"}
	noAssets := []string{"findings:read"}
	cases := []struct {
		name      string
		provider  string
		fullData  bool
		role      bool
		scopes    []string
		visible   int64
		org       int64
		want      string // substring; "" = no notice
		forbidden string // must not appear
	}{
		{"member, scope covers nothing", middleware.AuthProviderAPIKey, false, false, allReadScopes, 0, 960, "You can see 0 assets", "960"},
		{"member, scope covers assets", middleware.AuthProviderAPIKey, false, false, allReadScopes, 3, 960, "", "960"},
		{"full-data person, key", middleware.AuthProviderAPIKey, false, true, allReadScopes, 0, 960, "You can see 0 of 960 assets", "reconnect"},
		{"full-data person, oauth", middleware.AuthProviderMCPOAuth, false, true, allReadScopes, 4, 960, "You can see 4 of 960 assets; the rest are not assigned to a group you belong to. This connection reads only your groups' assets: reconnect", ""},
		{"full-data person, all assets in scope", middleware.AuthProviderMCPOAuth, false, true, allReadScopes, 960, 960, "", ""},
		{"full-data person, no assets:read", middleware.AuthProviderMCPOAuth, false, true, noAssets, 0, 960, "You can see 0 assets", "960"},
		{"oauth allowed full data", middleware.AuthProviderMCPOAuth, true, true, allReadScopes, 960, 960, "", ""},
	}
	for _, c := range cases {
		for _, tool := range tools {
			t.Run(c.name+"/"+tool, func(t *testing.T) {
				if tool == "list_assets" && !slices.Contains(c.scopes, "assets:read") {
					t.Skip("tool needs assets:read")
				}
				h := NewMCPHandler(&fakeFindingReader{}, nil, nil, nil, nil, fakeTotalAssets{total: c.visible, org: c.org}, nil, logger.NewNop())
				h.SetFullDataRoles(fakeRoles{full: c.role})
				resp := doRPCAs(t, h, c.provider, c.fullData, c.scopes,
					`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"`+tool+`","arguments":{}}}`)
				var r struct {
					Content []struct {
						Text string `json:"text"`
					} `json:"content"`
				}
				if err := json.Unmarshal(resp.Result, &r); err != nil || len(r.Content) == 0 {
					t.Fatalf("result: %s", resp.Result)
				}
				var out map[string]any
				if err := json.Unmarshal([]byte(r.Content[0].Text), &out); err != nil {
					t.Fatalf("payload: %v", err)
				}
				notice, _ := out["scope_notice"].(string)
				if c.want == "" && notice != "" {
					t.Fatalf("want no notice, got %q", notice)
				}
				if c.want != "" && !strings.Contains(notice, c.want) {
					t.Fatalf("notice %q: want %q", notice, c.want)
				}
				if c.forbidden != "" && strings.Contains(notice, c.forbidden) {
					t.Fatalf("notice %q must not contain %q", notice, c.forbidden)
				}
			})
		}
	}
}

// finding_stats and list_active_cves compile as the same caller, so their
// counts are over the same findings: on the connection's own scope rows,
// except an MCP connection allowed to read all organization data, which
// reads like its person in the console (it may not on a key).
func TestMCP_FindingToolsShareOneCaller(t *testing.T) {
	for _, c := range []struct {
		name     string
		provider string
		fullData bool
		ownScope bool
	}{
		{"oct_ key", middleware.AuthProviderAPIKey, false, true},
		{"oauth, own scope", middleware.AuthProviderMCPOAuth, false, true},
		{"oauth, all organization data", middleware.AuthProviderMCPOAuth, true, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			fr := &fakeFindingReader{}
			h := newTestMCP(fr)
			doRPCAs(t, h, c.provider, c.fullData, allReadScopes, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"finding_stats","arguments":{}}}`)
			doRPCAs(t, h, c.provider, c.fullData, allReadScopes, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_active_cves","arguments":{"kev_only":true}}}`)
			sc, cc := fr.gotStatsCaller, fr.gotCVECaller
			if sc.TenantID != cc.TenantID || sc.UserID != cc.UserID || sc.IsAdmin != cc.IsAdmin || sc.APIKey != cc.APIKey {
				t.Fatalf("callers differ: stats %+v, cves %+v", sc, cc)
			}
			if sc.IsAdmin {
				t.Fatal("an MCP connection never gets the administrator bypass")
			}
			if sc.APIKey != c.ownScope {
				t.Fatalf("own-scope reads = %v, want %v", sc.APIKey, c.ownScope)
			}
		})
	}
}
