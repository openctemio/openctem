package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/internal/app/attack"
	auditapp "github.com/openctemio/api/internal/app/audit"
	appcompliance "github.com/openctemio/api/internal/app/compliance"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/apierror"
	assetdom "github.com/openctemio/api/pkg/domain/asset"
	auditdom "github.com/openctemio/api/pkg/domain/audit"
	remediationdom "github.com/openctemio/api/pkg/domain/remediation"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// mcpProtocolVersion is the MCP revision this server advertises in `initialize`.
const mcpProtocolVersion = "2024-11-05"

// JSON-RPC 2.0 error codes (subset used here).
const (
	rpcParseError     = -32700
	rpcInvalidRequest = -32600
	rpcMethodNotFound = -32601
	rpcInvalidParams  = -32602
	rpcInternalError  = -32603
)

type jsonrpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type jsonrpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *jsonrpcError   `json:"error,omitempty"`
}

type jsonrpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// --- Narrow read interfaces (reuse existing tenant-scoped services) ----------
// Each MCP tool calls one of these; every method takes the tenant explicitly so
// the handler can never widen scope beyond the authenticated key's tenant.

type mcpFindingReader interface {
	ListFindings(ctx context.Context, in app.ListFindingsInput) (pagination.Result[*vulnerability.Finding], error)
	// GetFindingWithScope enforces the caller's data-scope + pentest membership
	// (never the admin-bypass GetFinding).
	GetFindingWithScope(ctx context.Context, tenantID, findingID, actingUserID string, isAdmin bool) (*vulnerability.Finding, error)
	// GetFindingStatsWithScope applies the caller's group data-scope (isAdmin=false),
	// so aggregate posture is confined exactly like list_findings — never the
	// admin-wide GetFindingStats.
	GetFindingStatsWithScope(ctx context.Context, input app.GetFindingStatsInput) (*vulnerability.FindingStats, error)
	ListActiveCVEs(ctx context.Context, in app.ListActiveCVEsInput) (pagination.Result[vulnerability.ActiveCVE], error)
}

type mcpPriorityExplainer interface {
	ExplainFinding(ctx context.Context, tenantID, findingID shared.ID) (*app.PriorityExplanation, error)
}

type mcpSurfaceReader interface {
	GetExposureChains(ctx context.Context, tenantID shared.ID) (*attack.ExposureChainResult, error)
}

type mcpGroupReader interface {
	ListGroups(ctx context.Context, tenantID shared.ID) ([]remediationdom.Group, error)
}

type mcpComplianceReader interface {
	GetComplianceStats(ctx context.Context, tenantID string) (*appcompliance.ComplianceStatsResponse, error)
}

type mcpAssetReader interface {
	ListAssets(ctx context.Context, in app.ListAssetsInput) (pagination.Result[*assetdom.Asset], error)
	GetAsset(ctx context.Context, tenantID, assetID string) (*assetdom.Asset, error)
}

// mcpTool is one callable tool: an MCP declaration plus a tenant-scoped executor.
type mcpTool struct {
	Name        string
	Description string
	InputSchema json.RawMessage
	// RequiredPerm is the permission (API-key scope) the caller must hold to run
	// this tool. Enforced by handleToolsCall via the same HasPermission check the
	// REST routes use — so an MCP key can do exactly what its scopes allow.
	RequiredPerm string
	// call runs the tool for a single tenant. args is the raw JSON `arguments`
	// object; the return value is JSON-marshaled into the tool's text result.
	call func(ctx context.Context, tenantID string, args json.RawMessage) (any, error)
}

// MCPHandler serves a read-only Model Context Protocol endpoint over JSON-RPC,
// exposing a tenant's CTEM data (findings, KEV/EPSS CVEs, attack-path exposure
// chains, remediation groups, compliance posture, assets) to an AI client. The
// tenant is taken solely from the authenticated API key's context — never from
// tool arguments — so every tool is confined to that tenant.
type MCPHandler struct {
	findings   mcpFindingReader
	priority   mcpPriorityExplainer
	surface    mcpSurfaceReader
	groups     mcpGroupReader
	compliance mcpComplianceReader
	assets     mcpAssetReader
	logger     *logger.Logger
	tools      []mcpTool
	// audit records every tools/call (success and error). Optional: when nil the
	// handler behaves identically minus the audit trail, so tests and stub builds
	// need not provide one.
	audit *auditapp.AuditService
}

// NewMCPHandler builds the handler and its tool registry from existing services.
func NewMCPHandler(
	findings mcpFindingReader,
	priority mcpPriorityExplainer,
	surface mcpSurfaceReader,
	groups mcpGroupReader,
	compliance mcpComplianceReader,
	assets mcpAssetReader,
	log *logger.Logger,
) *MCPHandler {
	h := &MCPHandler{
		findings:   findings,
		priority:   priority,
		surface:    surface,
		groups:     groups,
		compliance: compliance,
		assets:     assets,
		logger:     log.With("handler", "mcp"),
	}
	h.tools = h.buildTools()
	return h
}

// SetAuditService wires the audit logger so every MCP tools/call emits a
// non-repudiable audit event (which key, tenant, user, tool, sanitized args,
// outcome). Nil-safe: when unset, tool calls run identically minus the audit.
func (h *MCPHandler) SetAuditService(svc *auditapp.AuditService) {
	h.audit = svc
}

// ServeHTTP handles a single JSON-RPC 2.0 request over HTTP POST. The tenant is
// already bound by APIKeyAuth middleware; a missing tenant is a wiring error and
// is rejected outright.
func (h *MCPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantID(r.Context())
	if tenantID == "" {
		apierror.Unauthorized("Invalid credentials").WriteJSON(w)
		return
	}

	var req jsonrpcRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, nil, rpcParseError, "parse error")
		return
	}
	if req.JSONRPC != "2.0" || req.Method == "" {
		h.writeError(w, req.ID, rpcInvalidRequest, "invalid request")
		return
	}

	// JSON-RPC notifications (the `notifications/*` methods) carry no id and
	// expect no response body — just acknowledge them.
	if strings.HasPrefix(req.Method, "notifications/") {
		w.WriteHeader(http.StatusAccepted)
		return
	}

	switch req.Method {
	case "initialize":
		h.writeResult(w, req.ID, h.initializeResult())
	case "ping":
		h.writeResult(w, req.ID, struct{}{})
	case "tools/list":
		h.writeResult(w, req.ID, h.toolsListResult(r.Context()))
	case "tools/call":
		h.handleToolsCall(w, r, req, tenantID)
	default:
		h.writeError(w, req.ID, rpcMethodNotFound, "method not found")
	}
}

func (h *MCPHandler) initializeResult() map[string]any {
	return map[string]any{
		"protocolVersion": mcpProtocolVersion,
		"capabilities":    map[string]any{"tools": map[string]any{}},
		"serverInfo": map[string]any{
			"name":    "openctem-mcp",
			"version": "1.0.0",
		},
		"instructions": "Read-only access to this tenant's OpenCTEM CTEM data: " +
			"findings, KEV/EPSS-prioritized CVEs, attack-path exposure chains, " +
			"remediation groups (solution families), compliance posture, and assets.",
	}
}

// toolsListResult advertises only the tools the calling key can actually run:
// a tool is listed only if its RequiredPerm passes HasPermission for this
// context (API keys are never admin, so this consults just the key's scopes).
// A scopeless/narrow key therefore never even sees tools it cannot call.
func (h *MCPHandler) toolsListResult(ctx context.Context) map[string]any {
	list := make([]map[string]any, 0, len(h.tools))
	for _, t := range h.tools {
		if t.RequiredPerm != "" && !middleware.HasPermission(ctx, t.RequiredPerm) {
			continue
		}
		list = append(list, map[string]any{
			"name":        t.Name,
			"description": t.Description,
			"inputSchema": t.InputSchema,
		})
	}
	return map[string]any{"tools": list}
}

func (h *MCPHandler) handleToolsCall(w http.ResponseWriter, r *http.Request, req jsonrpcRequest, tenantID string) {
	ctx := r.Context()
	var p struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &p); err != nil {
		h.writeError(w, req.ID, rpcInvalidParams, "invalid params")
		return
	}

	var tool *mcpTool
	for i := range h.tools {
		if h.tools[i].Name == p.Name {
			tool = &h.tools[i]
			break
		}
	}
	if tool == nil {
		h.writeError(w, req.ID, rpcInvalidParams, "unknown tool")
		return
	}

	// Enforce the key's scope: an MCP key can call a tool only if it carries the
	// tool's required permission — the same gate the equivalent REST route uses.
	// API keys are never admin, so HasPermission consults only the key's scopes.
	if tool.RequiredPerm != "" && !middleware.HasPermission(ctx, tool.RequiredPerm) {
		h.auditToolCall(r, tenantID, tool.Name, p.Arguments, auditdom.ResultDenied, true, 0)
		h.writeResult(w, req.ID, toolResult("permission denied: this API key lacks the scope required for this tool ("+tool.RequiredPerm+")", true))
		return
	}

	result, err := tool.call(ctx, tenantID, p.Arguments)
	if err != nil {
		// MCP convention: tool execution failures are a normal result with
		// isError=true, not a JSON-RPC protocol error. Only safe input-validation
		// messages are surfaced verbatim; any other (internal/service) error is
		// redacted to avoid leaking DB/internal detail — logged in full server-side.
		h.logger.Warn("mcp tool error", "tool", tool.Name, "error", err.Error())
		h.auditToolCall(r, tenantID, tool.Name, p.Arguments, auditdom.ResultFailure, true, 0)
		var ie toolInputError
		if errors.As(err, &ie) {
			h.writeResult(w, req.ID, toolResult(ie.Error(), true))
		} else {
			h.writeResult(w, req.ID, toolResult("tool execution failed", true))
		}
		return
	}
	text, mErr := json.Marshal(result)
	if mErr != nil {
		h.writeError(w, req.ID, rpcInternalError, "internal error")
		return
	}
	h.auditToolCall(r, tenantID, tool.Name, p.Arguments, auditdom.ResultSuccess, false, len(text))
	h.writeResult(w, req.ID, toolResult(string(text), false))
}

// auditToolCall records one MCP tools/call. It is nil-safe (no audit service →
// no-op). The args summary is SANITIZED: only argument keys and any id/severity/
// status/exposure-style scalar filters are recorded — never free-text search
// content or full finding data — so the trail can't become a data-exfil channel.
func (h *MCPHandler) auditToolCall(r *http.Request, tenantID, toolName string, args json.RawMessage, result auditdom.Result, isError bool, resultSize int) {
	if h.audit == nil {
		return
	}
	ctx := r.Context()
	event := auditapp.AuditEvent{
		Action:       auditdom.ActionMCPToolCalled,
		ResourceType: auditdom.ResourceTypeMCPTool,
		ResourceID:   toolName,
		Result:       result,
		Severity:     auditdom.SeverityLow,
		Message:      "MCP tool called: " + toolName,
		Metadata: map[string]any{
			"tool":           toolName,
			"is_error":       isError,
			"result_size":    resultSize,
			"args":           sanitizeMCPArgs(args),
			"api_key_id":     middleware.GetAPIKeyID(ctx),
			"api_key_prefix": middleware.GetAPIKeyPrefix(ctx),
		},
	}
	actx := auditapp.AuditContext{
		TenantID:   tenantID,
		ActorID:    middleware.GetUserID(ctx),
		ActorEmail: middleware.GetUsername(ctx),
		ActorIP:    auditClientIP(r),
		UserAgent:  r.UserAgent(),
		RequestID:  r.Header.Get("X-Request-ID"),
	}
	_ = h.audit.LogEvent(ctx, actx, event)
}

// mcpAuditSafeArgs is the allowlist of tool-argument keys whose scalar value is
// safe to record verbatim in the audit trail (ids and enum-like filters). Any
// other key (e.g. free-text `search`) is recorded present-but-redacted so the
// audit log never stores query content or finding data.
var mcpAuditSafeArgs = map[string]bool{
	"id": true, "severity": true, "status": true, "source": true,
	"exposure": true, "criticality": true, "kev_only": true,
	"min_epss": true, "limit": true,
}

// sanitizeMCPArgs reduces raw tool arguments to an audit-safe summary: every
// key present, with the value only for allowlisted non-sensitive scalars.
func sanitizeMCPArgs(raw json.RawMessage) map[string]any {
	if len(raw) == 0 {
		return nil
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return map[string]any{"_unparsable": true}
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		if mcpAuditSafeArgs[k] {
			var val any
			if err := json.Unmarshal(v, &val); err == nil {
				if s, ok := val.(string); ok && len(s) > 128 {
					val = s[:128]
				}
				out[k] = val
				continue
			}
		}
		out[k] = "<redacted>"
	}
	return out
}

// auditClientIP resolves the caller IP, preferring proxy headers.
func auditClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return xff
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	return r.RemoteAddr
}

// toolResult wraps text as an MCP tools/call result content block.
func toolResult(text string, isError bool) map[string]any {
	return map[string]any{
		"content": []map[string]any{{"type": "text", "text": text}},
		"isError": isError,
	}
}

func (h *MCPHandler) writeResult(w http.ResponseWriter, id json.RawMessage, result any) {
	h.writeJSON(w, jsonrpcResponse{JSONRPC: "2.0", ID: id, Result: result})
}

func (h *MCPHandler) writeError(w http.ResponseWriter, id json.RawMessage, code int, msg string) {
	h.writeJSON(w, jsonrpcResponse{JSONRPC: "2.0", ID: id, Error: &jsonrpcError{Code: code, Message: msg}})
}

func (h *MCPHandler) writeJSON(w http.ResponseWriter, resp jsonrpcResponse) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}
