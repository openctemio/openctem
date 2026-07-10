package handler

import (
	"context"
	"encoding/json"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/internal/infra/http/middleware"
	assetdom "github.com/openctemio/api/pkg/domain/asset"
	"github.com/openctemio/api/pkg/domain/permission"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
)

// toolInputError is a tool argument-validation error whose message is safe to
// return to the client verbatim. Any other error is redacted by the dispatcher.
type toolInputError struct{ msg string }

func (e toolInputError) Error() string { return e.msg }

// actingUser returns the API key's owning user (from context, set by
// APIKeyAuth). Tools pass this with isAdmin=false so a key sees exactly the
// data-scope of the user it was minted for — never an admin-wide view.
func actingUser(ctx context.Context) string { return middleware.GetUserID(ctx) }

// mcpDefaultLimit / mcpMaxLimit bound how many rows a list tool returns, so an
// AI client can't pull an unbounded result set into its context.
const (
	mcpDefaultLimit = 25
	mcpMaxLimit     = 100
)

func clampLimit(n int) int {
	if n <= 0 {
		return mcpDefaultLimit
	}
	if n > mcpMaxLimit {
		return mcpMaxLimit
	}
	return n
}

// --- compact DTOs (domain entities expose getters, not JSON fields) ----------

type mcpFindingDTO struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
	Status   string `json:"status"`
	CVE      string `json:"cve,omitempty"`
	AssetID  string `json:"asset_id,omitempty"`
	Source   string `json:"source,omitempty"`
}

func toFindingDTO(f *vulnerability.Finding) mcpFindingDTO {
	return mcpFindingDTO{
		ID:       f.ID().String(),
		Title:    f.Title(),
		Severity: string(f.Severity()),
		Status:   string(f.Status()),
		CVE:      f.CVEID(),
		AssetID:  f.AssetID().String(),
		Source:   string(f.Source()),
	}
}

type mcpAssetDTO struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Type        string `json:"type"`
	Criticality string `json:"criticality"`
	Exposure    string `json:"exposure"`
	RiskScore   int    `json:"risk_score"`
}

func toAssetDTO(a *assetdom.Asset) mcpAssetDTO {
	return mcpAssetDTO{
		ID:          a.ID().String(),
		Name:        a.Name(),
		Type:        string(a.Type()),
		Criticality: string(a.Criticality()),
		Exposure:    string(a.Exposure()),
		RiskScore:   a.RiskScore(),
	}
}

// buildTools registers every read-only tool. Each executor reads its tenant from
// the (already-authenticated) tenantID argument the dispatcher passes — never
// from the tool's own arguments — so scope can't be widened by a caller.
func (h *MCPHandler) buildTools() []mcpTool {
	return []mcpTool{
		{
			Name: "list_findings",
			Description: "List this tenant's vulnerability findings. Optional filters: " +
				"severity (critical/high/medium/low/info), status, source, free-text search.",
			InputSchema: json.RawMessage(`{"type":"object","properties":{` +
				`"severity":{"type":"string","description":"critical|high|medium|low|info"},` +
				`"status":{"type":"string"},` +
				`"source":{"type":"string"},` +
				`"search":{"type":"string"},` +
				`"limit":{"type":"integer","description":"max rows (default 25, max 100)"}}}`),
			RequiredPerm: string(permission.FindingsRead),
			call:         h.toolListFindings,
		},
		{
			Name:         "get_finding",
			Description:  "Get a single finding by its ID, scoped to this tenant.",
			InputSchema:  json.RawMessage(`{"type":"object","properties":{"id":{"type":"string"}},"required":["id"]}`),
			RequiredPerm: string(permission.FindingsRead),
			call:         h.toolGetFinding,
		},
		{
			Name: "finding_stats",
			Description: "Aggregate finding posture for this tenant: totals by severity and " +
				"status plus risk rollups (open KEV findings, high-EPSS open findings, SLA-breached).",
			InputSchema:  json.RawMessage(`{"type":"object","properties":{}}`),
			RequiredPerm: string(permission.FindingsRead),
			call:         h.toolFindingStats,
		},
		{
			Name: "list_active_cves",
			Description: "List KEV/EPSS-prioritized CVEs active in this tenant. Filters: " +
				"kev_only (CISA Known Exploited), min_epss (0..1 exploit-probability floor), severity.",
			InputSchema: json.RawMessage(`{"type":"object","properties":{` +
				`"kev_only":{"type":"boolean"},` +
				`"min_epss":{"type":"number","description":"0..1 EPSS floor"},` +
				`"severity":{"type":"string"},` +
				`"limit":{"type":"integer"}}}`),
			RequiredPerm: string(permission.FindingsRead),
			call:         h.toolListActiveCVEs,
		},
		{
			Name: "explain_finding_priority",
			Description: "Explain why a finding has its priority (KEV / EPSS / reachability / " +
				"severity weighting), scoped to this tenant. Read-only; does not reclassify.",
			InputSchema:  json.RawMessage(`{"type":"object","properties":{"id":{"type":"string"}},"required":["id"]}`),
			RequiredPerm: string(permission.FindingsRead),
			call:         h.toolExplainPriority,
		},
		{
			Name: "get_exposure_chains",
			Description: "Shortest attack-path hop-chains from public entry points to assets " +
				"carrying open KEV/critical findings (crown jewels), for this tenant.",
			InputSchema:  json.RawMessage(`{"type":"object","properties":{}}`),
			RequiredPerm: string(permission.AssetsRead),
			call:         h.toolExposureChains,
		},
		{
			Name: "list_remediation_groups",
			Description: "List remediation groups (solution families): each is the set of open " +
				"findings one fix resolves, with finding/asset counts and severity breakdown.",
			InputSchema:  json.RawMessage(`{"type":"object","properties":{}}`),
			RequiredPerm: string(permission.FindingsRead),
			call:         h.toolListRemediationGroups,
		},
		{
			Name: "list_assets",
			Description: "List this tenant's assets. Filters: exposure (public/private/unknown), " +
				"criticality, free-text search.",
			InputSchema: json.RawMessage(`{"type":"object","properties":{` +
				`"exposure":{"type":"string","description":"public|private|unknown"},` +
				`"criticality":{"type":"string"},` +
				`"search":{"type":"string"},` +
				`"limit":{"type":"integer"}}}`),
			RequiredPerm: string(permission.AssetsRead),
			call:         h.toolListAssets,
		},
		{
			Name:         "compliance_posture",
			Description:  "Compliance posture rollup for this tenant: framework/control totals and overdue controls.",
			InputSchema:  json.RawMessage(`{"type":"object","properties":{}}`),
			RequiredPerm: string(permission.ComplianceFrameworksRead),
			call:         h.toolCompliancePosture,
		},
	}
}

// --- tool executors ----------------------------------------------------------

type findingListArgs struct {
	Severity string `json:"severity"`
	Status   string `json:"status"`
	Source   string `json:"source"`
	Search   string `json:"search"`
	Limit    int    `json:"limit"`
}

func (h *MCPHandler) toolListFindings(ctx context.Context, tenantID string, raw json.RawMessage) (any, error) {
	var a findingListArgs
	_ = json.Unmarshal(raw, &a)

	in := app.ListFindingsInput{
		TenantID:     tenantID,
		ActingUserID: actingUser(ctx), // confine to the key owner's data-scope
		IsAdmin:      false,           // API keys never get admin bypass
		Search:       a.Search,
		PerPage:      clampLimit(a.Limit),
		Page:         1,
	}
	if a.Severity != "" {
		in.Severities = []string{a.Severity}
	}
	if a.Status != "" {
		in.Statuses = []string{a.Status}
	}
	if a.Source != "" {
		in.Sources = []string{a.Source}
	}

	res, err := h.findings.ListFindings(ctx, in)
	if err != nil {
		return nil, err
	}
	out := make([]mcpFindingDTO, 0, len(res.Data))
	for _, f := range res.Data {
		out = append(out, toFindingDTO(f))
	}
	return map[string]any{"total": res.Total, "findings": out}, nil
}

type idArg struct {
	ID string `json:"id"`
}

func (h *MCPHandler) toolGetFinding(ctx context.Context, tenantID string, raw json.RawMessage) (any, error) {
	var a idArg
	if err := json.Unmarshal(raw, &a); err != nil || a.ID == "" {
		return nil, toolInputError{"id is required"}
	}
	// Scoped read: the key owner's data-scope + pentest membership apply.
	f, err := h.findings.GetFindingWithScope(ctx, tenantID, a.ID, actingUser(ctx), false)
	if err != nil {
		return nil, err
	}
	return toFindingDTO(f), nil
}

func (h *MCPHandler) toolFindingStats(ctx context.Context, tenantID string, _ json.RawMessage) (any, error) {
	stats, err := h.findings.GetFindingStats(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	bySeverity := make(map[string]int64, len(stats.BySeverity))
	for k, v := range stats.BySeverity {
		bySeverity[string(k)] = v
	}
	byStatus := make(map[string]int64, len(stats.ByStatus))
	for k, v := range stats.ByStatus {
		byStatus[string(k)] = v
	}
	return map[string]any{
		"total":          stats.Total,
		"open":           stats.OpenCount,
		"resolved":       stats.ResolvedCount,
		"by_severity":    bySeverity,
		"by_status":      byStatus,
		"kev_open":       stats.KevOpen,
		"epss_high_open": stats.EpssHighOpen,
		"sla_breached":   stats.SLABreached,
	}, nil
}

type activeCVEArgs struct {
	KEVOnly  bool     `json:"kev_only"`
	MinEPSS  *float64 `json:"min_epss"`
	Severity string   `json:"severity"`
	Limit    int      `json:"limit"`
}

func (h *MCPHandler) toolListActiveCVEs(ctx context.Context, tenantID string, raw json.RawMessage) (any, error) {
	var a activeCVEArgs
	_ = json.Unmarshal(raw, &a)

	in := app.ListActiveCVEsInput{
		TenantID: tenantID,
		KEVOnly:  a.KEVOnly,
		MinEPSS:  a.MinEPSS,
		Page:     1,
		PerPage:  clampLimit(a.Limit),
	}
	if a.Severity != "" {
		in.SeverityIn = []string{a.Severity}
	}
	res, err := h.findings.ListActiveCVEs(ctx, in)
	if err != nil {
		return nil, err
	}
	return map[string]any{"total": res.Total, "cves": res.Data}, nil
}

func (h *MCPHandler) toolExplainPriority(ctx context.Context, tenantID string, raw json.RawMessage) (any, error) {
	var a idArg
	if err := json.Unmarshal(raw, &a); err != nil || a.ID == "" {
		return nil, toolInputError{"id is required"}
	}
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, toolInputError{"invalid tenant"}
	}
	fid, err := shared.IDFromString(a.ID)
	if err != nil {
		return nil, toolInputError{"invalid finding id"}
	}
	return h.priority.ExplainFinding(ctx, tid, fid)
}

func (h *MCPHandler) toolExposureChains(ctx context.Context, tenantID string, _ json.RawMessage) (any, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, toolInputError{"invalid tenant"}
	}
	return h.surface.GetExposureChains(ctx, tid)
}

func (h *MCPHandler) toolListRemediationGroups(ctx context.Context, tenantID string, _ json.RawMessage) (any, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, toolInputError{"invalid tenant"}
	}
	groups, err := h.groups.ListGroups(ctx, tid)
	if err != nil {
		return nil, err
	}
	return map[string]any{"total": len(groups), "groups": groups}, nil
}

type assetListArgs struct {
	Exposure    string `json:"exposure"`
	Criticality string `json:"criticality"`
	Search      string `json:"search"`
	Limit       int    `json:"limit"`
}

func (h *MCPHandler) toolListAssets(ctx context.Context, tenantID string, raw json.RawMessage) (any, error) {
	var a assetListArgs
	_ = json.Unmarshal(raw, &a)

	in := app.ListAssetsInput{
		TenantID:     tenantID,
		ActingUserID: actingUser(ctx), // confine to the key owner's data-scope
		IsAdmin:      false,           // API keys never get admin bypass
		Search:       a.Search,
		Page:         1,
		PerPage:      clampLimit(a.Limit),
	}
	if a.Exposure != "" {
		in.Exposures = []string{a.Exposure}
	}
	if a.Criticality != "" {
		in.Criticalities = []string{a.Criticality}
	}
	res, err := h.assets.ListAssets(ctx, in)
	if err != nil {
		return nil, err
	}
	out := make([]mcpAssetDTO, 0, len(res.Data))
	for _, as := range res.Data {
		out = append(out, toAssetDTO(as))
	}
	return map[string]any{"total": res.Total, "assets": out}, nil
}

func (h *MCPHandler) toolCompliancePosture(ctx context.Context, tenantID string, _ json.RawMessage) (any, error) {
	return h.compliance.GetComplianceStats(ctx, tenantID)
}
