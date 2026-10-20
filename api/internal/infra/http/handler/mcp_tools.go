package handler

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/openctemio/openctem/api/internal/app/asset"
	"github.com/openctemio/openctem/api/internal/app/finding"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	assetdom "github.com/openctemio/openctem/api/pkg/domain/asset"
	moduledom "github.com/openctemio/openctem/api/pkg/domain/module"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
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

// parseToolArgs unmarshals an optional-filter tool's arguments. Empty/omitted
// arguments are fine (the tool runs with defaults); malformed JSON is surfaced
// as a toolInputError instead of being silently swallowed into a default result.
func parseToolArgs(raw json.RawMessage, dst any) error {
	if len(raw) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		var ie toolInputError
		if errors.As(err, &ie) {
			return ie
		}
		return toolInputError{"invalid arguments: malformed JSON"}
	}
	return nil
}

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

// requireActingUser returns the key owner's user ID, or a toolInputError when the
// key has no owning user. Pentest campaign/finding reads are gated by the owner's
// campaign membership; a user-less key therefore must NOT reach the membership
// filter (with an empty viewer, ListAllPentestFindings would skip its subquery
// and leak every campaign finding) — so we fail closed here.
func requireActingUser(ctx context.Context) (string, error) {
	u := actingUser(ctx)
	if u == "" {
		return "", toolInputError{"this API key has no owning user; pentest campaign data requires a user-scoped key"}
	}
	return u, nil
}

// buildTools registers every read-only tool. Each executor reads its tenant from
// the (already-authenticated) tenantID argument the dispatcher passes — never
// from the tool's own arguments — so scope can't be widened by a caller.
func (h *MCPHandler) buildTools() []mcpTool {
	return append([]mcpTool{
		{
			Name: "list_findings",
			Description: "List this tenant's vulnerability findings. Optional filters: " +
				"severity (critical/high/medium/low/info), status, source, free-text search." + mcpUntrustedHint,
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
			Description:  "Get a single finding by its ID, scoped to this tenant." + mcpUntrustedHint,
			InputSchema:  json.RawMessage(`{"type":"object","properties":{"finding_id":{"type":"string","format":"uuid","description":"finding UUID"}},"required":["finding_id"]}`),
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
				"kev_only (CISA Known Exploited), min_epss (0..1 exploit-probability floor), severity." + mcpUntrustedHint,
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
			InputSchema:  json.RawMessage(`{"type":"object","properties":{"finding_id":{"type":"string","format":"uuid","description":"finding UUID"}},"required":["finding_id"]}`),
			RequiredPerm: string(permission.FindingsRead),
			call:         h.toolExplainPriority,
		},
		{
			Name: "list_finding_transitions",
			Description: "The status moves of a finding this key may make, from the one transition engine every " +
				"status change uses: each move with allowed, how (direct, an approval request, the duplicate picker), " +
				"the inputs it needs, or the reason codes why not. Read-only.",
			InputSchema:  json.RawMessage(`{"type":"object","properties":{"finding_id":{"type":"string","format":"uuid","description":"finding UUID"}},"required":["finding_id"]}`),
			RequiredPerm: string(permission.FindingsRead),
			call:         h.toolListFindingTransitions,
		},
		{
			Name: "get_exposure_chains",
			Description: "Shortest attack-path hop-chains from public entry points to assets " +
				"carrying open KEV/critical findings (crown jewels), for this tenant." + mcpUntrustedHint,
			InputSchema:  json.RawMessage(`{"type":"object","properties":{}}`),
			RequiredPerm: string(permission.AssetsRead),
			Module:       moduledom.ModuleAttackSurface,
			call:         h.toolExposureChains,
		},
		{
			Name: "list_remediation_groups",
			Description: "List remediation groups (solution families): each is the set of open " +
				"findings one fix resolves, with finding/asset counts and severity breakdown." + mcpUntrustedHint,
			InputSchema:  json.RawMessage(`{"type":"object","properties":{}}`),
			RequiredPerm: string(permission.FindingsRead),
			call:         h.toolListRemediationGroups,
		},
		{
			Name: "list_assets",
			Description: "List this tenant's assets. Filters: exposure (public/private/unknown), " +
				"criticality, free-text search." + mcpUntrustedHint,
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
			Module:       moduledom.ModuleCompliance,
			call:         h.toolCompliancePosture,
		},
	}, h.buildPentestTools()...)
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
	if err := parseToolArgs(raw, &a); err != nil {
		return nil, err
	}

	// Pentest findings of campaigns kept away from AI applications (TLP
	// above the organization's limit, or turned off by the lead) are left
	// out in SQL.
	aiTLPs, err := h.aiAllowedTLPs(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	in := finding.ListFindingsInput{
		TenantID:          tenantID,
		ActingUserID:      actingUser(ctx), // confine to the key owner's data-scope
		IsAdmin:           false,           // API keys never get admin bypass
		Search:            a.Search,
		PerPage:           clampLimit(a.Limit),
		Page:              1,
		PentestAIAllowTLP: aiTLPs,
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
	return untrustedResult(map[string]any{"findings": out}, map[string]any{"total": res.Total}), nil
}

func (h *MCPHandler) toolGetFinding(ctx context.Context, tenantID string, raw json.RawMessage) (any, error) {
	id, err := uuidArg(raw, "finding_id")
	if err != nil {
		return nil, err
	}
	// Scoped read: the key owner's data-scope + pentest membership apply.
	f, err := h.findings.GetFindingWithScope(ctx, tenantID, id, actingUser(ctx), false)
	if err != nil {
		return nil, err
	}
	if err := h.checkFindingAI(ctx, tenantID, f); err != nil {
		return nil, err
	}
	return untrustedResult(toFindingDTO(f), map[string]any{"finding_id": id}), nil
}

func (h *MCPHandler) toolFindingStats(ctx context.Context, tenantID string, _ json.RawMessage) (any, error) {
	// Scoped stats: confine the aggregate to the key owner's group data-scope
	// (IsAdmin=false), mirroring how list_findings builds its scope — so a
	// restricted key never sees posture for findings it can't list.
	stats, err := h.findings.GetFindingStatsWithScope(ctx, finding.GetFindingStatsInput{
		TenantID:     tenantID,
		ActingUserID: actingUser(ctx),
		IsAdmin:      false,
	})
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
	if err := parseToolArgs(raw, &a); err != nil {
		return nil, err
	}

	in := finding.ListActiveCVEsInput{
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
	return untrustedResult(map[string]any{"cves": res.Data}, map[string]any{"total": res.Total}), nil
}

func (h *MCPHandler) toolExplainPriority(ctx context.Context, tenantID string, raw json.RawMessage) (any, error) {
	id, err := uuidArg(raw, "finding_id")
	if err != nil {
		return nil, err
	}
	// Data-scope gate: ExplainFinding is tenant-only (no scope, no pentest gate),
	// so first resolve the finding through the SAME scoped path get_finding uses.
	// If the key's data-scope / pentest membership can't read it, this returns the
	// not-found/denied error and we never reveal priority factors — parity with
	// get_finding's 404 for out-of-scope findings.
	f, err := h.findings.GetFindingWithScope(ctx, tenantID, id, actingUser(ctx), false)
	if err != nil {
		return nil, err
	}
	if err := h.checkFindingAI(ctx, tenantID, f); err != nil {
		return nil, err
	}
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, toolInputError{"invalid tenant"}
	}
	fid, err := shared.IDFromString(id)
	if err != nil {
		return nil, toolInputError{"invalid finding id"}
	}
	exp, err := h.priority.ExplainFinding(ctx, tid, fid)
	if err != nil {
		return nil, err
	}
	// reason and rule_name are written by people in the tenant.
	return untrustedResult(exp, map[string]any{"finding_id": id}), nil
}

// toolListFindingTransitions lists the key owner's allowed moves of one
// finding, resolved through the same scoped read as get_finding (out of scope
// is not found).
func (h *MCPHandler) toolListFindingTransitions(ctx context.Context, tenantID string, raw json.RawMessage) (any, error) {
	id, err := uuidArg(raw, "finding_id")
	if err != nil {
		return nil, err
	}
	f, err := h.findings.GetFindingWithScope(ctx, tenantID, id, actingUser(ctx), false)
	if err != nil {
		return nil, err
	}
	if err := h.checkFindingAI(ctx, tenantID, f); err != nil {
		return nil, err
	}
	has := func(p permission.Permission) bool { return middleware.HasPermission(ctx, string(p)) }
	transitions, status, err := h.findings.ListFindingTransitions(ctx, tenantID, id, actingUser(ctx), finding.TransitionPermissions{
		Status: has(permission.FindingsStatus), Verify: has(permission.FindingsVerify), FixApply: has(permission.FindingsFixApply),
		Triage: has(permission.FindingsTriage), Write: has(permission.FindingsWrite), Approve: has(permission.FindingsApprove),
	})
	if err != nil {
		return nil, err
	}
	return FindingTransitionsResponse{Status: status.String(), Transitions: transitions}, nil
}

// toolExposureChains returns exposure chains narrowed to the key owner's data
// scope: the chains are computed over the whole tenant graph, but a chain is
// returned only when every hop is an asset the key owner may see (the summary
// counts stay tenant-wide). Gated by the assets:read scope.
func (h *MCPHandler) toolExposureChains(ctx context.Context, tenantID string, _ json.RawMessage) (any, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, toolInputError{"invalid tenant"}
	}
	chains, err := h.surface.ExposureChainsForCaller(ctx, tid)
	if err != nil {
		return nil, err
	}
	return untrustedResult(chains, nil), nil
}

// toolListRemediationGroups lists remediation groups over the key owner's
// data scope (GroupService.ListGroups resolves it from the request). Gated by
// findings:read.
func (h *MCPHandler) toolListRemediationGroups(ctx context.Context, tenantID string, _ json.RawMessage) (any, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, toolInputError{"invalid tenant"}
	}
	groups, err := h.groups.ListGroups(ctx, tid)
	if err != nil {
		return nil, err
	}
	return untrustedResult(map[string]any{"groups": groups}, map[string]any{"total": len(groups)}), nil
}

type assetListArgs struct {
	Exposure    string `json:"exposure"`
	Criticality string `json:"criticality"`
	Search      string `json:"search"`
	Limit       int    `json:"limit"`
}

func (h *MCPHandler) toolListAssets(ctx context.Context, tenantID string, raw json.RawMessage) (any, error) {
	var a assetListArgs
	if err := parseToolArgs(raw, &a); err != nil {
		return nil, err
	}

	in := asset.ListAssetsInput{
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
	return untrustedResult(map[string]any{"assets": out}, map[string]any{"total": res.Total}), nil
}

// toolCompliancePosture is an intentionally TENANT-WIDE aggregate: framework /
// control posture is a tenant-level rollup with no per-user data-scope variant
// (GetComplianceStats). Gated by the compliance:frameworks:read scope.
func (h *MCPHandler) toolCompliancePosture(ctx context.Context, tenantID string, _ json.RawMessage) (any, error) {
	return h.compliance.GetComplianceStats(ctx, tenantID)
}
