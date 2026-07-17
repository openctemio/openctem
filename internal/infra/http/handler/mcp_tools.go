package handler

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/internal/infra/http/middleware"
	assetdom "github.com/openctemio/api/pkg/domain/asset"
	pentestdom "github.com/openctemio/api/pkg/domain/pentest"
	"github.com/openctemio/api/pkg/domain/permission"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/pagination"
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

// --- pentest report-writing DTOs ---------------------------------------------

type mcpCampaignMemberDTO struct {
	UserID string `json:"user_id"`
	Name   string `json:"name,omitempty"`
	Role   string `json:"role"`
}

// mcpCampaignDTO is the whitelisted projection of a pentest campaign: the report
// header context (client, dates, scope, rules of engagement, methodology,
// objectives, team) — never raw domain internals.
type mcpCampaignDTO struct {
	ID                string                 `json:"id"`
	Name              string                 `json:"name"`
	Type              string                 `json:"type"`
	Status            string                 `json:"status"`
	Priority          string                 `json:"priority"`
	Description       string                 `json:"description,omitempty"`
	ClientName        string                 `json:"client_name,omitempty"`
	ClientContact     string                 `json:"client_contact,omitempty"`
	StartDate         string                 `json:"start_date,omitempty"`
	EndDate           string                 `json:"end_date,omitempty"`
	Methodology       string                 `json:"methodology,omitempty"`
	Objectives        []string               `json:"objectives,omitempty"`
	ScopeItems        []map[string]any       `json:"scope_items,omitempty"`
	RulesOfEngagement map[string]any         `json:"rules_of_engagement,omitempty"`
	Tags              []string               `json:"tags,omitempty"`
	Team              []mcpCampaignMemberDTO `json:"team,omitempty"`
}

func toCampaignDTO(c *pentestdom.Campaign, members []*pentestdom.CampaignMember) mcpCampaignDTO {
	dto := mcpCampaignDTO{
		ID:                c.ID().String(),
		Name:              c.Name(),
		Type:              string(c.CampaignType()),
		Status:            string(c.Status()),
		Priority:          string(c.Priority()),
		Description:       c.Description(),
		ClientName:        c.ClientName(),
		ClientContact:     c.ClientContact(),
		Methodology:       c.Methodology(),
		Objectives:        c.Objectives(),
		ScopeItems:        c.ScopeItems(),
		RulesOfEngagement: c.RulesOfEngagement(),
		Tags:              c.Tags(),
	}
	if c.StartDate() != nil {
		dto.StartDate = c.StartDate().Format("2006-01-02")
	}
	if c.EndDate() != nil {
		dto.EndDate = c.EndDate().Format("2006-01-02")
	}
	// Team: user_id + display name + role only. Emails are intentionally omitted
	// so the MCP surface never leaks member PII.
	dto.Team = make([]mcpCampaignMemberDTO, 0, len(members))
	for _, m := range members {
		dto.Team = append(dto.Team, mcpCampaignMemberDTO{
			UserID: m.UserID().String(),
			Name:   m.UserName(),
			Role:   string(m.Role()),
		})
	}
	return dto
}

// mcpPentestFindingDTO is the RICH whitelisted projection of a pentest finding
// for report writing. Evidence and request/response captures are NEVER included
// as raw blobs — only counts + a has_poc flag (populated by get_pentest_finding).
type mcpPentestFindingDTO struct {
	ID                   string   `json:"id"`
	Title                string   `json:"title"`
	Description          string   `json:"description,omitempty"`
	Severity             string   `json:"severity"`
	Status               string   `json:"status"`
	CVSSScore            *float64 `json:"cvss_score,omitempty"`
	CVSSVector           string   `json:"cvss_vector,omitempty"`
	CVSSVersion          string   `json:"cvss_version,omitempty"`
	CWE                  string   `json:"cwe,omitempty"`
	CVE                  string   `json:"cve,omitempty"`
	OWASPCategory        string   `json:"owasp_category,omitempty"`
	MitreTechniqueID     string   `json:"mitre_technique_id,omitempty"`
	StepsToReproduce     []string `json:"steps_to_reproduce,omitempty"`
	BusinessImpact       string   `json:"business_impact,omitempty"`
	TechnicalImpact      string   `json:"technical_impact,omitempty"`
	RemediationGuidance  string   `json:"remediation_guidance,omitempty"`
	ReferenceURLs        []string `json:"reference_urls,omitempty"`
	AffectedAssets       []string `json:"affected_assets,omitempty"`
	EvidenceCount        *int     `json:"evidence_count,omitempty"`
	RequestResponseCount *int     `json:"request_response_count,omitempty"`
	HasPoC               *bool    `json:"has_poc,omitempty"`
}

// mcpMetaStrings extracts a []string from a JSON-decoded []any metadata field.
func mcpMetaStrings(meta map[string]any, key string) []string {
	raw, ok := meta[key].([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func metaStr(meta map[string]any, key string) string {
	if v, ok := meta[key].(string); ok {
		return v
	}
	return ""
}

func metaCount(meta map[string]any, key string) int {
	if raw, ok := meta[key].([]any); ok {
		return len(raw)
	}
	return 0
}

// toPentestFindingDTO projects a unified pentest finding, pulling rich fields out
// of source_metadata. When includeEvidenceMeta is true (single-finding reads),
// evidence/request-response COUNTS and a has_poc flag are added — but never the
// raw evidence blobs, PoC code, or captured request/response bodies.
func toPentestFindingDTO(f *vulnerability.Finding, includeEvidenceMeta bool) mcpPentestFindingDTO {
	meta := f.SourceMetadata()
	dto := mcpPentestFindingDTO{
		ID:                  f.ID().String(),
		Title:               f.Title(),
		Description:         f.Description(),
		Severity:            string(f.Severity()),
		Status:              string(f.Status()),
		CVSSScore:           f.CVSSScore(),
		CVSSVector:          f.CVSSVector(),
		CVSSVersion:         metaStr(meta, "cvss_version"),
		CVE:                 f.CVEID(),
		OWASPCategory:       metaStr(meta, "owasp_category"),
		MitreTechniqueID:    metaStr(meta, "mitre_technique_id"),
		StepsToReproduce:    mcpMetaStrings(meta, "steps_to_reproduce"),
		BusinessImpact:      metaStr(meta, "business_impact"),
		TechnicalImpact:     metaStr(meta, "technical_impact"),
		RemediationGuidance: metaStr(meta, "remediation_guidance"),
		ReferenceURLs:       mcpMetaStrings(meta, "reference_urls"),
		AffectedAssets:      mcpMetaStrings(meta, "affected_assets"),
	}
	if cwes := f.CWEIDs(); len(cwes) > 0 {
		dto.CWE = cwes[0]
	}
	if includeEvidenceMeta {
		ec := metaCount(meta, "evidence")
		rc := metaCount(meta, "request_responses")
		hasPoC := metaStr(meta, "poc_code") != ""
		dto.EvidenceCount = &ec
		dto.RequestResponseCount = &rc
		dto.HasPoC = &hasPoC
	}
	return dto
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
		// --- pentest report-writing tools (campaign-membership gated) ---------
		{
			Name: "get_campaign",
			Description: "Get a pentest campaign's report context: name, type, status, client, dates, " +
				"scope items, rules of engagement, methodology, objectives, and team. Requires the " +
				"key owner to be a member of the campaign.",
			InputSchema:  json.RawMessage(`{"type":"object","properties":{"id":{"type":"string"}},"required":["id"]}`),
			RequiredPerm: string(permission.PentestCampaignsRead),
			call:         h.toolGetCampaign,
		},
		{
			Name: "list_campaign_findings",
			Description: "List a pentest campaign's findings with rich report fields (description, CVSS, " +
				"CWE/CVE, OWASP, MITRE, steps, impacts, remediation, references, affected assets). " +
				"Optional filters: severity, status, limit. Requires campaign membership.",
			InputSchema: json.RawMessage(`{"type":"object","properties":{` +
				`"campaign_id":{"type":"string"},` +
				`"severity":{"type":"string","description":"critical|high|medium|low|info"},` +
				`"status":{"type":"string"},` +
				`"limit":{"type":"integer","description":"max rows (default 25, max 100)"}},"required":["campaign_id"]}`),
			RequiredPerm: string(permission.PentestFindingsRead),
			call:         h.toolListCampaignFindings,
		},
		{
			Name: "get_pentest_finding",
			Description: "Get one pentest finding with full report fields. Evidence and request/response " +
				"captures are returned only as COUNTS plus a has_poc flag — never raw blobs. Requires " +
				"campaign membership.",
			InputSchema:  json.RawMessage(`{"type":"object","properties":{"id":{"type":"string"}},"required":["id"]}`),
			RequiredPerm: string(permission.PentestFindingsRead),
			call:         h.toolGetPentestFinding,
		},
		{
			Name: "list_retests",
			Description: "List retests for a pentest campaign: finding title, severity, retest status, " +
				"notes, tested_at. Requires campaign membership.",
			InputSchema:  json.RawMessage(`{"type":"object","properties":{"campaign_id":{"type":"string"}},"required":["campaign_id"]}`),
			RequiredPerm: string(permission.PentestRetestsRead),
			call:         h.toolListRetests,
		},
		{
			Name: "list_finding_templates",
			Description: "List reusable finding templates (name, category, severity, description, steps, " +
				"impact, remediation). Optional filters: category, free-text search.",
			InputSchema: json.RawMessage(`{"type":"object","properties":{` +
				`"category":{"type":"string"},` +
				`"search":{"type":"string"},` +
				`"limit":{"type":"integer"}}}`),
			RequiredPerm: string(permission.PentestTemplatesRead),
			call:         h.toolListFindingTemplates,
		},
		{
			Name: "campaign_report_stats",
			Description: "Report statistics for a pentest campaign: finding counts by severity/status, " +
				"average and max CVSS, and progress. Requires campaign membership.",
			InputSchema:  json.RawMessage(`{"type":"object","properties":{"campaign_id":{"type":"string"}},"required":["campaign_id"]}`),
			RequiredPerm: string(permission.PentestCampaignsRead),
			call:         h.toolCampaignReportStats,
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
	if err := parseToolArgs(raw, &a); err != nil {
		return nil, err
	}

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
	// Scoped stats: confine the aggregate to the key owner's group data-scope
	// (IsAdmin=false), mirroring how list_findings builds its scope — so a
	// restricted key never sees posture for findings it can't list.
	stats, err := h.findings.GetFindingStatsWithScope(ctx, app.GetFindingStatsInput{
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
	// Data-scope gate: ExplainFinding is tenant-only (no scope, no pentest gate),
	// so first resolve the finding through the SAME scoped path get_finding uses.
	// If the key's data-scope / pentest membership can't read it, this returns the
	// not-found/denied error and we never reveal priority factors — parity with
	// get_finding's 404 for out-of-scope findings.
	if _, err := h.findings.GetFindingWithScope(ctx, tenantID, a.ID, actingUser(ctx), false); err != nil {
		return nil, err
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

// toolExposureChains is an intentionally TENANT-WIDE aggregate: the attack-path
// engine (GetExposureChains) computes graph-level exposure chains across the
// whole tenant estate and exposes no per-user data-scope variant. It is gated by
// the assets:read scope only; there is no *WithScope path to route through.
func (h *MCPHandler) toolExposureChains(ctx context.Context, tenantID string, _ json.RawMessage) (any, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, toolInputError{"invalid tenant"}
	}
	return h.surface.GetExposureChains(ctx, tid)
}

// toolListRemediationGroups is an intentionally TENANT-WIDE aggregate: a
// remediation group is a solution family spanning many findings/assets and the
// service (ListGroups) has no per-user data-scope variant. Gated by findings:read.
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
	if err := parseToolArgs(raw, &a); err != nil {
		return nil, err
	}

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

// toolCompliancePosture is an intentionally TENANT-WIDE aggregate: framework /
// control posture is a tenant-level rollup with no per-user data-scope variant
// (GetComplianceStats). Gated by the compliance:frameworks:read scope.
func (h *MCPHandler) toolCompliancePosture(ctx context.Context, tenantID string, _ json.RawMessage) (any, error) {
	return h.compliance.GetComplianceStats(ctx, tenantID)
}

// --- pentest report-writing tool executors -----------------------------------
//
// SECURITY: MCP keys always act with IsAdmin=false and the campaign-membership
// gate of the key's OWNING USER. This is intentionally stricter than the REST
// path (where a tenant admin bypasses membership): an MCP key that is not a
// member of a campaign — or that has no owning user at all — cannot read that
// campaign's context, findings, retests, or stats. get_pentest_finding routes
// through the same GetFindingWithScope path the generic get_finding tool uses,
// which asserts pentest membership + data-scope for source='pentest' findings.

type campaignIDArg struct {
	CampaignID string `json:"campaign_id"`
}

func (h *MCPHandler) toolGetCampaign(ctx context.Context, tenantID string, raw json.RawMessage) (any, error) {
	if h.pentest == nil {
		return nil, toolInputError{"pentest reader not configured"}
	}
	var a idArg
	if err := json.Unmarshal(raw, &a); err != nil || a.ID == "" {
		return nil, toolInputError{"id is required"}
	}
	user, err := requireActingUser(ctx)
	if err != nil {
		return nil, err
	}
	// Membership gate: non-members get ErrNotCampaignMember (→ generic "not found").
	if err := h.pentest.CheckCampaignAccess(ctx, tenantID, a.ID, user, false); err != nil {
		return nil, err
	}
	campaign, err := h.pentest.GetCampaign(ctx, tenantID, a.ID)
	if err != nil {
		return nil, err
	}
	members, err := h.pentest.ListCampaignMembers(ctx, tenantID, a.ID)
	if err != nil {
		// Members are enrichment; a lookup failure must not deny the campaign read.
		h.logger.Warn("mcp get_campaign: member lookup failed", "error", err.Error())
		members = nil
	}
	return toCampaignDTO(campaign, members), nil
}

type campaignFindingsArgs struct {
	CampaignID string `json:"campaign_id"`
	Severity   string `json:"severity"`
	Status     string `json:"status"`
	Limit      int    `json:"limit"`
}

func (h *MCPHandler) toolListCampaignFindings(ctx context.Context, tenantID string, raw json.RawMessage) (any, error) {
	if h.pentest == nil {
		return nil, toolInputError{"pentest reader not configured"}
	}
	var a campaignFindingsArgs
	if err := json.Unmarshal(raw, &a); err != nil || a.CampaignID == "" {
		return nil, toolInputError{"campaign_id is required"}
	}
	user, err := requireActingUser(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.pentest.CheckCampaignAccess(ctx, tenantID, a.CampaignID, user, false); err != nil {
		return nil, err
	}
	limit := clampLimit(a.Limit)
	// Fetch up to the hard max, then apply the optional severity/status filters in
	// memory and truncate to the requested limit. ListAllPentestFindings pushes a
	// membership subquery (viewer=key owner, isAdmin=false), so this is a second,
	// DB-level enforcement of the same campaign-membership gate.
	res, err := h.pentest.ListAllPentestFindings(ctx, tenantID, a.CampaignID, user, "", false,
		pagination.Pagination{Page: 1, PerPage: mcpMaxLimit})
	if err != nil {
		return nil, err
	}
	sevFilter := strings.ToLower(strings.TrimSpace(a.Severity))
	statFilter := strings.ToLower(strings.TrimSpace(a.Status))
	out := make([]mcpPentestFindingDTO, 0, len(res.Data))
	for _, f := range res.Data {
		if sevFilter != "" && strings.ToLower(string(f.Severity())) != sevFilter {
			continue
		}
		if statFilter != "" && strings.ToLower(string(f.Status())) != statFilter {
			continue
		}
		out = append(out, toPentestFindingDTO(f, false))
		if len(out) >= limit {
			break
		}
	}
	return map[string]any{"total": res.Total, "findings": out}, nil
}

func (h *MCPHandler) toolGetPentestFinding(ctx context.Context, tenantID string, raw json.RawMessage) (any, error) {
	var a idArg
	if err := json.Unmarshal(raw, &a); err != nil || a.ID == "" {
		return nil, toolInputError{"id is required"}
	}
	if _, err := requireActingUser(ctx); err != nil {
		return nil, err
	}
	// Scoped read: GetFindingWithScope asserts pentest campaign-membership +
	// data-scope for source='pentest' findings (IsAdmin=false).
	f, err := h.findings.GetFindingWithScope(ctx, tenantID, a.ID, actingUser(ctx), false)
	if err != nil {
		return nil, err
	}
	if f == nil || f.Source() != vulnerability.FindingSourcePentest {
		return nil, toolInputError{"pentest finding not found"}
	}
	return toPentestFindingDTO(f, true), nil
}

type mcpRetestDTO struct {
	FindingID       string `json:"finding_id"`
	FindingTitle    string `json:"finding_title,omitempty"`
	FindingSeverity string `json:"finding_severity,omitempty"`
	Status          string `json:"status"`
	Notes           string `json:"notes,omitempty"`
	TestedAt        string `json:"tested_at,omitempty"`
}

func (h *MCPHandler) toolListRetests(ctx context.Context, tenantID string, raw json.RawMessage) (any, error) {
	if h.pentest == nil {
		return nil, toolInputError{"pentest reader not configured"}
	}
	var a campaignIDArg
	if err := json.Unmarshal(raw, &a); err != nil || a.CampaignID == "" {
		return nil, toolInputError{"campaign_id is required"}
	}
	user, err := requireActingUser(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.pentest.CheckCampaignAccess(ctx, tenantID, a.CampaignID, user, false); err != nil {
		return nil, err
	}
	// Build a finding_id → (title, severity) lookup from the findings the key owner
	// can see in this campaign, to enrich retests without a separate per-retest read.
	lookup := map[string]*vulnerability.Finding{}
	if fres, ferr := h.pentest.ListAllPentestFindings(ctx, tenantID, a.CampaignID, user, "", false,
		pagination.Pagination{Page: 1, PerPage: 500}); ferr == nil {
		for _, f := range fres.Data {
			lookup[f.ID().String()] = f
		}
	}
	retests, err := h.pentest.ListCampaignRetests(ctx, tenantID, a.CampaignID)
	if err != nil {
		return nil, err
	}
	out := make([]mcpRetestDTO, 0, len(retests))
	for _, rt := range retests {
		dto := mcpRetestDTO{
			FindingID: rt.FindingID().String(),
			Status:    string(rt.Status()),
			Notes:     rt.Notes(),
		}
		if f, ok := lookup[rt.FindingID().String()]; ok {
			dto.FindingTitle = f.Title()
			dto.FindingSeverity = string(f.Severity())
		}
		if rt.TestedAt() != nil {
			dto.TestedAt = rt.TestedAt().Format("2006-01-02")
		}
		out = append(out, dto)
	}
	return map[string]any{"total": len(out), "retests": out}, nil
}

type templateListArgs struct {
	Category string `json:"category"`
	Search   string `json:"search"`
	Limit    int    `json:"limit"`
}

type mcpTemplateDTO struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Category        string   `json:"category,omitempty"`
	Severity        string   `json:"severity"`
	OWASPCategory   string   `json:"owasp_category,omitempty"`
	CWE             string   `json:"cwe,omitempty"`
	Description     string   `json:"description,omitempty"`
	Steps           []string `json:"steps,omitempty"`
	BusinessImpact  string   `json:"business_impact,omitempty"`
	TechnicalImpact string   `json:"technical_impact,omitempty"`
	Remediation     string   `json:"remediation,omitempty"`
	IsSystem        bool     `json:"is_system"`
}

func toTemplateDTO(t *pentestdom.Template) mcpTemplateDTO {
	return mcpTemplateDTO{
		ID:              t.ID().String(),
		Name:            t.Name(),
		Category:        string(t.Category()),
		Severity:        string(t.Severity()),
		OWASPCategory:   t.OWASPCategory(),
		CWE:             t.CWEID(),
		Description:     t.Description(),
		Steps:           t.StepsToReproduce(),
		BusinessImpact:  t.BusinessImpact(),
		TechnicalImpact: t.TechnicalImpact(),
		Remediation:     t.Remediation(),
		IsSystem:        t.IsSystem(),
	}
}

func (h *MCPHandler) toolListFindingTemplates(ctx context.Context, tenantID string, raw json.RawMessage) (any, error) {
	if h.pentest == nil {
		return nil, toolInputError{"pentest reader not configured"}
	}
	var a templateListArgs
	if err := parseToolArgs(raw, &a); err != nil {
		return nil, err
	}
	filter := pentestdom.TemplateFilter{}
	if a.Category != "" {
		cat, err := pentestdom.ParseTemplateCategory(a.Category)
		if err != nil {
			return nil, toolInputError{"invalid category"}
		}
		filter.Category = &cat
	}
	if a.Search != "" {
		filter.Search = &a.Search
	}
	res, err := h.pentest.ListTemplates(ctx, tenantID, filter,
		pagination.Pagination{Page: 1, PerPage: clampLimit(a.Limit)})
	if err != nil {
		return nil, err
	}
	out := make([]mcpTemplateDTO, 0, len(res.Data))
	for _, t := range res.Data {
		out = append(out, toTemplateDTO(t))
	}
	return map[string]any{"total": res.Total, "templates": out}, nil
}

func (h *MCPHandler) toolCampaignReportStats(ctx context.Context, tenantID string, raw json.RawMessage) (any, error) {
	if h.pentest == nil {
		return nil, toolInputError{"pentest reader not configured"}
	}
	var a campaignIDArg
	if err := json.Unmarshal(raw, &a); err != nil || a.CampaignID == "" {
		return nil, toolInputError{"campaign_id is required"}
	}
	user, err := requireActingUser(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.pentest.CheckCampaignAccess(ctx, tenantID, a.CampaignID, user, false); err != nil {
		return nil, err
	}
	return h.pentest.GetCampaignStats(ctx, tenantID, a.CampaignID)
}
