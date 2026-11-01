package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/internal/app/asset"
	"github.com/openctemio/openctem/api/internal/app/finding"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	assetdom "github.com/openctemio/openctem/api/pkg/domain/asset"
	moduledom "github.com/openctemio/openctem/api/pkg/domain/module"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/filterspec"
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
	ID    string `json:"id"`
	Title string `json:"title"`
	// DisplayTitle is "<title> on <target>": one finding as one string.
	DisplayTitle string `json:"display_title,omitempty"`
	Severity     string `json:"severity"`
	Status       string `json:"status"`
	CVE          string `json:"cve,omitempty"`
	AssetID      string `json:"asset_id,omitempty"`
	Source       string `json:"source,omitempty"`
}

func toFindingDTO(f *vulnerability.Finding, assetName string) mcpFindingDTO {
	return mcpFindingDTO{
		ID:           f.ID().String(),
		Title:        f.Title(),
		DisplayTitle: vulnerability.FindingDisplayTitle(f, assetName),
		Severity:     string(f.Severity()),
		Status:       string(f.Status()),
		CVE:          f.CVEID(),
		AssetID:      f.AssetID().String(),
		Source:       string(f.Source()),
	}
}

type mcpAssetDTO struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Type        string `json:"type"`
	Criticality string `json:"criticality"`
	Exposure    string `json:"exposure"`
	// RiskScore is 0..100 from the asset's open findings (0: no open finding
	// scored); RiskScoredAt is when it was last computed.
	RiskScore    int        `json:"risk_score"`
	RiskScoredAt *time.Time `json:"risk_scored_at,omitempty"`
}

func toAssetDTO(a *assetdom.Asset) mcpAssetDTO {
	return mcpAssetDTO{
		ID:           a.ID().String(),
		Name:         a.Name(),
		Type:         string(a.Type()),
		Criticality:  string(a.Criticality()),
		Exposure:     string(a.Exposure()),
		RiskScore:    a.RiskScore(),
		RiskScoredAt: a.RiskScoredAt(),
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
				"severity (critical/high/medium/low/info), status, source, free-text search. A finding is one " +
				"issue on one asset with its own status: the same CVE can be false_positive on one asset and new " +
				"on another." + mcpUntrustedHint,
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
				"status plus risk rollups (open KEV findings, high-EPSS open findings, SLA-breached). " +
				"Counts the same findings as list_active_cves: kev_open equals the open_kev_findings " +
				"total of list_active_cves.",
			InputSchema:  json.RawMessage(`{"type":"object","properties":{}}`),
			RequiredPerm: string(permission.FindingsRead),
			call:         h.toolFindingStats,
		},
		{
			Name: "list_active_cves",
			Description: "List the CVEs of open findings you can see, one row per CVE named on a finding, " +
				"riskiest first (priority, KEV, emerging threat, EPSS, CVSS, assets). Title, CVSS and EPSS " +
				"come from the vulnerability catalog when the CVE is in it (catalog_status \"in catalog\"), " +
				"otherwise from the findings (\"not in catalog\"). open_kev_findings counts the open known " +
				"exploited findings, the same count as finding_stats kev_open. Status stays per finding and " +
				"per asset. Filters: kev_only (CISA Known Exploited), min_epss (0..1 exploit-probability " +
				"floor), severity (of the findings)." + mcpUntrustedHint,
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
			Description: "List this tenant's assets, riskiest first. risk_score is 0..100 from the " +
				"asset's open findings (0: no open finding scored), risk_scored_at when it was computed. " +
				"Filters: exposure (public/private/unknown), criticality, free-text search." + mcpUntrustedHint,
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
	names := map[string]string{}
	for _, f := range res.Data {
		out = append(out, toFindingDTO(f, h.findingAssetName(ctx, tenantID, f, names)))
	}
	meta := map[string]any{"total": res.Total, "status_note": mcpStatusNote}
	h.noteScope(ctx, tenantID, meta)
	return untrustedResult(map[string]any{"findings": out}, meta), nil
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
	return untrustedResult(toFindingDTO(f, h.findingAssetName(ctx, tenantID, f, nil)), map[string]any{"finding_id": id}), nil
}

// findingAssetName names f's asset for its display title. The finding was
// read through the key owner's data scope, which admits its asset; the asset
// is read in the same tenant. cache (may be nil) saves repeat lookups on a
// page; a failed read leaves the name out.
func (h *MCPHandler) findingAssetName(ctx context.Context, tenantID string, f *vulnerability.Finding, cache map[string]string) string {
	if h.assets == nil || f.AssetID().IsZero() {
		return ""
	}
	id := f.AssetID().String()
	if name, ok := cache[id]; ok {
		return name
	}
	name := ""
	if a, err := h.assets.GetAsset(ctx, tenantID, id); err == nil && a != nil {
		name = a.Name()
	}
	if cache != nil {
		cache[id] = name
	}
	return name
}

func (h *MCPHandler) toolFindingStats(ctx context.Context, tenantID string, _ json.RawMessage) (any, error) {
	// The findings list's compiled filter as the connection's caller: the
	// same WHERE as list_active_cves, so kev_open and the CVE list's
	// open_kev_findings count the same findings.
	stats, err := h.findings.GetFindingStatsBySpec(ctx, mcpFilterCaller(ctx, tenantID), &filterspec.Spec{})
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
	out := map[string]any{
		"total":          stats.Total,
		"open":           stats.OpenCount,
		"resolved":       stats.ResolvedCount,
		"by_severity":    bySeverity,
		"by_status":      byStatus,
		"kev_open":       stats.KevOpen,
		"epss_high_open": stats.EpssHighOpen,
		"sla_breached":   stats.SLABreached,
	}
	h.noteScope(ctx, tenantID, out)
	return out, nil
}

type activeCVEArgs struct {
	KEVOnly  bool     `json:"kev_only"`
	MinEPSS  *float64 `json:"min_epss"`
	Severity string   `json:"severity"`
	Limit    int      `json:"limit"`
}

// mcpFilterCaller is the caller of a compiled findings read made by an MCP
// connection: the key owner, never with the administrator bypass, and on
// the owner's own scope rows unless the connection was allowed to read all
// organization data (middleware.ReadsOnOwnScope, the same decision the
// data-scope enforcer and every REST read make). One caller for every MCP
// findings tool, so their counts agree.
func mcpFilterCaller(ctx context.Context, tenantID string) finding.FilterCaller {
	return finding.FilterCaller{
		TenantID: tenantID,
		UserID:   actingUser(ctx),
		IsAdmin:  false,
		APIKey:   middleware.ReadsOnOwnScope(ctx),
		Has:      func(p string) bool { return middleware.HasPermission(ctx, p) },
	}
}

// mcpCVERow is a vulnerabilities list row as list_active_cves returns it:
// the list's row plus whether its catalog fields came from the catalog.
type mcpCVERow struct {
	vulnerability.CVEListItem
	CatalogStatus string `json:"catalog_status"`
}

// mcpStatusNote says that a finding's status is its own.
const mcpStatusNote = "Status is per finding: a finding is one CVE or issue on one asset, triaged on its own, " +
	"so the same CVE can be false_positive on one asset and new on another."

// toolListActiveCVEs is the vulnerabilities list (GET
// /vulnerability-exposures) for the key's owner: open findings grouped by
// the CVE they name, on the findings list's compiled filter, so the tenant,
// data scope and member visibility apply exactly as on the page. The key
// never gets an administrator's view.
func (h *MCPHandler) toolListActiveCVEs(ctx context.Context, tenantID string, raw json.RawMessage) (any, error) {
	var a activeCVEArgs
	if err := parseToolArgs(raw, &a); err != nil {
		return nil, err
	}
	if a.MinEPSS != nil && (*a.MinEPSS < 0 || *a.MinEPSS > 1) {
		return nil, toolInputError{"min_epss must be between 0 and 1"}
	}
	q := url.Values{"state": {"open"}}
	if a.Severity != "" {
		q.Set("severity", strings.ToLower(strings.TrimSpace(a.Severity)))
	}
	spec, err := filterspec.ParseValues(q, vulnerability.FindingFields, filterspec.Options{Unknown: filterspec.UnknownStrict})
	if err != nil {
		return nil, toolInputError{"severity must be one of critical, high, medium, low, info, none"}
	}
	opts := vulnerability.CVEListOptions{EPSSGte: a.MinEPSS, Page: 1, PerPage: clampLimit(a.Limit),
		Sort: vulnerability.CVEListSort{Key: vulnerability.CVEListSortRisk}}
	if a.KEVOnly {
		kev := true
		opts.KEV = &kev
	}
	res, err := h.findings.ListCVEExposures(ctx, mcpFilterCaller(ctx, tenantID), spec, opts)
	if err != nil {
		return nil, err
	}
	rows := make([]mcpCVERow, 0, len(res.Data))
	for _, it := range res.Data {
		st := "in catalog"
		if !it.InCatalog {
			st = "not in catalog"
		}
		rows = append(rows, mcpCVERow{CVEListItem: it, CatalogStatus: st})
	}
	meta := map[string]any{
		"total":             res.Total,
		"open_kev_findings": res.Summary.OpenKEVFindings,
		"kev_cves":          res.Summary.KEV,
		"status_note":       mcpStatusNote,
	}
	h.noteScope(ctx, tenantID, meta)
	return untrustedResult(map[string]any{"cves": rows}, meta), nil
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
// scope: a chain is returned when its target is an asset the key owner may
// see, and steps they may not see come back as hidden steps without id, name
// or type. Gated by the assets:read scope.
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
		Sort:         "-risk_score", // riskiest first
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
	meta := map[string]any{"total": res.Total}
	h.noteScope(ctx, tenantID, meta)
	return untrustedResult(map[string]any{"assets": out}, meta), nil
}

// toolCompliancePosture is an intentionally TENANT-WIDE aggregate: framework /
// control posture is a tenant-level rollup with no per-user data-scope variant
// (GetComplianceStats). Gated by the compliance:frameworks:read scope.
func (h *MCPHandler) toolCompliancePosture(ctx context.Context, tenantID string, _ json.RawMessage) (any, error) {
	return h.compliance.GetComplianceStats(ctx, tenantID)
}

// The scope notice (docs/architecture/mcp-authorization.md, "Data scope"):
// an MCP connection reads only the assets its person's groups and scope
// rules grant, unless the person allowed it to read all organization data
// at consent. Assets are granted through owner groups, so a person whose
// role reads everything in the web console can see far fewer assets over
// MCP. Every asset and finding tool says so in one line instead of
// returning data that looks like a small or empty organization.

// mcpScopeNoticeEmpty is the notice for a reader who may not see the
// organization's total: it never names it.
const mcpScopeNoticeEmpty = "You can see 0 assets: none is assigned to a group you belong to, so asset and " +
	"finding results are empty or partial for this connection (findings assigned to you still show). " +
	"Ask an owner to add you to a group that owns assets."

// mcpScopeNoticePartial is the notice for a person whose role reads all
// organization data in the web console: they may see the total there.
const mcpScopeNoticePartial = "You can see %d of %d assets; the rest are not assigned to a group you belong to."

// mcpScopeNoticeReconnect follows the partial notice on an MCP OAuth
// connection, which its person can allow to read all organization data.
const mcpScopeNoticeReconnect = " This connection reads only your groups' assets: reconnect and allow access " +
	"to all organization data to read them all."

// noteScope adds scope_notice to meta when the connection reads on its
// person's own scope rows and those leave assets out. It is best effort: a
// lookup failure leaves the result as it is. The visible count reads the
// asset list as the same caller. The organization's total is read, as a
// count only, when the person holds a full-data role (they see it in the
// web console) and the connection may read assets; anyone else is told
// only that their scope covers nothing.
func (h *MCPHandler) noteScope(ctx context.Context, tenantID string, meta map[string]any) {
	if h.assets == nil || !middleware.ReadsOnOwnScope(ctx) {
		return
	}
	user := actingUser(ctx)
	visible, err := h.assets.ListAssets(ctx, asset.ListAssetsInput{
		TenantID: tenantID, ActingUserID: user, IsAdmin: false, Page: 1, PerPage: 1,
	})
	if err != nil {
		return
	}
	if total, ok := h.orgAssetTotal(ctx, tenantID, user); ok {
		if visible.Total < total {
			n := fmt.Sprintf(mcpScopeNoticePartial, visible.Total, total)
			if middleware.GetAuthProvider(ctx) == middleware.AuthProviderMCPOAuth {
				n += mcpScopeNoticeReconnect
			}
			meta["scope_notice"] = n
		}
		return
	}
	if visible.Total == 0 {
		meta["scope_notice"] = mcpScopeNoticeEmpty
	}
}

// orgAssetTotal is the number of assets the person sees in the web console
// with their full-data role (every asset but private program assets hidden
// from them), and true; false when they hold no such role, the connection
// may not read assets, or a lookup fails. It is a count, never rows.
func (h *MCPHandler) orgAssetTotal(ctx context.Context, tenantID, user string) (int64, bool) {
	if h.roles == nil || user == "" || !middleware.HasPermission(ctx, string(permission.AssetsRead)) {
		return 0, false
	}
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return 0, false
	}
	full, err := h.roles.HoldsFullDataRole(ctx, tid, user)
	if err != nil || !full {
		return 0, false
	}
	// IsAdmin here is the full-data view the person has in the console
	// (unrestricted, private program assets still hidden), used for a count.
	all, err := h.assets.ListAssets(ctx, asset.ListAssetsInput{
		TenantID: tenantID, ActingUserID: user, IsAdmin: true, Page: 1, PerPage: 1,
	})
	if err != nil {
		return 0, false
	}
	return all.Total, true
}
