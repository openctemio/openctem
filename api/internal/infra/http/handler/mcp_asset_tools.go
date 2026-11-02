package handler

// MCP asset tools: search_assets (the inventory list) and get_asset (the
// asset page). Both read the same services as the console's asset list and
// asset page, as the connection's caller, so the tenant, the data scope and
// the private-program rule apply exactly as there; get_asset's sections are
// the asset page's endpoints' own responses (toAssetResponse,
// toChangePage, toLineageResponse, toResolvedPortsResponse).

import (
	"context"
	"encoding/json"
	"net"
	"net/url"
	"strings"

	"github.com/openctemio/openctem/api/internal/app/asset"
	assetdom "github.com/openctemio/openctem/api/pkg/domain/asset"
	covdom "github.com/openctemio/openctem/api/pkg/domain/coverage"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/filterspec"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// mcpAssetContext is the asset page's reads (*asset.AssetService). Each
// method resolves the asset in the request caller's data scope (out of
// scope is not found).
type mcpAssetContext interface {
	GetAssetInCallerScope(ctx context.Context, tenantID, assetID string) (*assetdom.Asset, error)
	GetCoverage(ctx context.Context, tenantID, assetID string) (*covdom.AssetView, error)
	ListAssetChanges(ctx context.Context, tenantID, assetID string, q assetdom.ChangeQuery) ([]assetdom.ChangeEvent, bool, error)
	GetResolvedPorts(ctx context.Context, tenantID, assetID string) (*assetdom.ResolvedPorts, error)
	GetLineage(ctx context.Context, tenantID, assetID string) (*assetdom.Lineage, error)
}

// SetAssetContext enables get_asset's page sections. webBase is the public
// web origin console_url links point to ("" leaves console_url out).
func (h *MCPHandler) SetAssetContext(c mcpAssetContext, webBase string) {
	h.assetCtx = c
	h.assetWebBase = strings.TrimRight(webBase, "/")
}

// assetConsoleURL is the asset page in the console, or "".
func (h *MCPHandler) assetConsoleURL(id string) string {
	if h.assetWebBase == "" || id == "" {
		return ""
	}
	return h.assetWebBase + "/assets/" + url.PathEscape(id)
}

// get_asset sections, in the order the asset page shows them.
const (
	assetSecOverview = "overview"
	assetSecFindings = "findings"
	assetSecCoverage = "coverage"
	assetSecPorts    = "ports"
	assetSecLineage  = "lineage"
	assetSecChanges  = "changes"
)

var assetSections = []string{assetSecOverview, assetSecFindings, assetSecCoverage, assetSecPorts, assetSecLineage, assetSecChanges}

// mcpAssetTopFindings is how many open findings get_asset lists.
const mcpAssetTopFindings = 10

// mcpAssetChangeLimit is how many changes get_asset lists (the page's first
// screen).
const mcpAssetChangeLimit = 20

func (h *MCPHandler) buildAssetTools() []mcpTool {
	return []mcpTool{
		{
			Name: "search_assets",
			Description: "Search the assets you can see, as the console's inventory: free text over name and " +
				"description, an IP or CIDR (assets inside it), a CVE (assets with an open finding of it), and filters " +
				"type, exposure, criticality, internet_facing, monitoring_state, scope_status, owner_id (user or group), " +
				"technology, has_findings. Riskiest first, paged; each row has a console_url." + mcpUntrustedHint,
			InputSchema: json.RawMessage(`{"type":"object","properties":{` +
				`"query":{"type":"string","description":"name or description text, an IP address, or a CIDR"},` +
				`"cve":{"type":"string","description":"a CVE id: assets with an open finding of it"},` +
				`"type":{"type":"string","description":"comma list of asset types, e.g. domain,subdomain,ip_address,service,repository"},` +
				`"exposure":{"type":"string","description":"comma list of public|private|restricted|isolated|unknown"},` +
				`"criticality":{"type":"string","description":"comma list of critical|high|medium|low|none"},` +
				`"internet_facing":{"type":"boolean"},` +
				`"monitoring_state":{"type":"string","description":"comma list, e.g. monitored,not_monitored,unvalidated"},` +
				`"scope_status":{"type":"string","description":"comma list of in_scope|not_covered|excluded|internal"},` +
				`"owner_id":{"type":"string","description":"a user or group UUID"},` +
				`"technology":{"type":"string","description":"comma list of technology names"},` +
				`"has_findings":{"type":"boolean"},` +
				`"page":{"type":"integer","description":"page number, from 1"},` +
				`"limit":{"type":"integer","description":"rows per page (default 25, max 100)"}}}`),
			RequiredPerm: string(permission.AssetsRead),
			call:         h.toolSearchAssets,
		},
		{
			Name: "get_asset",
			Description: "One asset as the console's asset page shows it, by asset_id or exact name. sections " +
				"(default all): overview (identity and attributes), findings (open findings by severity and the top " +
				"ones by priority, with ids), coverage (per capability: last run, gaps and causes), ports (open " +
				"ports and services of the addresses it resolves to), lineage (how it was discovered, parents), " +
				"changes (recent attribute changes). Each section is the asset page endpoint's own data; a section " +
				"you may not read says so. console_url links the page." + mcpUntrustedHint,
			InputSchema: json.RawMessage(`{"type":"object","properties":{` +
				`"asset_id":{"type":"string","format":"uuid"},` +
				`"name":{"type":"string","description":"exact asset name, when the id is not known"},` +
				`"sections":{"type":"array","items":{"type":"string","enum":["overview","findings","coverage","ports","lineage","changes"]}}}}`),
			RequiredPerm: string(permission.AssetsRead),
			call:         h.toolGetAsset,
		},
	}
}

type assetSearchArgs struct {
	Query           string `json:"query"`
	CVE             string `json:"cve"`
	Type            string `json:"type"`
	Exposure        string `json:"exposure"`
	Criticality     string `json:"criticality"`
	InternetFacing  *bool  `json:"internet_facing"`
	MonitoringState string `json:"monitoring_state"`
	ScopeStatus     string `json:"scope_status"`
	OwnerID         string `json:"owner_id"`
	Technology      string `json:"technology"`
	HasFindings     *bool  `json:"has_findings"`
	Page            int    `json:"page"`
	Limit           int    `json:"limit"`
}

// splitLowerList is a comma list, trimmed, lowercased, without empty items.
func splitLowerList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.ToLower(strings.TrimSpace(p)); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// mcpAssetSearchRow is one search_assets row.
type mcpAssetSearchRow struct {
	mcpAssetDTO
	SubType      string `json:"sub_type,omitempty"`
	FindingCount int    `json:"finding_count"`
	LastSeen     string `json:"last_seen,omitempty"`
	ConsoleURL   string `json:"console_url,omitempty"`
}

func (h *MCPHandler) toolSearchAssets(ctx context.Context, tenantID string, raw json.RawMessage) (any, error) {
	var a assetSearchArgs
	if err := parseToolArgs(raw, &a); err != nil {
		return nil, err
	}
	page, limit := pageOf(a.Page, a.Limit)
	in := asset.ListAssetsInput{
		TenantID: tenantID, ActingUserID: actingUser(ctx), IsAdmin: false,
		Types: splitLowerList(a.Type), Exposures: splitLowerList(a.Exposure), Criticalities: splitLowerList(a.Criticality),
		InternetFacing: a.InternetFacing, MonitoringState: splitLowerList(a.MonitoringState), ScopeStatus: splitLowerList(a.ScopeStatus),
		Technologies: splitLowerList(a.Technology), HasFindings: a.HasFindings,
		Sort: "-risk_score", Page: page, PerPage: limit,
	}
	if id := strings.TrimSpace(a.OwnerID); id != "" {
		if _, err := shared.IDFromString(id); err != nil {
			return nil, toolInputError{"owner_id must be a UUID"}
		}
		in.OwnerIDs = []string{id}
	}
	// An IP or a CIDR finds the address assets inside it; other text is the
	// list's search.
	switch q := strings.TrimSpace(a.Query); {
	case q == "":
	case net.ParseIP(q) != nil:
		bits := "/32"
		if strings.Contains(q, ":") {
			bits = "/128"
		}
		in.InCIDRs = []string{q + bits}
	case strings.Contains(q, "/") && isCIDR(q):
		in.InCIDRs = []string{q}
	default:
		in.Search = q
	}
	if c := strings.TrimSpace(a.CVE); c != "" {
		ids, err := h.assetIDsWithOpenCVE(ctx, tenantID, c)
		if err != nil {
			return nil, err
		}
		if len(ids) == 0 {
			meta := pageMeta(pagination.Pagination{Page: page, PerPage: limit}, 0)
			h.noteScope(ctx, tenantID, meta)
			return untrustedResult(map[string]any{"assets": []mcpAssetSearchRow{}}, meta), nil
		}
		in.IDs = ids
	}
	res, err := h.assets.ListAssets(ctx, in)
	if err != nil {
		return nil, err
	}
	rows := make([]mcpAssetSearchRow, 0, len(res.Data))
	for _, as := range res.Data {
		row := mcpAssetSearchRow{mcpAssetDTO: toAssetDTO(as), SubType: as.SubType(), FindingCount: as.FindingCount(),
			ConsoleURL: h.assetConsoleURL(as.ID().String())}
		if ls := as.LastSeen(); !ls.IsZero() {
			row.LastSeen = ls.UTC().Format("2006-01-02T15:04:05Z")
		}
		rows = append(rows, row)
	}
	meta := pageMeta(pagination.Pagination{Page: page, PerPage: limit}, res.Total)
	h.noteScope(ctx, tenantID, meta)
	return untrustedResult(map[string]any{"assets": rows}, meta), nil
}

func isCIDR(s string) bool {
	_, _, err := net.ParseCIDR(s)
	return err == nil
}

// assetIDsWithOpenCVE is the assets of the caller's open findings of a CVE,
// from the findings list as the same caller (at most a page of them, the
// most the asset list takes by id).
func (h *MCPHandler) assetIDsWithOpenCVE(ctx context.Context, tenantID, cve string) ([]string, error) {
	spec, err := filterspec.ParseValues(url.Values{"cve_id": {strings.ToUpper(cve)}, "state": {"open"}, "per_page": {"100"}},
		vulnerability.FindingFields, filterspec.Options{Unknown: filterspec.UnknownStrict, NoAliases: true})
	if err != nil {
		return nil, filterInputError(err)
	}
	aiTLPs, err := h.aiAllowedTLPs(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	caller := mcpFilterCaller(ctx, tenantID)
	caller.PentestAIAllowTLP = aiTLPs
	res, err := h.findings.ListFindingsBySpec(ctx, caller, spec)
	if err != nil {
		return nil, filterInputError(err)
	}
	seen := map[string]bool{}
	ids := make([]string, 0, len(res.Data))
	for _, f := range res.Data {
		if id := f.AssetID().String(); !seen[id] && !f.AssetID().IsZero() {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	return ids, nil
}

type getAssetArgs struct {
	AssetID  string   `json:"asset_id"`
	Name     string   `json:"name"`
	Sections []string `json:"sections"`
}

// mcpSectionError is a section the caller may not read or that failed: the
// rest of the asset is still returned.
type mcpSectionError struct {
	Error string `json:"error"`
}

func (h *MCPHandler) toolGetAsset(ctx context.Context, tenantID string, raw json.RawMessage) (any, error) {
	var a getAssetArgs
	if err := parseToolArgs(raw, &a); err != nil {
		return nil, err
	}
	if h.assetCtx == nil {
		return nil, toolInputError{"asset details are not available on this server"}
	}
	want := map[string]bool{}
	for _, s := range a.Sections {
		s = strings.ToLower(strings.TrimSpace(s))
		if !containsString(assetSections, s) {
			return nil, toolInputError{"unknown section " + s + "; one of " + strings.Join(assetSections, ", ")}
		}
		want[s] = true
	}
	if len(want) == 0 {
		for _, s := range assetSections {
			want[s] = true
		}
	}
	id, candidates, err := h.resolveAssetRef(ctx, tenantID, a.AssetID, a.Name)
	if err != nil {
		return nil, err
	}
	if id == "" {
		return untrustedResult(map[string]any{"candidates": candidates},
			map[string]any{"note": "the name matches several assets you can see; call get_asset with one asset_id"}), nil
	}
	// The asset itself, in the caller's scope: out of scope is not found.
	as, err := h.assetCtx.GetAssetInCallerScope(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	out := map[string]any{}
	if want[assetSecOverview] {
		out[assetSecOverview] = toAssetResponse(as)
	}
	if want[assetSecFindings] {
		out[assetSecFindings] = h.assetFindingsSection(ctx, tenantID, id)
	}
	if want[assetSecCoverage] {
		out[assetSecCoverage] = sectionOf(h.assetCtx.GetCoverage(ctx, tenantID, id))
	}
	if want[assetSecPorts] {
		if p, perr := h.assetCtx.GetResolvedPorts(ctx, tenantID, id); perr != nil {
			out[assetSecPorts] = sectionError(perr)
		} else {
			out[assetSecPorts] = toResolvedPortsResponse(p)
		}
	}
	if want[assetSecLineage] {
		if l, lerr := h.assetCtx.GetLineage(ctx, tenantID, id); lerr != nil {
			out[assetSecLineage] = sectionError(lerr)
		} else {
			out[assetSecLineage] = toLineageResponse(l)
		}
	}
	if want[assetSecChanges] {
		events, more, cerr := h.assetCtx.ListAssetChanges(ctx, tenantID, id, assetdom.ChangeQuery{Limit: mcpAssetChangeLimit})
		if cerr != nil {
			out[assetSecChanges] = sectionError(cerr)
		} else {
			out[assetSecChanges] = toChangePage(events, more)
		}
	}
	meta := map[string]any{"asset_id": id, "status_note": mcpStatusNote}
	if u := h.assetConsoleURL(id); u != "" {
		meta["console_url"] = u
	}
	return untrustedResult(out, meta), nil
}

func containsString(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// sectionOf returns a section's value, or its error as a section error.
func sectionOf[T any](v T, err error) any {
	if err != nil {
		return sectionError(err)
	}
	return v
}

// sectionError says why a section is missing without any internal detail.
func sectionError(err error) mcpSectionError {
	return mcpSectionError{Error: classifyMCPError(err).Code}
}

// resolveAssetRef returns the asset id to read: the given id, or the one
// asset the caller can see with exactly that name. Several matches return
// them as candidates (at most a page) and no id.
func (h *MCPHandler) resolveAssetRef(ctx context.Context, tenantID, id, name string) (string, []mcpAssetSearchRow, error) {
	if id = strings.TrimSpace(id); id != "" {
		if _, err := shared.IDFromString(id); err != nil {
			return "", nil, toolInputError{"asset_id must be a UUID"}
		}
		return id, nil, nil
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return "", nil, toolInputError{"asset_id or name is required"}
	}
	res, err := h.assets.ListAssets(ctx, asset.ListAssetsInput{
		TenantID: tenantID, ActingUserID: actingUser(ctx), IsAdmin: false, Name: name, Page: 1, PerPage: mcpMaxLimit,
	})
	if err != nil {
		return "", nil, err
	}
	var exact []mcpAssetSearchRow
	for _, as := range res.Data {
		if strings.EqualFold(as.Name(), name) {
			exact = append(exact, mcpAssetSearchRow{mcpAssetDTO: toAssetDTO(as), SubType: as.SubType(),
				FindingCount: as.FindingCount(), ConsoleURL: h.assetConsoleURL(as.ID().String())})
		}
	}
	switch len(exact) {
	case 0:
		return "", nil, errMCPNotFound
	case 1:
		return exact[0].ID, nil, nil
	default:
		return "", exact, nil
	}
}

// assetFindingsSection is the asset's open findings by severity and the
// top ones by priority, from the findings list as the same caller (so the
// asset page's findings tab and this section count the same findings).
func (h *MCPHandler) assetFindingsSection(ctx context.Context, tenantID, assetID string) any {
	aiTLPs, err := h.aiAllowedTLPs(ctx, tenantID)
	if err != nil {
		return sectionError(err)
	}
	caller := mcpFilterCaller(ctx, tenantID)
	caller.PentestAIAllowTLP = aiTLPs
	q := url.Values{"asset_id": {assetID}, "state": {"open"}, "per_page": {"10"}}
	spec, err := filterspec.ParseValues(q, vulnerability.FindingFields, filterspec.Options{Unknown: filterspec.UnknownStrict, NoAliases: true})
	if err != nil {
		return sectionError(err)
	}
	stats, err := h.findings.GetFindingStatsBySpec(ctx, caller, spec)
	if err != nil {
		return sectionError(err)
	}
	spec.PerPage = mcpAssetTopFindings
	list, err := h.findings.ListFindingsBySpec(ctx, caller, spec)
	if err != nil {
		return sectionError(err)
	}
	bySeverity := map[string]int64{}
	for k, v := range stats.OpenBySeverity {
		bySeverity[string(k)] = v
	}
	top := make([]mcpFindingDTO, 0, len(list.Data))
	for _, f := range list.Data {
		top = append(top, toFindingDTO(f, ""))
	}
	return map[string]any{
		"open": stats.OpenCount, "open_by_severity": bySeverity, "kev_open": stats.KevOpen,
		"top": top, "more": list.Total > int64(len(top)),
	}
}
