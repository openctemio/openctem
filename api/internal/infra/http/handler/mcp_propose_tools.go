package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	appcompliance "github.com/openctemio/openctem/api/internal/app/compliance"
	"github.com/openctemio/openctem/api/internal/app/finding"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	moduledom "github.com/openctemio/openctem/api/pkg/domain/module"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/safetext"
)

// Proposal tools (docs/rfcs/RFC-062-mcp-authorization.md, "Proposal tools").
// A proposal tool runs at once but decides nothing: what it writes is a
// pending request of the person who connected the AI application, which a
// DIFFERENT person decides in the web UI. The four-eyes rule refuses the
// requester as approver, so neither the person nor their agent can approve
// it. Like a write tool it needs a connection a person made (an OAuth token,
// never an oct_ key) and a scope the organization allows that is only ever
// granted through an insufficient_scope challenge.

// mcpApprovalRequester files a status approval request
// (*finding.VulnerabilityService).
type mcpApprovalRequester interface {
	RequestApproval(ctx context.Context, input finding.RequestApprovalInput) (*vulnerability.Approval, error)
}

// ApprovalsPagePath is the web page where approvers decide requests.
const ApprovalsPagePath = "/findings/approvals"

// SetProposalTools enables the proposal tools. webBase is the public web
// origin (APP_URL) the review link points to. Without a requester no
// proposal tool is listed.
func (h *MCPHandler) SetProposalTools(approvals mcpApprovalRequester, webBase string) {
	h.approvals = approvals
	h.webBase = strings.TrimRight(webBase, "/")
	if approvals != nil {
		h.tools = append(h.tools, h.buildProposalTools()...)
	}
}

// proposeToolsUsable reports whether the request may see and call proposal
// tools: only a connection a person made.
func proposeToolsUsable(ctx context.Context) bool {
	return middleware.GetMCPPrincipal(ctx) != nil
}

// maxMCPJustificationLen matches the REST approval request limit.
const maxMCPJustificationLen = 2000

func (h *MCPHandler) buildProposalTools() []mcpTool {
	return []mcpTool{{
		Name: "propose_finding_status",
		Description: "Propose that a finding is a false positive or an accepted risk. Nothing changes on the finding: " +
			"this files an approval request in the user's name, marked as written by this AI application, and another " +
			"person decides it in the approval queue (the user cannot approve it). Use list_finding_transitions first: " +
			"only findings that offer this move as an approval request accept it. One pending request per finding; " +
			"pentest findings are reviewed in their campaign instead.",
		InputSchema: json.RawMessage(`{"type":"object","properties":{` +
			`"finding_id":{"type":"string","format":"uuid","description":"finding UUID"},` +
			`"status":{"type":"string","enum":["false_positive","accepted"],"description":"the proposed status"},` +
			`"closure_reason":{"type":"string","description":"why: for false_positive one of component_not_present, vulnerable_code_not_present, vulnerable_code_not_in_execute_path, vulnerable_code_cannot_be_controlled_by_adversary, inline_mitigations_already_exist, detection_error, test_or_example_code; for accepted one of risk_accepted, compensating_control, wont_fix, no_fix_available"},` +
			`"justification":{"type":"string","description":"the evidence and reasoning the approver reads (plain text, at most 2000 characters)"},` +
			`"expires_at":{"type":"string","format":"date-time","description":"accepted only: when the accepted risk ends (RFC 3339); the organization's policy caps it"}},` +
			`"required":["finding_id","status","closure_reason","justification"]}`),
		RequiredPerm: string(permission.FindingsWrite),
		Propose:      true,
		call:         h.toolProposeFindingStatus,
	}}
}

type proposeStatusArgs struct {
	FindingID     string  `json:"finding_id"`
	Status        string  `json:"status"`
	ClosureReason string  `json:"closure_reason"`
	Justification string  `json:"justification"`
	ExpiresAt     *string `json:"expires_at"`
}

func parseProposeStatusArgs(raw json.RawMessage) (proposeStatusArgs, error) {
	var a proposeStatusArgs
	if err := json.Unmarshal(raw, &a); err != nil {
		return a, toolInputError{"invalid arguments: malformed JSON"}
	}
	if _, err := shared.IDFromString(a.FindingID); err != nil {
		return a, toolInputError{"finding_id must be a finding UUID"}
	}
	switch vulnerability.FindingStatus(a.Status) {
	case vulnerability.FindingStatusFalsePositive:
		if a.ExpiresAt != nil {
			return a, toolInputError{"expires_at applies to accepted only"}
		}
	case vulnerability.FindingStatusAccepted:
	default:
		return a, toolInputError{"status must be false_positive or accepted"}
	}
	if _, err := vulnerability.ParseClosureReason(vulnerability.FindingStatus(a.Status), a.ClosureReason); err != nil || a.ClosureReason == "" {
		return a, toolInputError{"closure_reason is not one of the reasons for " + a.Status}
	}
	// The justification is model output an approver reads: hidden characters
	// are refused, never dropped, so the approver reads exactly what was sent.
	j := strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(a.Justification, "\r\n", "\n"), "\r", "\n"))
	if safetext.Clean(j) != j {
		return a, toolInputError{"justification must not contain hidden or control characters (bidirectional, zero-width, tag or control characters)"}
	}
	if j == "" || utf8.RuneCountInString(j) > maxMCPJustificationLen {
		return a, toolInputError{fmt.Sprintf("justification is required, at most %d characters", maxMCPJustificationLen)}
	}
	a.Justification = j
	return a, nil
}

func (h *MCPHandler) toolProposeFindingStatus(ctx context.Context, tenantID string, raw json.RawMessage) (any, error) {
	p := middleware.GetMCPPrincipal(ctx)
	if p == nil { // the dispatcher refuses this first
		return nil, fmt.Errorf("%w: this tool needs a connection a person approved", shared.ErrForbidden)
	}
	a, err := parseProposeStatusArgs(raw)
	if err != nil {
		return nil, err
	}
	// The finding must be one the user can see (data scope, pentest
	// membership) and not kept away from AI applications.
	f, err := h.findings.GetFindingWithScope(ctx, tenantID, a.FindingID, actingUser(ctx), false)
	if err != nil {
		return nil, err
	}
	if err := h.checkFindingAI(ctx, tenantID, f); err != nil {
		return nil, err
	}
	if f.Source() == vulnerability.FindingSourcePentest {
		return nil, toolInputError{"pentest findings are reviewed in their campaign; this tool proposes statuses of other findings"}
	}
	approval, err := h.approvals.RequestApproval(ctx, finding.RequestApprovalInput{
		TenantID: tenantID, FindingID: a.FindingID, RequestedStatus: a.Status,
		Justification: a.Justification, RequestedBy: actingUser(ctx), ExpiresAt: a.ExpiresAt,
		ClosureReason: a.ClosureReason,
		RequestedVia:  proposalClientName(p.ClientName),
		Source:        string(vulnerability.SourceMCP),
	})
	if err != nil {
		// Typed by classifyMCPError: a pending request is a conflict, a
		// refused move an invalid argument with the reason.
		return nil, err
	}
	return map[string]any{
		"status":           "proposed",
		"approval_id":      approval.ID.String(),
		"finding_id":       a.FindingID,
		"requested_status": approval.RequestedStatus,
		"review_url":       h.webBase + ApprovalsPagePath,
		"next": "Nothing has changed on the finding. Another person decides this request in the approval queue; " +
			"the user you act for cannot approve it.",
	}, nil
}

// proposalClientName is the AI application name stored on a proposal.
func proposalClientName(name string) string {
	n := safetext.SingleLine(name, vulnerability.MaxRequestedViaLength)
	if n == "" {
		return "AI application"
	}
	return n
}

// mcpPentestDrafter creates pentest findings (*compliance.PentestService).
type mcpPentestDrafter interface {
	CreateUnifiedFinding(ctx context.Context, input appcompliance.PentestFindingInput) (*vulnerability.Finding, error)
}

// SetPentestDraftTool enables draft_pentest_finding. Without a drafter it is
// not listed.
func (h *MCPHandler) SetPentestDraftTool(drafter mcpPentestDrafter, webBase string) {
	h.drafter = drafter
	h.webBase = strings.TrimRight(webBase, "/")
	if drafter != nil {
		h.tools = append(h.tools, h.buildPentestDraftTool())
	}
}

// Caps on an AI draft beyond the service's own field bounds.
const (
	maxDraftRequestResponses = 10
	maxDraftHTTPBodyRunes    = 32000
	maxDraftHTTPHeaders      = 50
)

func (h *MCPHandler) buildPentestDraftTool() mcpTool {
	return mcpTool{
		Name: "draft_pentest_finding",
		Description: "Save a pentest finding as a DRAFT in a campaign you test or review. The draft is the user's, " +
			"marked as written by this AI application; the campaign client never sees a draft, and another campaign " +
			"member (a reviewer or the lead) must confirm it: the user cannot confirm a draft their AI application wrote. " +
			"Call list_campaign_findings first to avoid duplicates: a finding with the same title in the campaign " +
			"answers conflict. Who may add depends on the campaign phase (testers while testing, reviewers while " +
			"reporting). Write plain text; hidden characters are refused.",
		InputSchema: json.RawMessage(`{"type":"object","properties":{` +
			`"campaign_id":{"type":"string","format":"uuid","description":"campaign UUID (see list_campaigns)"},` +
			`"title":{"type":"string","description":"short title"},` +
			`"severity":{"type":"string","enum":["critical","high","medium","low","info"]},` +
			`"description":{"type":"string","description":"what the issue is"},` +
			`"asset_id":{"type":"string","format":"uuid","description":"the affected asset in the inventory, when there is one"},` +
			`"affected_targets":{"type":"array","items":{"type":"string"},"description":"affected URLs, hosts or components (required without asset_id)"},` +
			`"steps_to_reproduce":{"type":"array","items":{"type":"string"}},` +
			`"request_responses":{"type":"array","maxItems":10,"items":{"type":"object","properties":{` +
			`"method":{"type":"string"},"url":{"type":"string"},"request_headers":{"type":"object","additionalProperties":{"type":"string"}},` +
			`"request_body":{"type":"string"},"response_status":{"type":"integer"},"response_headers":{"type":"object","additionalProperties":{"type":"string"}},` +
			`"response_body":{"type":"string"},"notes":{"type":"string"}},"required":["method","url"]}},` +
			`"cvss_vector":{"type":"string","description":"CVSS v3.1 or v4.0 vector"},` +
			`"cwe_id":{"type":"string","description":"for example CWE-639"},` +
			`"owasp_category":{"type":"string"},` +
			`"business_impact":{"type":"string"},"technical_impact":{"type":"string"},` +
			`"remediation_guidance":{"type":"string"},` +
			`"reference_urls":{"type":"array","items":{"type":"string"}}},` +
			`"required":["campaign_id","title","severity","description"]}`),
		RequiredPerm: string(permission.PentestFindingsWrite),
		Module:       moduledom.ModulePentest,
		Propose:      true,
		call:         h.toolDraftPentestFinding,
	}
}

type draftHTTPExchange struct {
	Method          string            `json:"method"`
	URL             string            `json:"url"`
	RequestHeaders  map[string]string `json:"request_headers"`
	RequestBody     string            `json:"request_body"`
	ResponseStatus  int               `json:"response_status"`
	ResponseHeaders map[string]string `json:"response_headers"`
	ResponseBody    string            `json:"response_body"`
	Notes           string            `json:"notes"`
}

type draftPentestArgs struct {
	CampaignID          string              `json:"campaign_id"`
	Title               string              `json:"title"`
	Severity            string              `json:"severity"`
	Description         string              `json:"description"`
	AssetID             string              `json:"asset_id"`
	AffectedTargets     []string            `json:"affected_targets"`
	StepsToReproduce    []string            `json:"steps_to_reproduce"`
	RequestResponses    []draftHTTPExchange `json:"request_responses"`
	CVSSVector          string              `json:"cvss_vector"`
	CWEID               string              `json:"cwe_id"`
	OWASPCategory       string              `json:"owasp_category"`
	BusinessImpact      string              `json:"business_impact"`
	TechnicalImpact     string              `json:"technical_impact"`
	RemediationGuidance string              `json:"remediation_guidance"`
	ReferenceURLs       []string            `json:"reference_urls"`
}

// draftText normalizes line ends and refuses hidden characters: a reviewer
// reads exactly what the model sent.
func draftText(field, s string, maxRunes int) (string, error) {
	n := strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\r", "\n"))
	if safetext.Clean(n) != n {
		return "", toolInputError{field + " must not contain hidden or control characters (bidirectional, zero-width, tag or control characters)"}
	}
	if maxRunes > 0 && utf8.RuneCountInString(n) > maxRunes {
		return "", toolInputError{fmt.Sprintf("%s is longer than %d characters", field, maxRunes)}
	}
	return n, nil
}

func parseDraftPentestArgs(raw json.RawMessage) (draftPentestArgs, error) { //nolint:cyclop // one check per field
	var a draftPentestArgs
	if err := json.Unmarshal(raw, &a); err != nil {
		return a, toolInputError{"invalid arguments: malformed JSON"}
	}
	if _, err := shared.IDFromString(a.CampaignID); err != nil {
		return a, toolInputError{"campaign_id must be a campaign UUID"}
	}
	if a.AssetID != "" {
		if _, err := shared.IDFromString(a.AssetID); err != nil {
			return a, toolInputError{"asset_id must be an asset UUID"}
		}
	}
	var err error
	if a.Title, err = draftText("title", a.Title, safetext.MaxTitleRunes); err != nil {
		return a, err
	}
	if a.Title == "" || strings.ContainsRune(a.Title, '\n') {
		return a, toolInputError{"title is required, on one line"}
	}
	if a.Description, err = draftText("description", a.Description, 0); err != nil {
		return a, err
	}
	if a.Description == "" {
		return a, toolInputError{"description is required"}
	}
	for _, f := range []*string{&a.CVSSVector, &a.CWEID, &a.OWASPCategory, &a.BusinessImpact, &a.TechnicalImpact, &a.RemediationGuidance} {
		if *f, err = draftText("a text field", *f, 0); err != nil {
			return a, err
		}
	}
	for _, list := range [][]string{a.AffectedTargets, a.StepsToReproduce, a.ReferenceURLs} {
		for i := range list {
			if list[i], err = draftText("a list item", list[i], 0); err != nil {
				return a, err
			}
		}
	}
	if a.AssetID == "" && len(a.AffectedTargets) == 0 {
		return a, toolInputError{"give asset_id or at least one affected target"}
	}
	if len(a.RequestResponses) > maxDraftRequestResponses {
		return a, toolInputError{fmt.Sprintf("at most %d request/response pairs", maxDraftRequestResponses)}
	}
	for i := range a.RequestResponses {
		rr := &a.RequestResponses[i]
		if len(rr.RequestHeaders) > maxDraftHTTPHeaders || len(rr.ResponseHeaders) > maxDraftHTTPHeaders {
			return a, toolInputError{fmt.Sprintf("at most %d headers per request or response", maxDraftHTTPHeaders)}
		}
		for _, f := range []*string{&rr.Method, &rr.URL, &rr.Notes} {
			if *f, err = draftText("a request/response field", *f, safetext.MaxInlineRunes); err != nil {
				return a, err
			}
		}
		for _, f := range []*string{&rr.RequestBody, &rr.ResponseBody} {
			if *f, err = draftText("a request/response body", *f, maxDraftHTTPBodyRunes); err != nil {
				return a, err
			}
		}
		if rr.Method == "" || rr.URL == "" {
			return a, toolInputError{"each request/response needs method and url"}
		}
	}
	return a, nil
}

func (h *MCPHandler) toolDraftPentestFinding(ctx context.Context, tenantID string, raw json.RawMessage) (any, error) {
	p := middleware.GetMCPPrincipal(ctx)
	if p == nil { // the dispatcher refuses this first
		return nil, fmt.Errorf("%w: this tool needs a connection a person approved", shared.ErrForbidden)
	}
	a, err := parseDraftPentestArgs(raw)
	if err != nil {
		return nil, err
	}
	// Membership (a non-member gets not_found), TLP and the campaign's AI
	// switch before anything is written. The phase and role rule for adding
	// a finding is the service's.
	user, _, err := h.campaignReader(ctx, tenantID, a.CampaignID)
	if err != nil {
		return nil, err
	}
	exchanges := make([]map[string]any, 0, len(a.RequestResponses))
	for _, rr := range a.RequestResponses {
		exchanges = append(exchanges, map[string]any{
			"id": shared.NewID().String(), "method": rr.Method, "url": rr.URL,
			"request_headers": rr.RequestHeaders, "request_body": rr.RequestBody,
			"response_status": rr.ResponseStatus, "response_headers": rr.ResponseHeaders,
			"response_body": rr.ResponseBody, "notes": rr.Notes,
		})
	}
	f, err := h.drafter.CreateUnifiedFinding(ctx, appcompliance.PentestFindingInput{
		TenantID: tenantID, CampaignID: a.CampaignID, AssetID: a.AssetID,
		Title: a.Title, Description: a.Description, Severity: a.Severity,
		CVSSVector: a.CVSSVector, CWEID: a.CWEID, OWASPCategory: a.OWASPCategory,
		AffectedAssetsText: a.AffectedTargets, StepsToReproduce: a.StepsToReproduce,
		RequestResponses: exchanges, BusinessImpact: a.BusinessImpact, TechnicalImpact: a.TechnicalImpact,
		RemediationGuidance: a.RemediationGuidance, ReferenceURLs: a.ReferenceURLs,
		ActorID: user, ActorIsAdmin: false,
		DraftedVia: proposalClientName(p.ClientName),
	})
	if err != nil {
		if errors.Is(err, shared.ErrAlreadyExists) {
			return nil, fmt.Errorf("%w: the campaign already has a finding with this title; read it with list_campaign_findings and change the title if this is a different issue", shared.ErrConflict)
		}
		return nil, err
	}
	return map[string]any{
		"status":     "drafted",
		"finding_id": f.ID().String(),
		"review_url": h.webBase + "/findings/" + f.ID().String(),
		"next":       "Saved as a draft. Another campaign member (a reviewer or the lead) confirms it; the user cannot confirm a draft written by their AI application.",
	}, nil
}
