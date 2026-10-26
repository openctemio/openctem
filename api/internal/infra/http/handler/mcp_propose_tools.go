package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/openctemio/openctem/api/internal/app/finding"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
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
