package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/openctemio/openctem/api/internal/app/finding"
	mcpoauthapp "github.com/openctemio/openctem/api/internal/app/mcpoauth"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/mcpoauth"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// Write tools (RFC-062 §10). A write tool runs only for a connection a
// person made (an OAuth token, never an oct_ key), only when the token
// holds a write scope the organization allows, and only after the person
// approved the exact action in the OpenCTEM web UI. The first call returns
// where to approve; the second call, with the same arguments and the
// confirmation id, runs the action once.

// mcpConfirmer stores and consumes write-action confirmations
// (*mcpoauthapp.Service).
type mcpConfirmer interface {
	RequestConfirmation(ctx context.Context, p *mcpoauthapp.Principal, tool, digest, summary string, actor mcpoauthapp.Actor) (*mcpoauthapp.PendingConfirmation, error)
	UseConfirmation(ctx context.Context, p *mcpoauthapp.Principal, id, tool, digest string) error
}

// mcpFindingCommenter adds a comment to a finding (*finding.VulnerabilityService).
type mcpFindingCommenter interface {
	AddFindingCommentWithInput(ctx context.Context, in finding.AddFindingCommentInput) (*vulnerability.FindingComment, error)
}

// SetWriteTools enables the write tools: confirmations and the services
// they write through. Without them no write tool is listed.
func (h *MCPHandler) SetWriteTools(confirmer mcpConfirmer, comments mcpFindingCommenter) {
	h.confirmer = confirmer
	h.comments = comments
	if confirmer != nil && comments != nil {
		h.tools = append(h.tools, h.buildWriteTools()...)
	}
}

// writeToolsUsable reports whether the request may see and call write tools.
func (h *MCPHandler) writeToolsUsable(ctx context.Context) bool {
	return h.confirmer != nil && middleware.GetMCPPrincipal(ctx) != nil
}

const maxMCPCommentLen = 4000

func (h *MCPHandler) buildWriteTools() []mcpTool {
	return []mcpTool{{
		Name: "add_finding_comment",
		Description: "Add an internal comment to a finding (visible to the organization's members, never sent to " +
			"integrations). Changes data: the first call returns a link where the user confirms the exact comment " +
			"in OpenCTEM; after they confirm, call again with the same arguments plus confirmation_id.",
		InputSchema: json.RawMessage(`{"type":"object","properties":{` +
			`"finding_id":{"type":"string","description":"finding UUID"},` +
			`"content":{"type":"string","description":"comment text (plain text, at most 4000 characters)"},` +
			`"confirmation_id":{"type":"string","description":"the id returned by the first call, once the user confirmed"}},` +
			`"required":["finding_id","content"]}`),
		RequiredPerm: string(permission.FindingsWrite),
		Write:        true,
		prepare:      h.prepareAddFindingComment,
		call:         h.toolAddFindingComment,
	}}
}

type addCommentArgs struct {
	FindingID string `json:"finding_id"`
	Content   string `json:"content"`
}

func parseAddCommentArgs(raw json.RawMessage) (addCommentArgs, error) {
	var a addCommentArgs
	if err := json.Unmarshal(raw, &a); err != nil {
		return a, toolInputError{"invalid arguments: malformed JSON"}
	}
	if _, err := shared.IDFromString(a.FindingID); err != nil {
		return a, toolInputError{"finding_id must be a finding UUID"}
	}
	a.Content = strings.TrimSpace(a.Content)
	if a.Content == "" || utf8.RuneCountInString(a.Content) > maxMCPCommentLen {
		return a, toolInputError{fmt.Sprintf("content is required, at most %d characters", maxMCPCommentLen)}
	}
	return a, nil
}

// prepareAddFindingComment checks the action and describes it for the
// person: the finding must be one the user can see.
func (h *MCPHandler) prepareAddFindingComment(ctx context.Context, tenantID string, raw json.RawMessage) (string, error) {
	a, err := parseAddCommentArgs(raw)
	if err != nil {
		return "", err
	}
	f, err := h.findings.GetFindingWithScope(ctx, tenantID, a.FindingID, actingUser(ctx), false)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("Add an internal comment to the finding %q (%s severity):\n\n%s", f.Title(), f.Severity(), a.Content), nil
}

func (h *MCPHandler) toolAddFindingComment(ctx context.Context, tenantID string, raw json.RawMessage) (any, error) {
	a, err := parseAddCommentArgs(raw)
	if err != nil {
		return nil, err
	}
	// Scope again at execution: access may have changed since confirmation.
	if _, err := h.findings.GetFindingWithScope(ctx, tenantID, a.FindingID, actingUser(ctx), false); err != nil {
		return nil, err
	}
	c, err := h.comments.AddFindingCommentWithInput(ctx, finding.AddFindingCommentInput{
		TenantID: tenantID, FindingID: a.FindingID, AuthorID: actingUser(ctx), Content: a.Content, IsInternal: true,
	})
	if err != nil {
		return nil, err
	}
	return map[string]any{"status": "done", "comment_id": c.ID().String(), "finding_id": a.FindingID}, nil
}

// runWriteTool is the confirmation step in front of a write tool's
// executor. It returns the result to send, or nil when the tool should run.
func (h *MCPHandler) runWriteTool(r *http.Request, tool *mcpTool, tenantID string, raw json.RawMessage) (map[string]any, bool) {
	ctx := r.Context()
	p := middleware.GetMCPPrincipal(ctx)
	if p == nil || h.confirmer == nil {
		return toolResult("this tool needs a connection a person approved; API keys cannot change data", true), true
	}
	var args map[string]any
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &args); err != nil {
			return toolResult("invalid arguments: malformed JSON", true), true
		}
	}
	digest := mcpoauthapp.ArgsDigest(tool.Name, args)
	if id, _ := args["confirmation_id"].(string); id != "" {
		if err := h.confirmer.UseConfirmation(ctx, p, id, tool.Name, digest); err != nil {
			if errors.Is(err, mcpoauth.ErrConfirmationRequired) {
				return toolResult("not confirmed: the confirmation is missing, refused, expired, already used, or for "+
					"other arguments. Call again without confirmation_id to get a new confirmation link.", true), true
			}
			h.logger.Warn("mcp confirmation use failed", "error", err.Error())
			return toolResult("tool execution failed", true), true
		}
		return nil, false
	}
	summary, err := tool.prepare(ctx, tenantID, raw)
	if err != nil {
		var ie toolInputError
		if errors.As(err, &ie) {
			return toolResult(ie.Error(), true), true
		}
		h.logger.Warn("mcp write tool prepare failed", "tool", tool.Name, "error", err.Error())
		return toolResult("tool execution failed", true), true
	}
	pending, err := h.confirmer.RequestConfirmation(ctx, p, tool.Name, digest, summary, mcpoauthapp.Actor{
		IP: auditClientIP(r), UserAgent: r.UserAgent(), RequestID: r.Header.Get("X-Request-ID"),
	})
	if err != nil {
		h.logger.Warn("mcp confirmation request failed", "error", err.Error())
		return toolResult("tool execution failed", true), true
	}
	text, _ := json.Marshal(map[string]any{
		"status":             "confirmation_required",
		"confirmation_url":   pending.URL,
		"confirmation_id":    pending.ID,
		"expires_in_seconds": int(mcpoauth.ConfirmationTTL.Seconds()),
		"next": "Ask the user to open confirmation_url and confirm. Then call " + tool.Name +
			" again with the same arguments and confirmation_id. Nothing has changed yet.",
	})
	return toolResult(string(text), false), true
}
