package handler

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/openctemio/openctem/api/internal/app/finding"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// CommentReactionUser is one person who reacted.
type CommentReactionUser struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// CommentReactionSummary aggregates one emoji on a comment. Summaries are
// ordered by the emoji's first use, so they keep their place as counts change.
type CommentReactionSummary struct {
	Emoji       string `json:"emoji"`
	Count       int    `json:"count"`
	ReactedByMe bool   `json:"reacted_by_me"`
	// SampleUsers holds up to five reactors, earliest first.
	SampleUsers []CommentReactionUser `json:"sample_users"`
}

// CommentReactionsResponse is a comment's reactions after a change.
type CommentReactionsResponse struct {
	Data []CommentReactionSummary `json:"data"`
}

// AddCommentReactionRequest is the body of POST /comments/{comment_id}/reactions.
type AddCommentReactionRequest struct {
	// Emoji is a single emoji sequence (max 32 bytes).
	Emoji string `json:"emoji" example:"👀"`
}

func toCommentReactionSummaries(in []vulnerability.ReactionSummary) []CommentReactionSummary {
	out := make([]CommentReactionSummary, len(in))
	for i, s := range in {
		users := make([]CommentReactionUser, len(s.SampleUsers))
		for j, u := range s.SampleUsers {
			users[j] = CommentReactionUser{ID: u.ID.String(), Name: u.Name}
		}
		out[i] = CommentReactionSummary{Emoji: s.Emoji, Count: s.Count, ReactedByMe: s.ReactedByMe, SampleUsers: users}
	}
	return out
}

// attachReactions fills Reactions on every comment with one query. It
// reports false when the reactions could not be loaded.
func (h *VulnerabilityHandler) attachReactions(r *http.Request, tenantID string, comments []FindingCommentResponse) bool {
	if len(comments) == 0 {
		return true
	}
	ids := make([]shared.ID, 0, len(comments))
	for _, c := range comments {
		if id, err := shared.IDFromString(c.ID); err == nil {
			ids = append(ids, id)
		}
	}
	summaries, err := h.service.CommentReactionSummaries(r.Context(), tenantID, ids,
		middleware.GetLocalUserID(r.Context()).String())
	if err != nil {
		h.logger.Error("failed to load comment reactions", "error", err)
		return false
	}
	for i := range comments {
		id, err := shared.IDFromString(comments[i].ID)
		if err != nil {
			continue
		}
		if s := summaries[id]; len(s) > 0 {
			comments[i].Reactions = toCommentReactionSummaries(s)
		}
	}
	return true
}

// reactionInput builds the service input from the authenticated request.
// The tenant always comes from the credential.
func (h *VulnerabilityHandler) reactionInput(r *http.Request, emoji string) finding.CommentReactionInput {
	ctx := r.Context()
	return finding.CommentReactionInput{
		TenantID:     middleware.MustGetTenantID(ctx),
		CommentID:    r.PathValue("comment_id"),
		Emoji:        emoji,
		UserID:       middleware.GetLocalUserID(ctx).String(),
		ActingUserID: middleware.GetUserID(ctx),
		IsAdmin:      middleware.IsAdmin(ctx),
		Audit:        h.buildAuditContext(r),
	}
}

func writeReactions(w http.ResponseWriter, summaries []vulnerability.ReactionSummary) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(CommentReactionsResponse{Data: toCommentReactionSummaries(summaries)})
}

// AddCommentReaction handles POST /api/v1/comments/{comment_id}/reactions.
//
//	@Summary		React to a finding comment
//	@Description	Adds the caller's emoji reaction. Adding a reaction the caller already has changes nothing. A comment holds at most 20 different emoji and 10 reactions per person. Returns the comment's reactions, ordered by each emoji's first use.
//	@Tags			Findings
//	@Accept			json
//	@Produce		json
//	@Security		BearerAuth
//	@Param			comment_id	path		string						true	"Comment ID"
//	@Param			body		body		AddCommentReactionRequest	true	"Reaction"
//	@Success		200			{object}	CommentReactionsResponse
//	@Failure		400			{object}	apierror.Error	"Not a single emoji, or a reaction limit reached"
//	@Failure		404			{object}	apierror.Error
//	@Failure		429			{object}	apierror.Error
//	@Router			/comments/{comment_id}/reactions [post]
func (h *VulnerabilityHandler) AddCommentReaction(w http.ResponseWriter, r *http.Request) {
	var req AddCommentReactionRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	summaries, err := h.service.AddCommentReaction(r.Context(), h.reactionInput(r, req.Emoji))
	if err != nil {
		h.handleServiceError(w, err, "Comment")
		return
	}
	writeReactions(w, summaries)
}

// RemoveCommentReaction handles DELETE /api/v1/comments/{comment_id}/reactions/{emoji}.
//
//	@Summary		Remove a reaction from a finding comment
//	@Description	Removes the caller's reaction (the emoji is path-escaped). An organization admin or owner may pass user_id to remove another member's reaction; only that moderation is audited. Returns the comment's reactions.
//	@Tags			Findings
//	@Produce		json
//	@Security		BearerAuth
//	@Param			comment_id	path		string	true	"Comment ID"
//	@Param			emoji		path		string	true	"Emoji, path-escaped"
//	@Param			user_id		query		string	false	"Remove this member's reaction (admin/owner only)"
//	@Success		200			{object}	CommentReactionsResponse
//	@Failure		400			{object}	apierror.Error
//	@Failure		403			{object}	apierror.Error
//	@Failure		404			{object}	apierror.Error
//	@Failure		429			{object}	apierror.Error
//	@Router			/comments/{comment_id}/reactions/{emoji} [delete]
func (h *VulnerabilityHandler) RemoveCommentReaction(w http.ResponseWriter, r *http.Request) {
	emoji := r.PathValue("emoji")
	// The router matches on the escaped path when the client's escaping is
	// not Go's canonical one, and then the parameter is still escaped.
	if strings.Contains(emoji, "%") {
		unescaped, err := url.PathUnescape(emoji)
		if err != nil {
			apierror.BadRequest("Invalid emoji").WriteJSON(w)
			return
		}
		emoji = unescaped
	}
	in := h.reactionInput(r, emoji)
	in.TargetUserID = r.URL.Query().Get("user_id")
	summaries, err := h.service.RemoveCommentReaction(r.Context(), in)
	if err != nil {
		h.handleServiceError(w, err, "Comment")
		return
	}
	writeReactions(w, summaries)
}
