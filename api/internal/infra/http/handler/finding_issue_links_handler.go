package handler

// Same-issue groups of findings: the group a finding is in, and taking a
// finding out of it. Members on assets outside the caller's data scope are
// never listed or counted.
// https://github.com/openctemio/openctem/blob/develop/api/docs/architecture/deduplication.md

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/openctemio/openctem/api/internal/app/finding"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/issuelink"
)

// FindingIssueGroupMember is one finding of a same-issue group.
type FindingIssueGroupMember struct {
	ID        string     `json:"id"`
	Title     string     `json:"title"`
	ToolName  string     `json:"tool_name"`
	RuleID    string     `json:"rule_id"`
	Status    string     `json:"status"`
	Severity  string     `json:"severity"`
	AssetID   string     `json:"asset_id,omitempty"`
	AssetName string     `json:"asset_name,omitempty"`
	FilePath  string     `json:"file_path,omitempty"`
	StartLine int        `json:"start_line,omitempty"`
	IsPrimary bool       `json:"is_primary"`
	Rule      string     `json:"rule,omitempty"`
	Basis     []string   `json:"basis,omitempty"`
	LinkedAt  *time.Time `json:"linked_at,omitempty"`
}

// FindingIssueGroupResponse is the same-issue group of a finding: empty
// members when it is in none (or no other member is visible to the caller).
type FindingIssueGroupResponse struct {
	Members []FindingIssueGroupMember `json:"members"`
}

func toIssueGroupMembers(in []issuelink.GroupMember) []FindingIssueGroupMember {
	out := make([]FindingIssueGroupMember, 0, len(in))
	for _, m := range in {
		out = append(out, FindingIssueGroupMember{
			ID: m.FindingID, Title: m.Title, ToolName: m.ToolName, RuleID: m.RuleID, Status: m.Status, Severity: m.Severity,
			AssetID: m.AssetID, AssetName: m.AssetName, FilePath: m.FilePath, StartLine: m.StartLine,
			IsPrimary: m.IsPrimary, Rule: m.Rule, Basis: m.Basis, LinkedAt: m.LinkedAt,
		})
	}
	return out
}

// GetFindingIssueLinks handles GET /api/v1/findings/{id}/issue-links.
//
//	@Summary		Same-issue group of a finding
//	@Description	Findings other tools or rules report for the same issue (same SAST line and weakness, same secret value), linked without being merged: each keeps its own status. Only members in the caller's data scope are listed.
//	@Tags			Findings
//	@Produce		json
//	@Security		BearerAuth
//	@Param			id	path		string	true	"Finding ID"
//	@Success		200	{object}	FindingIssueGroupResponse
//	@Failure		404	{object}	map[string]string
//	@Router			/findings/{id}/issue-links [get]
func (h *VulnerabilityHandler) GetFindingIssueLinks(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	members, err := h.service.IssueGroup(ctx, middleware.MustGetTenantID(ctx), r.PathValue("id"), middleware.GetUserID(ctx), middleware.IsAdmin(ctx))
	if err != nil {
		h.handleServiceError(w, err, "Finding")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(FindingIssueGroupResponse{Members: toIssueGroupMembers(members)})
}

// UnlinkFindingIssue handles DELETE /api/v1/findings/{id}/issue-links/{other}.
//
//	@Summary		Take a finding out of a same-issue group
//	@Description	Ends the link between the finding and another one of its group (the other one leaves; when the other is the group's primary, this finding leaves). The pair is never linked again automatically. Both must be in the caller's data scope. Audited.
//	@Tags			Findings
//	@Security		BearerAuth
//	@Param			id		path	string	true	"Finding ID"
//	@Param			other	path	string	true	"The other finding's ID"
//	@Success		204
//	@Failure		404	{object}	map[string]string
//	@Router			/findings/{id}/issue-links/{other} [delete]
func (h *VulnerabilityHandler) UnlinkFindingIssue(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	err := h.service.UnlinkIssue(ctx, finding.UnlinkIssueInput{
		TenantID:  middleware.MustGetTenantID(ctx),
		FindingID: r.PathValue("id"),
		OtherID:   r.PathValue("other"),
		ActorID:   middleware.GetUserID(ctx),
		IsAdmin:   middleware.IsAdmin(ctx),
		Audit:     h.buildAuditContext(r),
	})
	if errors.Is(err, finding.ErrIssueLinkNotFound) {
		apierror.NotFound("Issue link not found").WriteJSON(w)
		return
	}
	if err != nil {
		h.handleServiceError(w, err, "Finding")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
