package handler

import (
	"net/http"
	"strings"

	"github.com/openctemio/openctem/api/pkg/apierror"

	remediationapp "github.com/openctemio/openctem/api/internal/app/remediation"
)

// OwnerCandidateResponse is one person or team the owner picker offers. It
// carries counts only: never the title or content of a finding.
type OwnerCandidateResponse struct {
	Type            string `json:"type"` // user or team
	ID              string `json:"id"`
	Name            string `json:"name"`
	Email           string `json:"email,omitempty"`
	MissingFindings int    `json:"missing_findings"`
	MissingAssets   int    `json:"missing_assets"`
	// Members and MembersMissing are set for a team: its active members and
	// how many of them cannot see some of the findings.
	Members        int `json:"members,omitempty"`
	MembersMissing int `json:"members_missing,omitempty"`
}

// OwnerCandidatesResponse is the picker answer.
type OwnerCandidatesResponse struct {
	// Findings is the number of open findings the owner would work on.
	Findings   int                      `json:"findings"`
	Candidates []OwnerCandidateResponse `json:"candidates"`
}

func toOwnerCandidates(res *remediationapp.OwnerCandidatesResult) OwnerCandidatesResponse {
	out := OwnerCandidatesResponse{Findings: res.Findings, Candidates: make([]OwnerCandidateResponse, 0, len(res.Candidates))}
	for _, c := range res.Candidates {
		typ := "user"
		if c.Team {
			typ = "team"
		}
		out.Candidates = append(out.Candidates, OwnerCandidateResponse{
			Type: typ, ID: c.ID.String(), Name: c.Name, Email: c.Email,
			MissingFindings: c.Findings, MissingAssets: c.Assets, Members: c.Members, MembersMissing: c.MembersMissing,
		})
	}
	return out
}

// OwnerCandidates lists who can own a task and what each cannot see.
// @Summary      Owner candidates for a remediation task
// @Description  People and teams to offer as the task's owner, those who can see all of its open findings first. Each carries counts only (findings and assets the candidate cannot see; for a team, members missing access), never finding titles. Naming a candidate with missing access needs findings:assign and confirm_owner_access.
// @Tags         Remediation
// @Produce      json
// @Param        task_id  path   string  true   "Task ID"
// @Param        q        query  string  false  "Search by name or email"
// @Success      200  {object}  OwnerCandidatesResponse
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /remediation/tasks/{task_id}/owner-candidates [get]
func (h *RemediationTaskHandler) OwnerCandidates(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenant(w, r)
	if !ok {
		return
	}
	id, ok := pathTaskID(w, r)
	if !ok {
		return
	}
	res, err := h.service.OwnerCandidates(r.Context(), remediationapp.OwnerCandidatesInput{TenantID: tid, TaskID: &id, Query: r.URL.Query().Get("q")})
	if err != nil {
		h.handleError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toOwnerCandidates(res))
}

// NewTaskOwnerCandidates is OwnerCandidates for a task not created yet: the
// findings it will hold come as finding_ids (comma separated, at most 100).
// @Summary      Owner candidates for a new remediation task
// @Tags         Remediation
// @Produce      json
// @Param        finding_ids  query  string  true   "Comma separated finding IDs"
// @Param        q            query  string  false  "Search by name or email"
// @Success      200  {object}  OwnerCandidatesResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /remediation/tasks/owner-candidates [get]
func (h *RemediationTaskHandler) NewTaskOwnerCandidates(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenant(w, r)
	if !ok {
		return
	}
	raw := strings.TrimSpace(r.URL.Query().Get("finding_ids"))
	if raw == "" {
		apierror.BadRequest("finding_ids is required").WriteJSON(w)
		return
	}
	parts := strings.Split(raw, ",")
	if len(parts) > 100 {
		h.handleError(w, remediationapp.ErrTaskTooManyFindings)
		return
	}
	ids, err := parseIDList("finding_ids", parts)
	if err != nil {
		h.handleError(w, err)
		return
	}
	res, err := h.service.OwnerCandidates(r.Context(), remediationapp.OwnerCandidatesInput{TenantID: tid, FindingIDs: ids, Query: r.URL.Query().Get("q")})
	if err != nil {
		h.handleError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toOwnerCandidates(res))
}
