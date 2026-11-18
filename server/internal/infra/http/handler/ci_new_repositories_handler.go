package handler

// New repositories of an all-projects CI trust configuration. Design:
// docs/architecture/ci-runner-identity.md ("Every project on this GitLab").

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"time"

	cirunapp "github.com/openctemio/openctem/server/internal/app/cirun"
	"github.com/openctemio/openctem/server/pkg/apierror"
	"github.com/openctemio/openctem/server/pkg/domain/cirun"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// CINewRepositoryService lists and decides new repositories.
type CINewRepositoryService interface {
	ListNewRepositories(ctx context.Context, tenantID, configID shared.ID) (*cirunapp.NewRepositoryList, error)
	DecideNewRepositories(ctx context.Context, tenantID, configID shared.ID, d cirun.NewRepositoryDecision, a cirunapp.Actor) (*cirun.TrustConfig, error)
}

// SetNewRepositoryService wires the new repositories (nil answers 503).
func (h *CIAdminHandler) SetNewRepositoryService(svc CINewRepositoryService) { h.newRepos = svc }

// CINewProject is one project waiting for approval.
type CINewProject struct {
	Name      string    `json:"name"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	// Count is how many CI token exchanges the project made.
	Count int64 `json:"count"`
	// ProjectID and NamespaceID are the verified ids of the first sighting.
	// Approving the project binds it to them: a project or namespace that
	// takes the path over later is refused.
	ProjectID   string `json:"project_id,omitempty"`
	NamespaceID string `json:"namespace_id,omitempty"`
}

// CINewGroup is a top-level group with projects waiting for approval.
type CINewGroup struct {
	Group    string         `json:"group"`
	Projects []CINewProject `json:"projects"`
	// Full: the group holds the most pending projects it may (25); a new
	// project of the group is refused without being listed until some are
	// approved or blocked.
	Full bool `json:"full"`
}

// CIBlockedRepository is a blocked project or group.
type CIBlockedRepository struct {
	Kind      string     `json:"kind"`
	Name      string     `json:"name"`
	BlockedBy string     `json:"blocked_by,omitempty"`
	BlockedAt *time.Time `json:"blocked_at,omitempty"`
}

// CINewRepositoriesResponse is an all-projects configuration's new
// repositories: pending projects by top-level group, blocked projects and
// groups, and the approved ones (the configuration's owners and
// repositories).
type CINewRepositoriesResponse struct {
	AllRepositories      bool                  `json:"all_repositories"`
	AdmitNewRepositories bool                  `json:"admit_new_repositories"`
	Pending              []CINewGroup          `json:"pending"`
	Blocked              []CIBlockedRepository `json:"blocked"`
	ApprovedGroups       []string              `json:"approved_groups"`
	ApprovedProjects     []string              `json:"approved_projects"`
	// ListFull: the configuration holds the most pending projects it may
	// (500); a new project is refused without being listed.
	ListFull bool `json:"list_full"`
	// FullGroups are the groups whose pending list is full (25 each).
	FullGroups []string `json:"full_groups"`
}

// ListNewRepositories handles GET /api/v1/ci/trust-configs/{id}/new-repositories
// @Summary      List the new repositories of an all-projects CI trust
// @Description  For a configuration that admits every project of a self-managed GitLab: the projects seen for the first time and waiting for approval, grouped by top-level group, with the verified project and namespace ids they were seen with; the blocked projects and groups; and the approved groups and projects. A group holds at most 25 pending projects and the configuration 500: full lists are named (full_groups, list_full) and a new project past them is refused without being listed. Empty lists for any other configuration.
// @Tags         CI
// @Produce      json
// @Security     BearerAuth
// @Param        id   path string true "Trust configuration ID"
// @Success      200  {object}  CINewRepositoriesResponse
// @Failure      404  {object}  apierror.Error
// @Router       /ci/trust-configs/{id}/new-repositories [get]
func (h *CIAdminHandler) ListNewRepositories(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenant(w, r)
	if !ok {
		return
	}
	if h.newRepos == nil {
		apierror.ServiceUnavailable("New repositories are not available").WriteJSON(w)
		return
	}
	id, ok := pathID(w, r, "CI trust configuration")
	if !ok {
		return
	}
	list, err := h.newRepos.ListNewRepositories(r.Context(), tenantID, id)
	if err != nil {
		h.writeErr(w, err, "list new repositories", "CI trust configuration")
		return
	}
	ciWriteJSON(w, http.StatusOK, newRepositoriesResponse(list))
}

func newRepositoriesResponse(list *cirunapp.NewRepositoryList) CINewRepositoriesResponse {
	c := list.Config
	resp := CINewRepositoriesResponse{AllRepositories: c.Rules.AllRepositories, AdmitNewRepositories: c.Rules.AdmitNewRepositories,
		Pending: []CINewGroup{}, Blocked: []CIBlockedRepository{}, ApprovedGroups: append([]string{}, c.Rules.Owners...),
		ApprovedProjects: append([]string{}, c.Rules.Repositories...), ListFull: list.ListFull,
		FullGroups: append([]string{}, list.FullGroups...)}
	index := map[string]int{}
	for _, row := range list.Rows {
		if row.State == cirun.NewRepoBlocked {
			resp.Blocked = append(resp.Blocked, CIBlockedRepository{Kind: row.Kind, Name: row.Name, BlockedBy: row.DecidedBy, BlockedAt: row.DecidedAt})
			continue
		}
		i, ok := index[row.Group]
		if !ok {
			i = len(resp.Pending)
			index[row.Group] = i
			resp.Pending = append(resp.Pending, CINewGroup{Group: row.Group, Projects: []CINewProject{},
				Full: slices.Contains(list.FullGroups, row.Group)})
		}
		resp.Pending[i].Projects = append(resp.Pending[i].Projects, CINewProject{Name: row.Name, FirstSeen: row.FirstSeen,
			LastSeen: row.LastSeen, Count: row.Count, ProjectID: row.ProjectID, NamespaceID: row.NamespaceID})
	}
	return resp
}

// CINewRepositoryDecisionRequest decides several projects or groups.
type CINewRepositoryDecisionRequest struct {
	// Decision: approve, block or unblock.
	Decision string `json:"decision" enums:"approve,block,unblock"`
	// Items: at most 100; kind project (a full path such as group/project)
	// or group (a top-level group).
	Items []cirun.NewRepositoryItem `json:"items"`
}

// DecideNewRepositories handles POST /api/v1/ci/trust-configs/{id}/new-repositories/decisions
// @Summary      Approve, block or unblock new repositories
// @Description  Approve a project (it joins the configuration's repositories) or a whole group (it joins the owners: every current and future project of the group is admitted with no further approval, and its pending projects are approved at once); block a project or group (refused at once, listed under blocked, reversible); unblock. Several items at once. The same permission (ci:write), recent sign-in and audit as changing the configuration, plus an audit record of the decision. Only for a configuration that admits every project.
// @Tags         CI
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        id   path string true "Trust configuration ID"
// @Param        body body CINewRepositoryDecisionRequest true "Decision"
// @Success      200  {object}  CINewRepositoriesResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Router       /ci/trust-configs/{id}/new-repositories/decisions [post]
func (h *CIAdminHandler) DecideNewRepositories(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenant(w, r)
	if !ok {
		return
	}
	if h.newRepos == nil {
		apierror.ServiceUnavailable("New repositories are not available").WriteJSON(w)
		return
	}
	id, ok := pathID(w, r, "CI trust configuration")
	if !ok {
		return
	}
	limitBody(w, r)
	var req CINewRepositoryDecisionRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	if _, err := h.newRepos.DecideNewRepositories(r.Context(), tenantID, id,
		cirun.NewRepositoryDecision{Action: req.Decision, Items: req.Items}, h.actor(r)); err != nil {
		if errors.Is(err, cirunapp.ErrNotAllRepositories) {
			apierror.BadRequest("This trust configuration does not admit every project; edit its groups and projects instead").WriteJSON(w)
			return
		}
		h.writeErr(w, err, "decide new repositories", "CI trust configuration")
		return
	}
	list, err := h.newRepos.ListNewRepositories(r.Context(), tenantID, id)
	if err != nil {
		h.writeErr(w, err, "list new repositories", "CI trust configuration")
		return
	}
	ciWriteJSON(w, http.StatusOK, newRepositoriesResponse(list))
}
