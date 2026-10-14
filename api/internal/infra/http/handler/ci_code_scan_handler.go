package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	codescanapp "github.com/openctemio/openctem/api/internal/app/codescan"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/codescan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Code scanning of repositories: the tenant's template, each repository's
// settings and the baseline of its protected branches
// (docs/rfcs/RFC-091-code-scanning-baseline.md). Same area, permissions and
// module as the rest of CI/CD.

// CICodeScanService is the code scanning service.
type CICodeScanService interface {
	Template(ctx context.Context, tenantID shared.ID) (codescan.Settings, string, error)
	UpdateTemplate(ctx context.Context, tenantID shared.ID, in codescanapp.SettingsInput, a codescanapp.Actor) (codescan.Settings, error)
	Repository(ctx context.Context, tenantID, assetID shared.ID) (*codescanapp.RepositoryStatus, error)
	ListRepositories(ctx context.Context, tenantID shared.ID, scope *shared.DataScope, limit, offset int) ([]codescanapp.RepositoryStatus, int, error)
	UpdateRepository(ctx context.Context, tenantID, assetID shared.ID, in codescanapp.SettingsInput, a codescanapp.Actor) (*codescanapp.RepositoryStatus, error)
	ResetRepository(ctx context.Context, tenantID, assetID shared.ID, a codescanapp.Actor) (*codescanapp.RepositoryStatus, error)
	Rebaseline(ctx context.Context, tenantID, assetID shared.ID, a codescanapp.Actor) (int, *codescanapp.RepositoryStatus, error)
}

// SetCodeScanService wires code scanning; without it the routes answer 404.
func (h *CIAdminHandler) SetCodeScanService(s CICodeScanService) { h.codeScan = s }

// CodeScanSettingsRequest sets the template or a repository's settings.
type CodeScanSettingsRequest struct {
	// ProtectedBranches are branch names or patterns ("release/*"), 1 to
	// 20; "{default}" is the repository's default branch.
	ProtectedBranches []string `json:"protected_branches"`
	// Capabilities: sast, secrets, sca, iac.
	Capabilities []string `json:"capabilities"`
	// Schedule of the full rescan: off, daily, weekly or monthly.
	Schedule string `json:"schedule"`
	// Routing: auto (public repositories on the platform's sensors, the
	// rest on the organization's), platform or tenant.
	Routing string `json:"routing"`
	Enabled bool   `json:"enabled"`
}

// CodeScanSettingsResponse is effective settings and where they come from
// (repository, template or default).
type CodeScanSettingsResponse struct {
	ProtectedBranches []string   `json:"protected_branches"`
	Capabilities      []string   `json:"capabilities"`
	Schedule          string     `json:"schedule"`
	Routing           string     `json:"routing"`
	Enabled           bool       `json:"enabled"`
	Source            string     `json:"source"`
	UpdatedAt         *time.Time `json:"updated_at,omitempty"`
}

// CodeScanBranchResponse is a branch and its baseline.
type CodeScanBranchResponse struct {
	Name                string     `json:"name"`
	IsDefault           bool       `json:"is_default"`
	Protected           bool       `json:"protected"`
	LastCommitSHA       string     `json:"last_commit_sha,omitempty"`
	BaselineState       string     `json:"baseline_state"`
	BaselineCommit      string     `json:"baseline_commit,omitempty"`
	BaselineAt          *time.Time `json:"baseline_at,omitempty"`
	BaselineError       string     `json:"baseline_error,omitempty"`
	LastFullScanAt      *time.Time `json:"last_full_scan_at,omitempty"`
	LastFullScanTrigger string     `json:"last_full_scan_trigger,omitempty"`
}

// CodeScanRepositoryResponse is one repository's code scanning.
type CodeScanRepositoryResponse struct {
	RepositoryAssetID string                   `json:"repository_asset_id"`
	Name              string                   `json:"name"`
	DefaultBranch     string                   `json:"default_branch,omitempty"`
	Visibility        string                   `json:"visibility,omitempty"`
	Settings          CodeScanSettingsResponse `json:"settings"`
	Branches          []CodeScanBranchResponse `json:"branches"`
	// Baseline counts the protected branches by baseline state.
	Baseline map[string]int `json:"baseline"`
}

// CodeScanRebaselineResponse says how many branches were queued.
type CodeScanRebaselineResponse struct {
	Queued     int                        `json:"queued"`
	Repository CodeScanRepositoryResponse `json:"repository"`
}

func toCodeScanSettings(s codescan.Settings, source string) CodeScanSettingsResponse {
	out := CodeScanSettingsResponse{ProtectedBranches: s.ProtectedBranches, Capabilities: s.Capabilities,
		Schedule: s.Schedule, Routing: s.Routing, Enabled: s.Enabled, Source: source}
	if !s.UpdatedAt.IsZero() {
		t := s.UpdatedAt
		out.UpdatedAt = &t
	}
	return out
}

func toCodeScanRepository(st *codescanapp.RepositoryStatus) CodeScanRepositoryResponse {
	out := CodeScanRepositoryResponse{RepositoryAssetID: st.Repository.AssetID.String(), Name: st.Repository.Name,
		DefaultBranch: st.Repository.DefaultBranch, Visibility: st.Repository.Visibility,
		Settings: toCodeScanSettings(st.Settings, st.Source), Branches: []CodeScanBranchResponse{}, Baseline: st.Summary()}
	for _, b := range st.Branches {
		out.Branches = append(out.Branches, CodeScanBranchResponse{Name: b.Name, IsDefault: b.IsDefault, Protected: b.Protected,
			LastCommitSHA: b.LastCommitSHA, BaselineState: b.BaselineState, BaselineCommit: b.BaselineCommit,
			BaselineAt: b.BaselineAt, BaselineError: b.BaselineError, LastFullScanAt: b.LastFullScanAt,
			LastFullScanTrigger: b.LastFullScanTrigger})
	}
	return out
}

func (h *CIAdminHandler) codeScanActor(r *http.Request) codescanapp.Actor {
	a := h.actor(r)
	return codescanapp.Actor{UserID: a.UserID, Email: a.Email, IP: a.IP, UserAgent: a.UserAgent}
}

func decodeCodeScanSettings(w http.ResponseWriter, r *http.Request) (codescanapp.SettingsInput, bool) {
	limitBody(w, r)
	var req CodeScanSettingsRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return codescanapp.SettingsInput{}, false
	}
	if len(req.ProtectedBranches) > 50 || len(req.Capabilities) > 8 {
		apierror.BadRequest("too many protected branches or capabilities").WriteJSON(w)
		return codescanapp.SettingsInput{}, false
	}
	return codescanapp.SettingsInput{ProtectedBranches: req.ProtectedBranches, Capabilities: req.Capabilities,
		Schedule: req.Schedule, Routing: req.Routing, Enabled: req.Enabled}, true
}

// GetCodeScanTemplate handles GET /api/v1/ci/code-scanning/settings
// @Summary      Get the code scanning template
// @Description  The settings a repository without its own inherits: protected branches, capabilities, schedule, routing. The built-in defaults (source "default") when the organization has not set any.
// @Tags         CI
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  CodeScanSettingsResponse
// @Router       /ci/code-scanning/settings [get]
func (h *CIAdminHandler) GetCodeScanTemplate(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenant(w, r)
	if !ok {
		return
	}
	if h.codeScan == nil {
		apierror.NotFound("Code scanning").WriteJSON(w)
		return
	}
	s, src, err := h.codeScan.Template(r.Context(), tenantID)
	if err != nil {
		h.writeErr(w, err, "get code scanning template", "Code scanning")
		return
	}
	ciWriteJSON(w, http.StatusOK, toCodeScanSettings(s, src))
}

// UpdateCodeScanTemplate handles PUT /api/v1/ci/code-scanning/settings
// @Summary      Set the code scanning template
// @Description  Audited. Repositories without their own settings use it from their next full scan.
// @Tags         CI
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        body body CodeScanSettingsRequest true "Settings"
// @Success      200  {object}  CodeScanSettingsResponse
// @Failure      400  {object}  apierror.Error
// @Router       /ci/code-scanning/settings [put]
func (h *CIAdminHandler) UpdateCodeScanTemplate(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenant(w, r)
	if !ok {
		return
	}
	if h.codeScan == nil {
		apierror.NotFound("Code scanning").WriteJSON(w)
		return
	}
	in, ok := decodeCodeScanSettings(w, r)
	if !ok {
		return
	}
	s, err := h.codeScan.UpdateTemplate(r.Context(), tenantID, in, h.codeScanActor(r))
	if err != nil {
		h.writeErr(w, err, "update code scanning template", "Code scanning")
		return
	}
	ciWriteJSON(w, http.StatusOK, toCodeScanSettings(s, codescan.SourceTemplate))
}

// ListCodeScanRepositories handles GET /api/v1/ci/code-scanning/repositories
// @Summary      List repositories with their code scanning
// @Description  The repositories in the caller's data scope, by name, each with its effective settings, its branches (protected ones marked) and the baseline of each.
// @Tags         CI
// @Produce      json
// @Security     BearerAuth
// @Param        page query int false "Page"
// @Param        per_page query int false "Per page (at most 100)"
// @Success      200  {object}  ListResponse[CodeScanRepositoryResponse]
// @Router       /ci/code-scanning/repositories [get]
func (h *CIAdminHandler) ListCodeScanRepositories(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenant(w, r)
	if !ok {
		return
	}
	if h.codeScan == nil {
		apierror.NotFound("Code scanning").WriteJSON(w)
		return
	}
	paging, ok := listPage(w, r, 25)
	if !ok {
		return
	}
	perPage := min(paging.PerPage, 100)
	scope, err := resolveDataScope(r.Context(), h.dataScope, tenantID)
	if err != nil {
		h.writeErr(w, err, "resolve data scope", "Repository")
		return
	}
	list, total, err := h.codeScan.ListRepositories(r.Context(), tenantID, scope, perPage, (paging.Page-1)*perPage)
	if err != nil {
		h.writeErr(w, err, "list code scanning repositories", "Repository")
		return
	}
	data := make([]CodeScanRepositoryResponse, 0, len(list))
	for i := range list {
		data = append(data, toCodeScanRepository(&list[i]))
	}
	pages := (total + perPage - 1) / perPage
	ciWriteJSON(w, http.StatusOK, ListResponse[CodeScanRepositoryResponse]{Data: data, Total: int64(total), Page: paging.Page,
		PerPage: perPage, TotalPages: pages, Links: NewPaginationLinks(r, paging.Page, perPage, pages)})
}

// codeScanRepository reads the path's repository id and checks the data
// scope: 404 outside it.
func (h *CIAdminHandler) codeScanRepository(w http.ResponseWriter, r *http.Request) (shared.ID, shared.ID, bool) {
	tenantID, ok := h.tenant(w, r)
	if !ok {
		return shared.ID{}, shared.ID{}, false
	}
	id, ok := pathID(w, r, "Repository")
	if !ok {
		return shared.ID{}, shared.ID{}, false
	}
	if h.codeScan == nil || !assetInDataScope(r.Context(), h.dataScope, tenantID, id) {
		apierror.NotFound("Repository").WriteJSON(w)
		return shared.ID{}, shared.ID{}, false
	}
	return tenantID, id, true
}

// GetCodeScanRepository handles GET /api/v1/ci/code-scanning/repositories/{id}
// @Summary      Get a repository's code scanning
// @Description  Effective settings (and their source), branches and baselines. 404 when the repository is outside the caller's data scope.
// @Tags         CI
// @Produce      json
// @Security     BearerAuth
// @Param        id path string true "Repository asset ID"
// @Success      200  {object}  CodeScanRepositoryResponse
// @Failure      404  {object}  apierror.Error
// @Router       /ci/code-scanning/repositories/{id} [get]
func (h *CIAdminHandler) GetCodeScanRepository(w http.ResponseWriter, r *http.Request) {
	tenantID, id, ok := h.codeScanRepository(w, r)
	if !ok {
		return
	}
	st, err := h.codeScan.Repository(r.Context(), tenantID, id)
	if err != nil {
		h.writeErr(w, err, "get code scanning", "Repository")
		return
	}
	ciWriteJSON(w, http.StatusOK, toCodeScanRepository(st))
}

// UpdateCodeScanRepository handles PUT /api/v1/ci/code-scanning/repositories/{id}/settings
// @Summary      Set a repository's code scanning settings
// @Description  Audited. The repository stops inheriting the template. 404 when it is outside the caller's data scope.
// @Tags         CI
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        id path string true "Repository asset ID"
// @Param        body body CodeScanSettingsRequest true "Settings"
// @Success      200  {object}  CodeScanRepositoryResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Router       /ci/code-scanning/repositories/{id}/settings [put]
func (h *CIAdminHandler) UpdateCodeScanRepository(w http.ResponseWriter, r *http.Request) {
	tenantID, id, ok := h.codeScanRepository(w, r)
	if !ok {
		return
	}
	in, ok := decodeCodeScanSettings(w, r)
	if !ok {
		return
	}
	st, err := h.codeScan.UpdateRepository(r.Context(), tenantID, id, in, h.codeScanActor(r))
	if err != nil {
		h.writeErr(w, err, "update code scanning", "Repository")
		return
	}
	ciWriteJSON(w, http.StatusOK, toCodeScanRepository(st))
}

// ResetCodeScanRepository handles DELETE /api/v1/ci/code-scanning/repositories/{id}/settings
// @Summary      Reset a repository's code scanning settings
// @Description  Audited. The repository inherits the organization's template again. 404 when it is outside the caller's data scope.
// @Tags         CI
// @Produce      json
// @Security     BearerAuth
// @Param        id path string true "Repository asset ID"
// @Success      200  {object}  CodeScanRepositoryResponse
// @Failure      404  {object}  apierror.Error
// @Router       /ci/code-scanning/repositories/{id}/settings [delete]
func (h *CIAdminHandler) ResetCodeScanRepository(w http.ResponseWriter, r *http.Request) {
	tenantID, id, ok := h.codeScanRepository(w, r)
	if !ok {
		return
	}
	st, err := h.codeScan.ResetRepository(r.Context(), tenantID, id, h.codeScanActor(r))
	if err != nil {
		h.writeErr(w, err, "reset code scanning", "Repository")
		return
	}
	ciWriteJSON(w, http.StatusOK, toCodeScanRepository(st))
}

// RebaselineCodeScanRepository handles POST /api/v1/ci/code-scanning/repositories/{id}/rebaseline
// @Summary      Re-baseline a repository now
// @Description  Audited. Queues a full scan of every known protected branch of the repository (its default branch is recorded first when no branch is known); branches already queued or running stay as they are. 409 when no known branch is protected, 400 when code scanning is off for the repository, 404 outside the caller's data scope.
// @Tags         CI
// @Produce      json
// @Security     BearerAuth
// @Param        id path string true "Repository asset ID"
// @Success      202  {object}  CodeScanRebaselineResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Router       /ci/code-scanning/repositories/{id}/rebaseline [post]
func (h *CIAdminHandler) RebaselineCodeScanRepository(w http.ResponseWriter, r *http.Request) {
	tenantID, id, ok := h.codeScanRepository(w, r)
	if !ok {
		return
	}
	n, st, err := h.codeScan.Rebaseline(r.Context(), tenantID, id, h.codeScanActor(r))
	if err != nil {
		h.writeErr(w, err, "re-baseline repository", "Repository")
		return
	}
	ciWriteJSON(w, http.StatusAccepted, CodeScanRebaselineResponse{Queued: n, Repository: toCodeScanRepository(st)})
}
