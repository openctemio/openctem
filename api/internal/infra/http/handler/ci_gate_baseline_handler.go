package handler

// The gate baseline of a repository
// (docs/rfcs/RFC-051-ci-runner-identity-and-gate.md, "Gate baseline").

import (
	"context"
	"net/http"
	"time"

	cirunapp "github.com/openctemio/openctem/api/internal/app/cirun"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// CIGateBaselineService records and removes repositories' gate baselines.
type CIGateBaselineService interface {
	GetGateBaseline(ctx context.Context, tenantID, assetID shared.ID) (*cirun.GateBaseline, error)
	SetGateBaseline(ctx context.Context, tenantID, assetID shared.ID, a cirunapp.Actor) (*cirun.GateBaseline, error)
	DeleteGateBaseline(ctx context.Context, tenantID, assetID shared.ID, a cirunapp.Actor) error
}

// SetGateBaselineService wires the gate baseline endpoints (nil leaves them
// 404).
func (h *CIAdminHandler) SetGateBaselineService(s CIGateBaselineService) { h.baseline = s }

// CIGateBaselineResponse is a repository's gate baseline.
type CIGateBaselineResponse struct {
	RepositoryAssetID string `json:"repository_asset_id"`
	// Source: manual (recorded by a person).
	Source string `json:"source"`
	// Branch is the default branch whose open findings were recorded.
	Branch        string    `json:"branch,omitempty"`
	FindingsCount int       `json:"findings_count"`
	SetBy         string    `json:"set_by,omitempty"`
	SetAt         time.Time `json:"set_at"`
}

func toCIGateBaseline(b *cirun.GateBaseline) CIGateBaselineResponse {
	out := CIGateBaselineResponse{RepositoryAssetID: b.RepositoryAssetID.String(), Source: b.Source, Branch: b.Branch,
		FindingsCount: b.FindingsCount, SetAt: b.SetAt}
	if b.SetBy != nil {
		out.SetBy = b.SetBy.String()
	}
	return out
}

// baselineRepository reads the repository id of the path and checks the
// caller may see it (404 otherwise, as for any asset out of their scope).
func (h *CIAdminHandler) baselineRepository(w http.ResponseWriter, r *http.Request) (shared.ID, shared.ID, bool) {
	tenantID, ok := h.tenant(w, r)
	if !ok {
		return shared.ID{}, shared.ID{}, false
	}
	id, ok := pathID(w, r, "Repository")
	if !ok {
		return shared.ID{}, shared.ID{}, false
	}
	if h.baseline == nil || !assetInDataScope(r.Context(), h.dataScope, tenantID, id) {
		apierror.NotFound("Repository").WriteJSON(w)
		return shared.ID{}, shared.ID{}, false
	}
	return tenantID, id, true
}

// GetGateBaseline handles GET /api/v1/ci/gate-baselines/{id}
// @Summary      A repository's CI gate baseline
// @Description  The findings open on the repository's default branch when an administrator recorded them. A default-branch run is judged against it only; 404 when none is recorded (every finding of a default-branch run counts as new) or the repository is outside the caller's data scope.
// @Tags         CI
// @Produce      json
// @Security     BearerAuth
// @Param        id path string true "Repository asset ID"
// @Success      200  {object}  CIGateBaselineResponse
// @Failure      404  {object}  apierror.Error
// @Router       /ci/gate-baselines/{id} [get]
func (h *CIAdminHandler) GetGateBaseline(w http.ResponseWriter, r *http.Request) {
	tenantID, id, ok := h.baselineRepository(w, r)
	if !ok {
		return
	}
	b, err := h.baseline.GetGateBaseline(r.Context(), tenantID, id)
	if err != nil {
		h.writeErr(w, err, "read gate baseline", "Gate baseline")
		return
	}
	ciWriteJSON(w, http.StatusOK, toCIGateBaseline(b))
}

// SetGateBaseline handles PUT /api/v1/ci/gate-baselines/{id}
// @Summary      Record a repository's CI gate baseline now
// @Description  Records the findings open now on the repository's default branch; they stop failing default-branch runs and the gate then blocks only findings new since. Replaces an earlier baseline. Needs a recent sign-in; audited at high severity and announced to the administrators. Nothing a CI job sends can record or change a baseline.
// @Tags         CI
// @Produce      json
// @Security     BearerAuth
// @Param        id path string true "Repository asset ID"
// @Success      200  {object}  CIGateBaselineResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Router       /ci/gate-baselines/{id} [put]
func (h *CIAdminHandler) SetGateBaseline(w http.ResponseWriter, r *http.Request) {
	tenantID, id, ok := h.baselineRepository(w, r)
	if !ok {
		return
	}
	b, err := h.baseline.SetGateBaseline(r.Context(), tenantID, id, h.actor(r))
	if err != nil {
		h.writeErr(w, err, "record gate baseline", "Repository")
		return
	}
	ciWriteJSON(w, http.StatusOK, toCIGateBaseline(b))
}

// DeleteGateBaseline handles DELETE /api/v1/ci/gate-baselines/{id}
// @Summary      Remove a repository's CI gate baseline
// @Description  Every finding of a default-branch run counts as new again (stricter). Audited.
// @Tags         CI
// @Security     BearerAuth
// @Param        id path string true "Repository asset ID"
// @Success      204
// @Failure      404  {object}  apierror.Error
// @Router       /ci/gate-baselines/{id} [delete]
func (h *CIAdminHandler) DeleteGateBaseline(w http.ResponseWriter, r *http.Request) {
	tenantID, id, ok := h.baselineRepository(w, r)
	if !ok {
		return
	}
	if err := h.baseline.DeleteGateBaseline(r.Context(), tenantID, id, h.actor(r)); err != nil {
		h.writeErr(w, err, "remove gate baseline", "Gate baseline")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
