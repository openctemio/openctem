package handler

// A repository's effective CI gate settings and where each value comes from
// (docs/rfcs/RFC-095-ci-per-repository-settings.md).

import (
	"context"
	"net/http"
	"time"

	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// CIRepositorySettingsService resolves a repository's effective gate policy.
type CIRepositorySettingsService interface {
	ResolveRepositoryPolicy(ctx context.Context, tenantID, assetID shared.ID) (cirun.Resolution, error)
}

// SetRepositorySettingsService wires the repository settings endpoint (nil
// leaves it 404).
func (h *CIAdminHandler) SetRepositorySettingsService(s CIRepositorySettingsService) {
	h.repoSettings = s
}

// CIRepositorySettingField is one gate setting of a repository.
type CIRepositorySettingField struct {
	Field string `json:"field"`
	// Value is the effective value; Inherited what applies without the
	// repository's own policy.
	Value     any `json:"value"`
	Inherited any `json:"inherited"`
	// Source: default, tenant, business_unit or repository.
	Source   string `json:"source"`
	PolicyID string `json:"policy_id,omitempty"`
	// LockedBy names the layer that locks the field (only stricter values
	// below it); empty when unlocked.
	LockedBy string `json:"locked_by,omitempty"`
	// Ignored: a looser value set below a lock, not applied.
	Ignored bool `json:"ignored,omitempty"`
}

// CIRepositorySettingsResponse is a repository's effective gate settings.
type CIRepositorySettingsResponse struct {
	RepositoryAssetID string                     `json:"repository_asset_id"`
	Source            string                     `json:"source"`
	Fields            []CIRepositorySettingField `json:"fields"`
	// Repository is the repository's own policy, when it has one.
	Repository *CIGatePolicyResponse `json:"repository,omitempty"`
	// Expired: the repository policy has expired and no longer applies.
	Expired   bool      `json:"expired,omitempty"`
	CheckedAt time.Time `json:"checked_at"`
}

// GetRepositorySettings handles GET /api/v1/ci/gate-settings/{id}
// @Summary      A repository's effective CI gate settings
// @Description  Every gate setting with its effective value, the value inherited without the repository's own policy, the layer it comes from (default, tenant, business_unit, repository) and any lock. The gate judges the repository's runs with exactly these values. 404 when the repository is outside the caller's data scope.
// @Tags         CI
// @Produce      json
// @Security     BearerAuth
// @Param        id path string true "Repository asset ID"
// @Success      200  {object}  CIRepositorySettingsResponse
// @Failure      404  {object}  apierror.Error
// @Router       /ci/gate-settings/{id} [get]
func (h *CIAdminHandler) GetRepositorySettings(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenant(w, r)
	if !ok {
		return
	}
	id, ok := pathID(w, r, "Repository")
	if !ok {
		return
	}
	if h.repoSettings == nil || !assetInDataScope(r.Context(), h.dataScope, tenantID, id) {
		apierror.NotFound("Repository").WriteJSON(w)
		return
	}
	res, err := h.repoSettings.ResolveRepositoryPolicy(r.Context(), tenantID, id)
	if err != nil {
		h.writeErr(w, err, "resolve repository settings", "Repository")
		return
	}
	out := CIRepositorySettingsResponse{RepositoryAssetID: id.String(), Source: res.Source, Expired: res.RepositoryExpired,
		Fields: make([]CIRepositorySettingField, 0, len(res.Fields)), CheckedAt: time.Now().UTC()}
	for _, f := range res.Fields {
		item := CIRepositorySettingField{Field: f.Field, Value: cirun.FieldValue(res.Policy, f.Field),
			Inherited: cirun.FieldValue(res.Inherited, f.Field), Source: f.Source, LockedBy: f.LockedBy, Ignored: f.Ignored}
		if f.PolicyID != nil {
			item.PolicyID = f.PolicyID.String()
		}
		out.Fields = append(out.Fields, item)
	}
	if res.Repository != nil {
		p := toCIPolicyResponse(res.Repository)
		out.Repository = &p
	}
	ciWriteJSON(w, http.StatusOK, out)
}
