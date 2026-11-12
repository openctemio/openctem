package handler

// POST /api/v1/integrations/{id}/scans/run: scan chosen assets now with a
// Tenable.sc connector (architecture: docs/architecture/tenable-sc-connector.md,
// "Scan now and rescan after a fix").

import (
	"encoding/json"
	"errors"
	"net/http"

	scansvc "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/internal/app/tenablesc"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ConnectorScanNowRequest names the assets to scan.
type ConnectorScanNowRequest struct {
	// AssetIDs are inventory assets of the organization in the caller's data
	// scope; each is scanned by its name (1 to 50).
	AssetIDs []string `json:"asset_ids"`
}

// ConnectorScanNow handles POST /api/v1/integrations/{id}/scans/run
// @Summary      Scan assets now with a Tenable.sc connector
// @Description  Scans the assets now through the Tenable.sc connector integration, with the connector's coverage scan policy, repository and zone, as a manual run by the caller. Every gate of a scan run applies (act scope, active-probe gate, scan windows, scan approval). An asset that is not the organization's or not in the caller's data scope, and another organization's integration, answer 404.
// @Tags         Integrations
// @Accept       json
// @Produce      json
// @Param        id       path      string                   true  "Integration ID"  format(uuid)
// @Param        request  body      ConnectorScanNowRequest  true  "Assets to scan"
// @Success      201  {object}  RunResponse
// @Failure      400  {object}  apierror.Error  "validation, or the connector has no coverage policy and repository"
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error  "integration or asset not found"
// @Failure      409  {object}  apierror.Error  "the connector cannot run the scan now (sensor, disabled, grant)"
// @Security     BearerAuth
// @Router       /integrations/{id}/scans/run [post]
func (h *ScanHandler) ConnectorScanNow(w http.ResponseWriter, r *http.Request) {
	tid, err := shared.IDFromString(middleware.MustGetTenantID(r.Context()))
	if err != nil {
		apierror.Unauthorized("Invalid tenant").WriteJSON(w)
		return
	}
	uid, err := shared.IDFromString(middleware.GetUserID(r.Context()))
	if err != nil {
		apierror.Unauthorized("").WriteJSON(w)
		return
	}
	iid, err := shared.IDFromString(r.PathValue("id"))
	if err != nil {
		apierror.BadRequest("Invalid integration ID").WriteJSON(w)
		return
	}
	var req ConnectorScanNowRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	if len(req.AssetIDs) == 0 || len(req.AssetIDs) > scansvc.MaxConnectorScanNowAssets {
		apierror.BadRequest("asset_ids takes 1 to 50 assets").WriteJSON(w)
		return
	}
	ids := make([]shared.ID, 0, len(req.AssetIDs))
	for _, raw := range req.AssetIDs {
		id, err := shared.IDFromString(raw)
		if err != nil {
			apierror.BadRequest("asset_ids must be UUIDs").WriteJSON(w)
			return
		}
		ids = append(ids, id)
	}

	run, err := h.service.StartConnectorScan(r.Context(), scansvc.ConnectorScanNowInput{
		TenantID: tid, UserID: uid, IntegrationID: iid, AssetIDs: ids,
	})
	if err != nil {
		h.connectorScanNowError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(toRunResponse(run))
}

// connectorScanNowError: not found names the integration or asset; the
// connector's own refusals keep their codes as 409; the rest is a scan
// trigger's answer.
func (h *ScanHandler) connectorScanNowError(w http.ResponseWriter, err error) {
	var de *shared.DomainError
	switch {
	case errors.Is(err, scansvc.ErrConnectorAssetsNotFound):
		apierror.NotFound("Asset").WriteJSON(w)
	case errors.Is(err, shared.ErrNotFound):
		// Another organization's integration, or one that is not a
		// Tenable.sc connector.
		apierror.NotFound("Integration").WriteJSON(w)
	case errors.Is(err, tenablesc.ErrSensorUnavailable), errors.Is(err, tenablesc.ErrDisabled),
		errors.Is(err, scansvc.ErrConnectorScansUnavailable), tenablesc.IsGrantRefusal(err),
		errors.Is(err, scansvc.ErrOnDemandScanNameTaken):
		_ = errors.As(err, &de)
		apierror.New(http.StatusConflict, apierror.Code(de.Code), de.Message).WriteJSON(w)
	default:
		h.handleServiceError(w, err)
	}
}
