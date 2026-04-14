package handler

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/apierror"
	"github.com/openctemio/api/pkg/logger"
)

// AssetImportHandler handles bulk asset import endpoints.
type AssetImportHandler struct {
	service *app.AssetImportService
	logger  *logger.Logger
}

// NewAssetImportHandler creates a new AssetImportHandler.
func NewAssetImportHandler(svc *app.AssetImportService, log *logger.Logger) *AssetImportHandler {
	return &AssetImportHandler{service: svc, logger: log}
}

// ImportCSV handles POST /api/v1/assets/import/csv
func (h *AssetImportHandler) ImportCSV(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	// Limit body to 50MB
	r.Body = http.MaxBytesReader(w, r.Body, 50*1024*1024)

	result, err := h.service.ImportCSVAssets(r.Context(), tenantID, r.Body)
	if err != nil {
		if strings.Contains(err.Error(), "validation") {
			apierror.BadRequest(err.Error()).WriteJSON(w)
		} else {
			h.logger.Error("CSV import failed", "error", err)
			apierror.InternalServerError("import failed").WriteJSON(w)
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(result)
}

// ImportNessus handles POST /api/v1/assets/import/nessus
func (h *AssetImportHandler) ImportNessus(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	// Limit body to 100MB
	r.Body = http.MaxBytesReader(w, r.Body, 100*1024*1024)

	result, err := h.service.ImportNessus(r.Context(), tenantID, r.Body)
	if err != nil {
		if strings.Contains(err.Error(), "validation") {
			apierror.BadRequest(err.Error()).WriteJSON(w)
		} else {
			h.logger.Error("Nessus import failed", "error", err)
			apierror.InternalServerError("import failed").WriteJSON(w)
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(result)
}

// ImportKubernetes handles POST /api/v1/assets/import/kubernetes
func (h *AssetImportHandler) ImportKubernetes(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	var input app.K8sDiscoveryInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}

	result, err := h.service.ImportKubernetes(r.Context(), tenantID, input)
	if err != nil {
		if strings.Contains(err.Error(), "validation") {
			apierror.BadRequest(err.Error()).WriteJSON(w)
		} else {
			h.logger.Error("Kubernetes import failed", "error", err)
			apierror.InternalServerError("import failed").WriteJSON(w)
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(result)
}
