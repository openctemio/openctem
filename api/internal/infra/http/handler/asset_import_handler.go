package handler

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/openctemio/openctem/api/internal/app/asset"
	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// AssetImportHandler handles bulk asset import endpoints.
type AssetImportHandler struct {
	service      *asset.AssetImportService
	logger       *logger.Logger
	auditService *auditapp.AuditService
}

// SetAuditService wires the audit logger: every import records who imported
// what and how many assets it created or updated.
func (h *AssetImportHandler) SetAuditService(svc *auditapp.AuditService) {
	h.auditService = svc
}

// auditImport records a finished import (counts only, never row data).
func (h *AssetImportHandler) auditImport(r *http.Request, source string, result *asset.AssetImportResult) {
	if h.auditService == nil || result == nil {
		return
	}
	event := auditapp.NewSuccessEvent(auditdom.ActionAssetImported, auditdom.ResourceTypeAsset, "").
		WithMessage("Assets imported from "+source).
		WithSeverity(auditdom.SeverityForAction(auditdom.ActionAssetImported)).
		WithMetadata("source", source).
		WithMetadata("created", result.AssetsCreated).
		WithMetadata("updated", result.AssetsUpdated).
		WithMetadata("skipped", result.AssetsSkipped).
		WithMetadata("errors", len(result.Errors))
	actx := auditapp.AuditContext{
		TenantID:   middleware.GetTenantID(r.Context()),
		ActorID:    middleware.GetUserID(r.Context()),
		ActorEmail: auditActorEmail(r.Context()),
		ActorIP:    getClientIP(r),
		UserAgent:  r.UserAgent(),
		RequestID:  r.Header.Get("X-Request-ID"),
	}
	_ = h.auditService.LogEvent(r.Context(), actx, event)
}

// NewAssetImportHandler creates a new AssetImportHandler.
func NewAssetImportHandler(svc *asset.AssetImportService, log *logger.Logger) *AssetImportHandler {
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
	h.auditImport(r, "csv", result)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(result)
}
