package handler

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/internal/app/ingest"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/internal/infra/scanner/nessus"
	"github.com/openctemio/api/pkg/apierror"
	"github.com/openctemio/api/pkg/domain/agent"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// AssetImportHandler handles bulk asset import endpoints.
type AssetImportHandler struct {
	service *app.AssetImportService
	ingest  *ingest.Service
	logger  *logger.Logger
}

// NewAssetImportHandler creates a new AssetImportHandler.
func NewAssetImportHandler(svc *app.AssetImportService, ingestSvc *ingest.Service, log *logger.Logger) *AssetImportHandler {
	return &AssetImportHandler{service: svc, ingest: ingestSvc, logger: log}
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

// IngestNessusFindings handles POST /api/v1/assets/import/nessus-findings.
//
// Unlike ImportNessus (which only creates host assets), this converts a
// .nessus export into a full CTIS report and ingests both assets AND
// vulnerability findings through the standard ingest pipeline. Each upload is
// one scan session/batch: stale Tenable findings on the uploaded hosts are
// auto-resolved, scoped to this batch only (tool + session id + asset set), so
// uploading one batch never resolves another batch's findings. This is the
// manual/cron entry point for license-aware rolling coverage (RFC-007) until
// the live Tenable connector lands.
//
// Query params: session_id (optional, default generated — unique per batch),
// tool (default "tenable"), min_severity (0..4, default 1 = skip info).
func (h *AssetImportHandler) IngestNessusFindings(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		apierror.BadRequest("invalid tenant").WriteJSON(w)
		return
	}

	// .nessus exports for a 500-host batch can be large.
	r.Body = http.MaxBytesReader(w, r.Body, 200*1024*1024)

	sessionID := r.URL.Query().Get("session_id")
	if sessionID == "" {
		sessionID = shared.NewID().String()
	}
	minSeverity := 1
	if v := r.URL.Query().Get("min_severity"); v != "" {
		if n, convErr := strconv.Atoi(v); convErr == nil && n >= 0 && n <= 4 {
			minSeverity = n
		}
	}

	report, err := nessus.Convert(r.Body, nessus.ConvertOptions{
		ScanSessionID: sessionID,
		ToolName:      r.URL.Query().Get("tool"),
		MinSeverity:   minSeverity,
	})
	if err != nil {
		apierror.BadRequest(err.Error()).WriteJSON(w)
		return
	}

	// Tenant-initiated upload (not an agent push): build a synthetic agent for
	// the tenant, mirroring the ingest job processor.
	agt := &agent.Agent{TenantID: &tid, Status: agent.AgentStatusActive}

	output, err := h.ingest.Ingest(r.Context(), agt, ingest.Input{Report: report})
	if err != nil {
		if strings.Contains(err.Error(), "validation") || strings.Contains(err.Error(), "INVALID") {
			apierror.BadRequest(err.Error()).WriteJSON(w)
			return
		}
		h.logger.Error("nessus findings ingest failed", "error", err)
		apierror.InternalServerError("ingest failed").WriteJSON(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"scan_session_id": sessionID,
		"result":          output,
	})
}

// ImportKubernetes handles POST /api/v1/assets/import/kubernetes
func (h *AssetImportHandler) ImportKubernetes(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	// Cap body at 10 MB — K8s cluster exports are structured data, not
	// binary blobs; even a large cluster fits. Unbounded body + decode
	// would let an attacker OOM the process with a multi-GB JSON.
	r.Body = http.MaxBytesReader(w, r.Body, 10<<20)

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
