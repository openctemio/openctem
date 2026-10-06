package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/openctemio/openctem/api/internal/app/asset"
	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/datascope"
	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/scanner/nessus"
	"github.com/openctemio/openctem/api/pkg/apierror"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// AssetImportHandler handles bulk asset import endpoints.
type AssetImportHandler struct {
	service      *asset.AssetImportService
	ingest       *ingest.Service
	logger       *logger.Logger
	auditService *auditapp.AuditService
	dataScope    *datascope.Enforcer
}

// SetDataScope wires the caller's data scope into the Nessus findings
// upload. Without it the upload is refused (fail closed).
func (h *AssetImportHandler) SetDataScope(e *datascope.Enforcer) {
	h.dataScope = e
}

// uploaderScope is the data scope of a person uploading a report, as the
// ingest service consumes it.
type uploaderScope struct {
	enforcer *datascope.Enforcer
	scope    *shared.DataScope
}

func (u uploaderScope) AssetsInScope(ctx context.Context, ids []shared.ID) ([]shared.ID, error) {
	admit, err := u.enforcer.Filter(ctx, u.scope, ids)
	if err != nil {
		return nil, err
	}
	out := make([]shared.ID, 0, len(ids))
	for _, id := range ids {
		if admit(id) {
			out = append(out, id)
		}
	}
	return out, nil
}

// defaultNessusTool is the tool name the converter uses without ?tool=.
const defaultNessusTool = "tenable"

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

// auditNessusFindings records a Nessus findings upload (counts only).
func (h *AssetImportHandler) auditNessusFindings(r *http.Request, restricted bool, out *ingest.Output) {
	if h.auditService == nil || out == nil {
		return
	}
	event := auditapp.NewSuccessEvent(auditdom.ActionAssetImported, auditdom.ResourceTypeAsset, "").
		WithMessage("Findings imported from a Nessus upload").
		WithSeverity(auditdom.SeverityForAction(auditdom.ActionAssetImported)).
		WithMetadata("source", "nessus_findings").
		WithMetadata("restricted_uploader", restricted).
		WithMetadata("assets_created", out.AssetsCreated).
		WithMetadata("assets_updated", out.AssetsUpdated).
		WithMetadata("assets_skipped_out_of_scope", out.AssetsSkippedOutOfScope).
		WithMetadata("findings_created", out.FindingsCreated).
		WithMetadata("findings_updated", out.FindingsUpdated).
		WithMetadata("findings_auto_resolved", out.FindingsAutoResolved)
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
func NewAssetImportHandler(svc *asset.AssetImportService, ingestSvc *ingest.Service, log *logger.Logger) *AssetImportHandler {
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
	h.auditImport(r, "csv", result)

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
	h.auditImport(r, "nessus", result)

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
//
// The upload runs with the uploader's rights, never a sensor's (research
// doc 15, L-05):
//   - a person with a limited data scope only adds findings to existing
//     assets in their scope; other hosts (hidden or unknown alike) are
//     skipped and counted as assets_skipped_out_of_scope, and the upload
//     never auto-resolves anything;
//   - an unrestricted person (owner, admin, full-data role) auto-resolves
//     only Tenable findings:
//     with any other ?tool= the batch is treated as partial coverage, so the
//     tool name a person types cannot close another scanner's findings.
func (h *AssetImportHandler) IngestNessusFindings(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		apierror.BadRequest("invalid tenant").WriteJSON(w)
		return
	}
	if h.dataScope == nil {
		h.logger.Error("nessus findings upload refused: data scope not configured")
		apierror.InternalServerError("ingest failed").WriteJSON(w)
		return
	}
	scope, err := h.dataScope.Resolve(r.Context(), tid)
	if err != nil {
		h.logger.Error("nessus findings upload: resolve data scope", "error", err)
		apierror.InternalServerError("ingest failed").WriteJSON(w)
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

	toolName := strings.TrimSpace(r.URL.Query().Get("tool"))
	report, err := nessus.Convert(r.Body, nessus.ConvertOptions{
		ScanSessionID: sessionID,
		ToolName:      toolName,
		MinSeverity:   minSeverity,
	})
	if err != nil {
		apierror.BadRequest(err.Error()).WriteJSON(w)
		return
	}

	input := ingest.Input{Report: report}
	if scope != nil {
		input.Options.Actor = uploaderScope{enforcer: h.dataScope, scope: scope}
	}
	if scope != nil || (toolName != "" && !strings.EqualFold(toolName, defaultNessusTool)) {
		// No auto-resolve: a restricted uploader never closes findings, and
		// a typed tool name is not trusted to choose whose findings close.
		input.CoverageType = ingest.CoverageTypePartial
	}

	// The ingest service takes its tenant from a sensor record; this one
	// only carries the tenant. The uploader's rights come from Actor and
	// the coverage above, not from the record.
	agt := &sensor.Sensor{TenantID: &tid, Status: sensor.SensorStatusActive}

	output, err := h.ingest.Ingest(r.Context(), agt, input)
	if err != nil {
		if strings.Contains(err.Error(), "validation") || strings.Contains(err.Error(), "INVALID") {
			apierror.BadRequest(err.Error()).WriteJSON(w)
			return
		}
		h.logger.Error("nessus findings ingest failed", "error", err)
		apierror.InternalServerError("ingest failed").WriteJSON(w)
		return
	}

	h.auditNessusFindings(r, scope != nil, output)

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

	var input asset.K8sDiscoveryInput
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
	h.auditImport(r, "kubernetes", result)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(result)
}
