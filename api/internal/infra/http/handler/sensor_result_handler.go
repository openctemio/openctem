package handler

// Sensor results without a command (docs/rfcs/RFC-040-platform-sensor-mutual-distrust.md
// §5.3, owner decision Q6 (a)): the tenant policy and the review of the
// quarantine.

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/openctemio/ctis"

	auditsvc "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/sensorresult"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// SensorResultHandler serves the policy and quarantine review endpoints.
type SensorResultHandler struct {
	service *ingest.Service
	audit   func(r *http.Request) *auditsvc.AuditContext
	logger  *logger.Logger
}

// NewSensorResultHandler creates the handler. sensors provides the audit
// context of a request.
func NewSensorResultHandler(svc *ingest.Service, sensors *SensorHandler, log *logger.Logger) *SensorResultHandler {
	return &SensorResultHandler{service: svc, audit: sensors.buildAuditContext, logger: log.With("handler", "sensor_results")}
}

// SensorResultPolicyResponse is GET/PUT /sensors/result-policy.
type SensorResultPolicyResponse struct {
	// Mode is what happens to a report that names no command from a sensor
	// whose role may not push results on its own (every role but collector
	// and runner): "warn" applies it with limits and audits it, "quarantine"
	// holds it for review.
	Mode string `json:"mode" enums:"warn,quarantine"`
	// AllowAdvisoryEvidence accepts validation evidence without the validate
	// command assigned to the sensor (recorded as advisory, never changes the
	// finding).
	AllowAdvisoryEvidence bool `json:"allow_advisory_evidence"`
	// DefaultMode is the mode of a tenant that never set one.
	DefaultMode string `json:"default_mode"`
	// UpdatedAt / UpdatedBy are null while the tenant uses the defaults.
	UpdatedAt *string `json:"updated_at"`
	UpdatedBy *string `json:"updated_by"`
}

// UpdateSensorResultPolicyRequest is the PUT body.
type UpdateSensorResultPolicyRequest struct {
	Mode                  string `json:"mode" enums:"warn,quarantine"`
	AllowAdvisoryEvidence bool   `json:"allow_advisory_evidence"`
}

// QuarantinedResultResponse is one quarantined report.
type QuarantinedResultResponse struct {
	ID            string `json:"id"`
	SensorID      string `json:"sensor_id"`
	SensorName    string `json:"sensor_name"`
	SensorType    string `json:"sensor_type"`
	Protocol      string `json:"protocol" enums:"v1,v2"`
	Route         string `json:"route"`
	ReportID      string `json:"report_id"`
	Segment       *int   `json:"segment,omitempty"`
	ToolName      string `json:"tool_name"`
	Reason        string `json:"reason" enums:"no_command"`
	AssetsCount   int    `json:"assets_count"`
	FindingsCount int    `json:"findings_count"`
	PayloadSize   int    `json:"payload_size"`
	Status        string `json:"status" enums:"pending,accepted,discarded"`
	CreatedAt     string `json:"created_at"`
	ReviewedBy    string `json:"reviewed_by,omitempty"`
	ReviewedAt    string `json:"reviewed_at,omitempty"`
	// Result is what applying an accepted report did.
	Result map[string]any `json:"result,omitempty"`
}

// QuarantinedResultDetailResponse is one quarantined report with a preview of
// what it would write.
type QuarantinedResultDetailResponse struct {
	QuarantinedResultResponse
	// Preview lists the report's assets and findings (at most 100 of each);
	// absent once the report was discarded.
	Preview *QuarantinePreview `json:"preview,omitempty"`
}

// QuarantinePreview is a bounded summary of a quarantined report.
type QuarantinePreview struct {
	Assets         []QuarantinePreviewAsset   `json:"assets"`
	Findings       []QuarantinePreviewFinding `json:"findings"`
	AssetsOmitted  int                        `json:"assets_omitted"`
	FindingOmitted int                        `json:"findings_omitted"`
}

// QuarantinePreviewAsset is one asset of a quarantined report.
type QuarantinePreviewAsset struct {
	Ref   string `json:"ref"`
	Type  string `json:"type"`
	Value string `json:"value"`
}

// QuarantinePreviewFinding is one finding of a quarantined report.
type QuarantinePreviewFinding struct {
	Title    string `json:"title"`
	Severity string `json:"severity"`
	RuleID   string `json:"rule_id,omitempty"`
	AssetRef string `json:"asset_ref,omitempty"`
}

// AcceptQuarantinedResultResponse is what applying an accepted report did.
type AcceptQuarantinedResultResponse struct {
	AssetsCreated        int      `json:"assets_created"`
	AssetsUpdated        int      `json:"assets_updated"`
	FindingsCreated      int      `json:"findings_created"`
	FindingsUpdated      int      `json:"findings_updated"`
	FindingsAutoReopened int      `json:"findings_auto_reopened"`
	Errors               []string `json:"errors,omitempty"`
}

// GetPolicy handles GET /api/v1/sensors/result-policy
// @Summary      Get the policy for sensor results without a command
// @Description  What happens to a report that names no command (RFC-040 §5.3). Collector and CI runner sensors may always push results on their own; they are applied with limits (no change to existing assets, no reopening of findings a person resolved). For every other role the mode decides: warn applies them with the same limits and audits them, quarantine holds them for review. Tenants created before this policy existed are on warn; new tenants default to quarantine.
// @Tags         Sensors
// @Produce      json
// @Success      200  {object}  SensorResultPolicyResponse
// @Failure      401  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /sensors/result-policy [get]
func (h *SensorResultHandler) GetPolicy(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := resultTenant(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, resultPolicyResponse(h.service.ResultPolicy(r.Context(), tenantID)))
}

// UpdatePolicy handles PUT /api/v1/sensors/result-policy
// @Summary      Update the policy for sensor results without a command
// @Description  Set the mode (warn or quarantine) and whether advisory validation evidence is accepted. Audited.
// @Tags         Sensors
// @Accept       json
// @Produce      json
// @Param        body  body      UpdateSensorResultPolicyRequest  true  "Policy"
// @Success      200   {object}  SensorResultPolicyResponse
// @Failure      400   {object}  apierror.Error
// @Failure      403   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /sensors/result-policy [put]
func (h *SensorResultHandler) UpdatePolicy(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := resultTenant(w, r)
	if !ok {
		return
	}
	userID, ok := resultUser(w, r)
	if !ok {
		return
	}
	var req UpdateSensorResultPolicyRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	mode, err := sensorresult.ParseMode(req.Mode)
	if err != nil {
		apierror.BadRequest(err.Error()).WriteJSON(w)
		return
	}
	p, err := h.service.UpdateResultPolicy(r.Context(), *h.audit(r), tenantID, mode, req.AllowAdvisoryEvidence, userID)
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, resultPolicyResponse(p))
}

// List handles GET /api/v1/sensors/quarantined-results
// @Summary      List quarantined sensor results
// @Description  Reports that named no command, from a sensor whose role may not push results on its own, held for review (newest first). The payload is not included; GET one item for a preview.
// @Tags         Sensors
// @Produce      json
// @Param        status     query     string  false  "pending, accepted or discarded (default: every status)"
// @Param        sensor_id  query     string  false  "Only this sensor's reports"
// @Param        page       query     int     false  "Page number" default(1)
// @Param        per_page   query     int     false  "Items per page (max 100)" default(25)
// @Success      200  {object}  ListResponse[QuarantinedResultResponse]
// @Failure      400  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /sensors/quarantined-results [get]
func (h *SensorResultHandler) List(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := resultTenant(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	paging, ok := listPage(w, r, 25)
	if !ok {
		return
	}
	f := sensorresult.ListFilter{Page: paging.Page, PerPage: paging.PerPage}
	if v := q.Get("status"); v != "" {
		st, err := sensorresult.ParseStatus(v)
		if err != nil {
			apierror.BadRequest(err.Error()).WriteJSON(w)
			return
		}
		f.Status = st
	}
	if v := q.Get("sensor_id"); v != "" {
		id, err := shared.IDFromString(v)
		if err != nil {
			apierror.BadRequest("sensor_id must be a valid id").WriteJSON(w)
			return
		}
		f.SensorID = &id
	}
	items, total, err := h.service.ListQuarantined(r.Context(), tenantID, f)
	if err != nil {
		h.fail(w, err)
		return
	}
	out := make([]QuarantinedResultResponse, 0, len(items))
	for i := range items {
		out = append(out, quarantinedResponse(&items[i]))
	}
	totalPages := (total + f.PerPage - 1) / f.PerPage
	writeJSON(w, http.StatusOK, ListResponse[QuarantinedResultResponse]{
		Data: out, Total: int64(total), Page: f.Page, PerPage: f.PerPage, TotalPages: totalPages,
		Links: NewPaginationLinks(r, f.Page, f.PerPage, totalPages),
	})
}

// Get handles GET /api/v1/sensors/quarantined-results/{qid}
// @Summary      Get a quarantined sensor report
// @Description  One quarantined report with a preview of its assets and findings (at most 100 of each).
// @Tags         Sensors
// @Produce      json
// @Param        qid  path      string  true  "Quarantine item ID"
// @Success      200  {object}  QuarantinedResultDetailResponse
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /sensors/quarantined-results/{qid} [get]
func (h *SensorResultHandler) Get(w http.ResponseWriter, r *http.Request) {
	tenantID, id, ok := h.itemRef(w, r)
	if !ok {
		return
	}
	item, err := h.service.GetQuarantined(r.Context(), tenantID, id)
	if err != nil {
		h.fail(w, err)
		return
	}
	resp := QuarantinedResultDetailResponse{QuarantinedResultResponse: quarantinedResponse(item)}
	if len(item.Payload) > 0 {
		resp.Preview = previewOf(item.Payload)
	}
	writeJSON(w, http.StatusOK, resp)
}

// Accept handles POST /api/v1/sensors/quarantined-results/{qid}/approve
// @Summary      Accept a quarantined sensor report
// @Description  Apply the report as a person's decision: it may change the existing assets it names and reopen findings, but never auto-resolves anything. Applied once; a second accept or an accept after a discard is 409. Audited.
// @Tags         Sensors
// @Produce      json
// @Param        qid  path      string  true  "Quarantine item ID"
// @Success      200  {object}  AcceptQuarantinedResultResponse
// @Failure      404  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /sensors/quarantined-results/{qid}/approve [post]
func (h *SensorResultHandler) Accept(w http.ResponseWriter, r *http.Request) {
	tenantID, id, ok := h.itemRef(w, r)
	if !ok {
		return
	}
	userID, ok := resultUser(w, r)
	if !ok {
		return
	}
	out, err := h.service.AcceptQuarantined(r.Context(), *h.audit(r), tenantID, id, userID)
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, AcceptQuarantinedResultResponse{
		AssetsCreated: out.AssetsCreated, AssetsUpdated: out.AssetsUpdated,
		FindingsCreated: out.FindingsCreated, FindingsUpdated: out.FindingsUpdated,
		FindingsAutoReopened: out.FindingsAutoReopened, Errors: out.Errors,
	})
}

// Discard handles POST /api/v1/sensors/quarantined-results/{qid}/reject
// @Summary      Discard a quarantined sensor report
// @Description  Drop the report without applying it; its payload is deleted. 409 when it was already reviewed. Audited.
// @Tags         Sensors
// @Param        qid  path  string  true  "Quarantine item ID"
// @Success      204
// @Failure      404  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /sensors/quarantined-results/{qid}/reject [post]
func (h *SensorResultHandler) Discard(w http.ResponseWriter, r *http.Request) {
	tenantID, id, ok := h.itemRef(w, r)
	if !ok {
		return
	}
	userID, ok := resultUser(w, r)
	if !ok {
		return
	}
	if err := h.service.DiscardQuarantined(r.Context(), *h.audit(r), tenantID, id, userID); err != nil {
		h.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *SensorResultHandler) itemRef(w http.ResponseWriter, r *http.Request) (shared.ID, shared.ID, bool) {
	tenantID, ok := resultTenant(w, r)
	if !ok {
		return shared.ID{}, shared.ID{}, false
	}
	id, err := shared.IDFromString(chi.URLParam(r, "qid"))
	if err != nil {
		apierror.NotFound("Quarantined result").WriteJSON(w)
		return shared.ID{}, shared.ID{}, false
	}
	return tenantID, id, true
}

func (h *SensorResultHandler) fail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ingest.ErrQuarantineUnavailable):
		apierror.New(http.StatusServiceUnavailable, "UNAVAILABLE", "The results quarantine is not configured.").WriteJSON(w)
	case errors.Is(err, sensorresult.ErrAlreadyReviewed):
		apierror.Conflict("The quarantined result was already accepted or discarded.").WriteJSON(w)
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("Quarantined result").WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest(err.Error()).WriteJSON(w)
	default:
		h.logger.Error("sensor results request failed", "error", logger.SanitizeError(err))
		apierror.InternalError(err).WriteJSON(w)
	}
}

func resultTenant(w http.ResponseWriter, r *http.Request) (shared.ID, bool) {
	id, err := shared.IDFromString(middleware.GetTenantID(r.Context()))
	if err != nil {
		apierror.Unauthorized("").WriteJSON(w)
		return shared.ID{}, false
	}
	return id, true
}

func resultUser(w http.ResponseWriter, r *http.Request) (shared.ID, bool) {
	id, err := shared.IDFromString(middleware.GetUserID(r.Context()))
	if err != nil {
		apierror.Unauthorized("").WriteJSON(w)
		return shared.ID{}, false
	}
	return id, true
}

func resultPolicyResponse(p sensorresult.Policy) SensorResultPolicyResponse {
	resp := SensorResultPolicyResponse{
		Mode: string(p.Mode), AllowAdvisoryEvidence: p.AllowAdvisoryEvidence, DefaultMode: string(sensorresult.DefaultMode),
	}
	if p.Stored {
		at := p.UpdatedAt.UTC().Format(time.RFC3339)
		resp.UpdatedAt = &at
		if p.UpdatedBy != nil {
			by := p.UpdatedBy.String()
			resp.UpdatedBy = &by
		}
	}
	return resp
}

func quarantinedResponse(it *sensorresult.Item) QuarantinedResultResponse {
	resp := QuarantinedResultResponse{
		ID: it.ID.String(), SensorID: it.SensorID.String(), SensorName: it.SensorName, SensorType: it.SensorType,
		Protocol: string(it.Protocol), Route: it.Route, ReportID: it.ReportID, Segment: it.Segment,
		ToolName: it.ToolName, Reason: string(it.Reason), AssetsCount: it.AssetsCount, FindingsCount: it.FindingsCount,
		PayloadSize: it.PayloadSize, Status: string(it.Status), CreatedAt: it.CreatedAt.UTC().Format(time.RFC3339),
	}
	if it.ReviewedBy != nil {
		resp.ReviewedBy = it.ReviewedBy.String()
	}
	if it.ReviewedAt != nil {
		resp.ReviewedAt = it.ReviewedAt.UTC().Format(time.RFC3339)
	}
	if len(it.Result) > 0 {
		var m map[string]any
		if json.Unmarshal(it.Result, &m) == nil {
			resp.Result = m
		}
	}
	return resp
}

// previewLimit bounds the items a preview lists.
const previewLimit = 100

func previewOf(payload []byte) *QuarantinePreview {
	var rep ctis.Report
	if json.Unmarshal(payload, &rep) != nil {
		return nil
	}
	p := &QuarantinePreview{Assets: []QuarantinePreviewAsset{}, Findings: []QuarantinePreviewFinding{}}
	for i := range rep.Assets {
		if len(p.Assets) >= previewLimit {
			p.AssetsOmitted = len(rep.Assets) - previewLimit
			break
		}
		a := &rep.Assets[i]
		p.Assets = append(p.Assets, QuarantinePreviewAsset{Ref: a.ID, Type: string(a.Type), Value: firstNonEmpty(a.Value, a.Name)})
	}
	for i := range rep.Findings {
		if len(p.Findings) >= previewLimit {
			p.FindingOmitted = len(rep.Findings) - previewLimit
			break
		}
		f := &rep.Findings[i]
		p.Findings = append(p.Findings, QuarantinePreviewFinding{Title: f.Title, Severity: string(f.Severity), RuleID: f.RuleID, AssetRef: f.AssetRef})
	}
	return p
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
