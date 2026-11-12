package handler

// Retiring an import source: "stop using this source"
// (docs/architecture/source-retirement.md).

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	sourceretireapp "github.com/openctemio/openctem/api/internal/app/sourceretire"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/sourceretire"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// paramCount is the message parameter of a count.
const paramCount = "count"

// SourceRetirementService is the use cases the handler calls.
type SourceRetirementService interface {
	Preview(ctx context.Context, tenantID shared.ID, src sourceretireapp.Source, opts sourceretire.Options) (*sourceretire.Preview, string, error)
	Retire(ctx context.Context, tenantID shared.ID, in sourceretireapp.RetireInput, a sourceretireapp.Actor) (*sourceretire.Retirement, *sourceretire.Preview, error)
	Restore(ctx context.Context, tenantID, id shared.ID, reason string, a sourceretireapp.Actor) (*sourceretire.Retirement, error)
	Get(ctx context.Context, tenantID, id shared.ID) (*sourceretire.Retirement, error)
	List(ctx context.Context, tenantID shared.ID, includeRestored bool) ([]*sourceretire.Retirement, error)
}

// SourceRetirementHandler serves /api/v1/findings/sources/retirements.
type SourceRetirementHandler struct {
	svc    SourceRetirementService
	logger *logger.Logger
}

// NewSourceRetirementHandler returns the handler.
func NewSourceRetirementHandler(svc SourceRetirementService, log *logger.Logger) *SourceRetirementHandler {
	return &SourceRetirementHandler{svc: svc, logger: log}
}

// SourceSelectorRequest names a source: a kind with its keys, or a
// connector integration (resolved on the server).
type SourceSelectorRequest struct {
	Kind          string `json:"kind,omitempty" enums:"sensor_tool,upload,connector"`
	SensorID      string `json:"sensor_id,omitempty"`
	Sender        string `json:"sender,omitempty"`
	Tool          string `json:"tool,omitempty"`
	IntegrationID string `json:"integration_id,omitempty"`
}

// SourceRetireOptionsRequest are the dialog's options; empty is the
// default (archive every severity, keep findings in remediation open).
type SourceRetireOptionsRequest struct {
	Mode           string   `json:"mode,omitempty" enums:"archive,keep_open"`
	Severities     []string `json:"severities,omitempty"`
	IncludeEngaged bool     `json:"include_engaged,omitempty"`
}

// SourceRetirePreviewRequest asks what retiring a source would do.
type SourceRetirePreviewRequest struct {
	Source  SourceSelectorRequest      `json:"source"`
	Options SourceRetireOptionsRequest `json:"options"`
}

// SourceRetirePreviewResponse is the preview.
type SourceRetirePreviewResponse struct {
	Label   string               `json:"label"`
	Preview sourceretire.Preview `json:"preview"`
}

// SourceRetireRequest stops using a source.
type SourceRetireRequest struct {
	Source  SourceSelectorRequest      `json:"source"`
	Options SourceRetireOptionsRequest `json:"options"`
	// Reason, 10 to 500 characters (audited).
	Reason string `json:"reason"`
	// ConfirmCritical confirms the critical or known-exploited findings the
	// archive includes; required when there are any.
	ConfirmCritical bool `json:"confirm_critical,omitempty"`
}

// SourceRestoreRequest uses a retired source again.
type SourceRestoreRequest struct {
	Reason string `json:"reason,omitempty"`
}

// SourceRetirementResponse is one retirement.
type SourceRetirementResponse struct {
	ID             string     `json:"id"`
	Kind           string     `json:"kind"`
	SensorID       string     `json:"sensor_id,omitempty"`
	Sender         string     `json:"sender,omitempty"`
	Tool           string     `json:"tool,omitempty"`
	IntegrationID  string     `json:"integration_id,omitempty"`
	Label          string     `json:"label"`
	Mode           string     `json:"mode"`
	Severities     []string   `json:"severities"`
	IncludeEngaged bool       `json:"include_engaged"`
	State          string     `json:"state" enums:"applying,active,restoring,restored"`
	Reason         string     `json:"reason"`
	PlannedCount   int        `json:"planned_count"`
	ArchivedCount  int        `json:"archived_count"`
	RestoredCount  int        `json:"restored_count"`
	ChangedCount   int        `json:"changed_count"`
	RetiredBy      string     `json:"retired_by,omitempty"`
	RetiredAt      time.Time  `json:"retired_at"`
	RestoredBy     string     `json:"restored_by,omitempty"`
	RestoreReason  string     `json:"restore_reason,omitempty"`
	RestoredAt     *time.Time `json:"restored_at,omitempty"`
	AlreadyRetired bool       `json:"already_retired,omitempty"`
}

// SourceRetireResponse is the retirement and the preview it applied.
type SourceRetireResponse struct {
	Retirement SourceRetirementResponse `json:"retirement"`
	Preview    sourceretire.Preview     `json:"preview"`
}

// SourceRetirementListResponse lists retirements.
type SourceRetirementListResponse struct {
	Items []SourceRetirementResponse `json:"items"`
}

func toSourceRetirementResponse(r *sourceretire.Retirement) SourceRetirementResponse {
	out := SourceRetirementResponse{ID: r.ID.String(), Kind: string(r.Selector.Kind), Sender: r.Selector.Sender,
		Tool: r.Selector.Tool, Label: r.Label, Mode: string(r.Options.Mode), Severities: r.Options.SeverityStrings(),
		IncludeEngaged: r.Options.IncludeEngaged, State: string(r.State), Reason: r.Reason, PlannedCount: r.PlannedCount,
		ArchivedCount: r.ArchivedCount, RestoredCount: r.RestoredCount, ChangedCount: r.ChangedCount,
		RetiredAt: r.RetiredAt, RestoreReason: r.RestoreReason, RestoredAt: r.RestoredAt, AlreadyRetired: r.AlreadyRetired}
	if r.Selector.SensorID != nil {
		out.SensorID = r.Selector.SensorID.String()
	}
	if r.IntegrationID != nil {
		out.IntegrationID = r.IntegrationID.String()
	}
	if r.RetiredBy != nil {
		out.RetiredBy = r.RetiredBy.String()
	}
	if r.RestoredBy != nil {
		out.RestoredBy = r.RestoredBy.String()
	}
	return out
}

func parseSourceRequest(in SourceSelectorRequest) (sourceretireapp.Source, error) {
	var out sourceretireapp.Source
	if in.IntegrationID != "" {
		id, err := shared.IDFromString(in.IntegrationID)
		if err != nil {
			return out, sourceretire.ErrSourceNotFound
		}
		out.IntegrationID = &id
		return out, nil
	}
	out.Selector = sourceretire.Selector{Kind: sourceretire.Kind(in.Kind), Sender: in.Sender, Tool: in.Tool}
	if in.SensorID != "" {
		id, err := shared.IDFromString(in.SensorID)
		if err != nil {
			return out, sourceretire.ErrSourceNotFound
		}
		out.Selector.SensorID = &id
	}
	return out, nil
}

func parseRetireOptions(in SourceRetireOptionsRequest) sourceretire.Options {
	out := sourceretire.Options{Mode: sourceretire.Mode(in.Mode), IncludeEngaged: in.IncludeEngaged}
	for _, s := range in.Severities {
		out.Severities = append(out.Severities, vulnerability.Severity(s))
	}
	return out
}

func (h *SourceRetirementHandler) actor(r *http.Request) sourceretireapp.Actor {
	ctx := r.Context()
	return sourceretireapp.Actor{UserID: middleware.GetUserID(ctx), Email: auditActorEmail(ctx), IP: getClientIP(r),
		UserAgent: r.UserAgent(), RequestID: middleware.GetRequestID(ctx)}
}

func (h *SourceRetirementHandler) tenant(w http.ResponseWriter, r *http.Request) (shared.ID, bool) {
	id, err := shared.IDFromString(middleware.MustGetTenantID(r.Context()))
	if err != nil {
		apierror.Unauthorized("Invalid tenant ID").WriteJSON(w)
		return shared.ID{}, false
	}
	return id, true
}

func (h *SourceRetirementHandler) writeErr(w http.ResponseWriter, err error, preview *sourceretire.Preview) {
	switch {
	case errors.Is(err, sourceretire.ErrConfirmCriticalRequired):
		e := apierror.FromCode(apierror.CodeConfirmCriticalRequired)
		if preview != nil {
			e = e.WithParams(apierror.Params{paramCount: strconv.Itoa(preview.CriticalOrKEV)})
		}
		e.WriteJSON(w)
	case errors.Is(err, sourceretire.ErrFullDataAccessRequired):
		apierror.FromCode(apierror.CodeFullDataAccessRequired).WriteJSON(w)
	case errors.Is(err, sourceretire.ErrNotRestorable):
		apierror.FromCode(apierror.CodeSourceNotRestorable).WriteJSON(w)
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("Source").WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest(ciErrMessage(err)).WriteJSON(w)
	default:
		h.logger.Error("source retirement", "error", logger.SanitizeError(err))
		apierror.FromCode(apierror.CodeInternalError).WriteJSON(w)
	}
}

func decodeSourceRetireBody(w http.ResponseWriter, r *http.Request, v any) bool {
	limitBody(w, r)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return false
	}
	return true
}

// Preview handles POST /api/v1/findings/sources/retirements/preview
// @Summary      Preview stopping the use of an import source
// @Description  Counts what retiring the source would do, with the same query the retirement runs: the findings only this source reported that are archived as source retired, those another source also reported (unchanged), those kept open (in remediation, secrets, severities not selected), and the critical or known-exploited ones that need a separate confirmation. Needs full data access; a sensor or integration of another organization is 404.
// @Tags         Findings
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        body body SourceRetirePreviewRequest true "Source and options"
// @Success      200  {object}  SourceRetirePreviewResponse
// @Failure      400  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Router       /findings/sources/retirements/preview [post]
func (h *SourceRetirementHandler) Preview(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenant(w, r)
	if !ok {
		return
	}
	var req SourceRetirePreviewRequest
	if !decodeSourceRetireBody(w, r, &req) {
		return
	}
	src, err := parseSourceRequest(req.Source)
	if err != nil {
		h.writeErr(w, err, nil)
		return
	}
	p, label, err := h.svc.Preview(r.Context(), tenantID, src, parseRetireOptions(req.Options))
	if err != nil {
		h.writeErr(w, err, nil)
		return
	}
	ciWriteJSON(w, http.StatusOK, SourceRetirePreviewResponse{Label: label, Preview: *p})
}

// Retire handles POST /api/v1/findings/sources/retirements
// @Summary      Stop using an import source
// @Description  From now on the source's reports are refused (each receipt counts their findings as source_retired). The open findings only this source reported are archived as source retired (resolved, closure reason obsolete_source: not fixed, out of metrics and SLA, restorable). 200 when done, 202 while batches remain (the retirement shows the progress). A source already retired returns its retirement (already_retired). 409 CONFIRM_CRITICAL_REQUIRED when critical or known-exploited findings would be archived without confirm_critical. Re-authentication as the organization's sensitive rule says; audited.
// @Tags         Findings
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        body body SourceRetireRequest true "Source, options, reason"
// @Success      200  {object}  SourceRetireResponse
// @Success      202  {object}  SourceRetireResponse
// @Failure      400  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Router       /findings/sources/retirements [post]
func (h *SourceRetirementHandler) Retire(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenant(w, r)
	if !ok {
		return
	}
	var req SourceRetireRequest
	if !decodeSourceRetireBody(w, r, &req) {
		return
	}
	src, err := parseSourceRequest(req.Source)
	if err != nil {
		h.writeErr(w, err, nil)
		return
	}
	ret, p, err := h.svc.Retire(r.Context(), tenantID, sourceretireapp.RetireInput{Source: src,
		Options: parseRetireOptions(req.Options), Reason: req.Reason, ConfirmCritical: req.ConfirmCritical}, h.actor(r))
	if err != nil {
		h.writeErr(w, err, p)
		return
	}
	status := http.StatusOK
	if !ret.Done() {
		status = http.StatusAccepted
	}
	ciWriteJSON(w, status, SourceRetireResponse{Retirement: toSourceRetirementResponse(ret), Preview: *p})
}

// List handles GET /api/v1/findings/sources/retirements
// @Summary      List retired import sources
// @Tags         Findings
// @Produce      json
// @Security     BearerAuth
// @Param        include_restored query bool false "Also list sources used again"
// @Success      200  {object}  SourceRetirementListResponse
// @Failure      403  {object}  apierror.Error
// @Router       /findings/sources/retirements [get]
func (h *SourceRetirementHandler) List(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenant(w, r)
	if !ok {
		return
	}
	include := r.URL.Query().Get("include_restored") == queryParamTrue
	list, err := h.svc.List(r.Context(), tenantID, include)
	if err != nil {
		h.writeErr(w, err, nil)
		return
	}
	out := SourceRetirementListResponse{Items: make([]SourceRetirementResponse, 0, len(list))}
	for _, ret := range list {
		out.Items = append(out.Items, toSourceRetirementResponse(ret))
	}
	ciWriteJSON(w, http.StatusOK, out)
}

// Get handles GET /api/v1/findings/sources/retirements/{id}
// @Summary      Get a retired import source (with its progress)
// @Tags         Findings
// @Produce      json
// @Security     BearerAuth
// @Param        id path string true "Retirement ID"
// @Success      200  {object}  SourceRetirementResponse
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Router       /findings/sources/retirements/{id} [get]
func (h *SourceRetirementHandler) Get(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenant(w, r)
	if !ok {
		return
	}
	id, ok := pathID(w, r, "Source")
	if !ok {
		return
	}
	ret, err := h.svc.Get(r.Context(), tenantID, id)
	if err != nil {
		h.writeErr(w, err, nil)
		return
	}
	ciWriteJSON(w, http.StatusOK, toSourceRetirementResponse(ret))
}

// Restore handles POST /api/v1/findings/sources/retirements/{id}/reactivate
// @Summary      Use a retired import source again
// @Description  The source's reports are accepted again at once, and the findings its retirement archived return to the status they had, unless someone changed them since (counted as changed, left as they are). 200 when done, 202 while batches remain. Re-authentication as the organization's sensitive rule says; audited.
// @Tags         Findings
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        id   path string true "Retirement ID"
// @Param        body body SourceRestoreRequest false "Reason"
// @Success      200  {object}  SourceRetirementResponse
// @Success      202  {object}  SourceRetirementResponse
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Router       /findings/sources/retirements/{id}/reactivate [post]
func (h *SourceRetirementHandler) Restore(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenant(w, r)
	if !ok {
		return
	}
	id, ok := pathID(w, r, "Source")
	if !ok {
		return
	}
	var req SourceRestoreRequest
	if r.ContentLength != 0 && !decodeSourceRetireBody(w, r, &req) {
		return
	}
	ret, err := h.svc.Restore(r.Context(), tenantID, id, req.Reason, h.actor(r))
	if err != nil {
		h.writeErr(w, err, nil)
		return
	}
	status := http.StatusOK
	if !ret.Done() {
		status = http.StatusAccepted
	}
	ciWriteJSON(w, status, toSourceRetirementResponse(ret))
}
