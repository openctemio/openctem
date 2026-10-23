package handler

// Bulk changes of findings by filter and the operations they run as
// (docs/architecture/findings-bulk-by-filter.md, docs/architecture/operations.md).

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/api/internal/app/finding"
	"github.com/openctemio/openctem/api/internal/infra/http/filterquery"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/operation"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/filterspec"
)

// maxBulkByFilterBody bounds a bulk-by-filter request body.
const maxBulkByFilterBody = 64 << 10

// FilterValues is a list filter as the list URL has it: param name to one
// value (a comma list is fine) or a list of values.
type FilterValues map[string]filterValue

type filterValue []string

// UnmarshalJSON takes a string or an array of strings.
func (v *filterValue) UnmarshalJSON(b []byte) error {
	var one string
	if err := json.Unmarshal(b, &one); err == nil {
		*v = filterValue{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return errors.New("a filter value is a string or an array of strings")
	}
	*v = many
	return nil
}

// BulkByFilterRequest is a bulk change of every finding a filter selects.
type BulkByFilterRequest struct {
	// Filter is the list's filter (GET /findings params, without paging or
	// sort), e.g. {"severity": "critical,high", "state": "open", "q": "log4j"}.
	Filter FilterValues `json:"filter"`
	// ExpectedCount is the total the caller saw and confirmed; the server
	// recounts in the caller's scope and answers 409 SELECTION_CHANGED when
	// it differs.
	ExpectedCount int `json:"expected_count"`
	// IdempotencyKey makes a retry return the first request's operation.
	IdempotencyKey string `json:"idempotency_key,omitempty"`
	// Status change (POST /findings/bulk/by-filter/status).
	Status        string `json:"status,omitempty"`
	Resolution    string `json:"resolution,omitempty"`
	ClosureReason string `json:"closure_reason,omitempty" enums:"fixed,mitigated"`
	// Assignee (POST /findings/bulk/by-filter/assignee).
	UserID string `json:"user_id,omitempty"`
}

// OperationItemResponse is one item of an operation that did not succeed.
type OperationItemResponse struct {
	ID      string `json:"id"`
	Outcome string `json:"outcome"`
	Reason  string `json:"reason"`
}

// OperationResponse is an operation (GET /api/v1/operations/{id}).
type OperationResponse struct {
	ID         string                  `json:"id"`
	Kind       string                  `json:"kind" enums:"findings_bulk_status,findings_bulk_assign"`
	Status     string                  `json:"status" enums:"running,succeeded,failed,interrupted"`
	Total      int                     `json:"total"`
	Processed  int                     `json:"processed"`
	Succeeded  int                     `json:"succeeded"`
	Skipped    int                     `json:"skipped"`
	Failed     int                     `json:"failed"`
	Items      []OperationItemResponse `json:"items"`
	Error      string                  `json:"error,omitempty"`
	CreatedAt  time.Time               `json:"created_at"`
	UpdatedAt  time.Time               `json:"updated_at"`
	FinishedAt *time.Time              `json:"finished_at,omitempty"`
	Self       string                  `json:"self"`
}

// BulkByFilterResponse wraps the operation of a bulk change by filter.
type BulkByFilterResponse struct {
	Operation OperationResponse `json:"operation"`
}

func toOperationResponse(op *operation.Operation) OperationResponse {
	items := make([]OperationItemResponse, 0, len(op.Items))
	for _, it := range op.Items {
		items = append(items, OperationItemResponse(it))
	}
	return OperationResponse{
		ID: op.ID.String(), Kind: string(op.Kind), Status: string(op.Status), Total: op.Total,
		Processed: op.Processed, Succeeded: op.Succeeded, Skipped: op.Skipped, Failed: op.Failed,
		Items: items, Error: op.Error, CreatedAt: op.CreatedAt, UpdatedAt: op.UpdatedAt, FinishedAt: op.FinishedAt,
		Self: "/api/v1/operations/" + op.ID.String(),
	}
}

// BulkUpdateFindingsStatusByFilter handles POST /api/v1/findings/bulk/by-filter/status
// @Summary      Change the status of every finding a filter selects
// @Description  "Select all matching" on the findings list. The filter (GET /findings params) is parsed strictly
// @Description  and recompiled in the caller's scope; the count must equal expected_count (409 SELECTION_CHANGED
// @Description  with the new count otherwise). At most 10,000 findings (400 BULK_TOO_LARGE). Up to 1,000 run in the
// @Description  request (200); more run in the background (202, poll GET /operations/{id}). False positive, accepted
// @Description  and duplicate are never set by filter (400 BULK_NOT_ALLOWED). A closing status needs step-up and a
// @Description  note. Each finding follows the same rules as POST /findings/bulk/status and gets its own audit row.
// @Tags         Findings
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        request  body  BulkByFilterRequest  true  "Filter, expected count and the status change"
// @Success      200  {object}  BulkByFilterResponse
// @Success      202  {object}  BulkByFilterResponse
// @Failure      400  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Failure      422  {object}  apierror.Error
// @Failure      429  {object}  apierror.Error
// @Router       /findings/bulk/by-filter/status [post]
func (h *VulnerabilityHandler) BulkUpdateFindingsStatusByFilter(w http.ResponseWriter, r *http.Request) {
	h.bulkByFilter(w, r, finding.BulkVerbStatus)
}

// BulkAssignFindingsByFilter handles POST /api/v1/findings/bulk/by-filter/assignee
// @Summary      Assign every finding a filter selects
// @Description  As POST /findings/bulk/by-filter/status, with user_id: the scope, expected_count, cap, background
// @Description  run and audit rules are the same.
// @Tags         Findings
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        request  body  BulkByFilterRequest  true  "Filter, expected count and the assignee"
// @Success      200  {object}  BulkByFilterResponse
// @Success      202  {object}  BulkByFilterResponse
// @Failure      400  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Failure      422  {object}  apierror.Error
// @Failure      429  {object}  apierror.Error
// @Router       /findings/bulk/by-filter/assignee [post]
func (h *VulnerabilityHandler) BulkAssignFindingsByFilter(w http.ResponseWriter, r *http.Request) {
	h.bulkByFilter(w, r, finding.BulkVerbAssign)
}

func (h *VulnerabilityHandler) bulkByFilter(w http.ResponseWriter, r *http.Request, verb string) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBulkByFilterBody))
	if err != nil {
		apierror.BadRequest("Request body is too large or unreadable").WriteJSON(w)
		return
	}
	var req BulkByFilterRequest
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		// Only the field name of an unknown field is echoed, never values.
		apierror.BadRequest("Invalid request body: unknown field, or a filter value that is not a string or a list of strings").WriteJSON(w)
		return
	}
	if req.ExpectedCount < 1 || req.ExpectedCount > finding.MaxBulkByFilter {
		apierror.ValidationFailed("expected_count must be between 1 and 10000", nil).WriteJSON(w)
		return
	}
	if len(req.IdempotencyKey) > 128 || len(req.Resolution) > 1000 || len(req.ClosureReason) > 64 {
		apierror.ValidationFailed("idempotency_key (128), resolution (1000) or closure_reason (64) is too long", nil).WriteJSON(w)
		return
	}

	q := url.Values{}
	for k, v := range req.Filter {
		q[k] = v
	}
	// The selection is the filter only: a saved view is sent as its filter,
	// and paging and sort do not change which findings match.
	for _, k := range []string{"view", "page", "per_page", "cursor", "sort"} {
		if _, ok := q[k]; ok {
			filterquery.WriteError(w, &filterspec.Error{Details: []filterspec.Detail{{
				Param: k, Reason: "not part of a bulk selection; send the filter params only",
			}}})
			return
		}
	}
	if !rewriteBranchStatus(w, q) {
		return
	}
	route := h.findingsListRoute()
	route.Name = "POST /findings/bulk/by-filter/" + verb
	route.Options.Unknown = filterspec.UnknownStrict
	spec, ok := route.ParseValues(w, r, q)
	if !ok {
		return
	}

	ctx := r.Context()
	actorID := middleware.GetUserID(ctx)
	if local := middleware.GetLocalUserID(ctx); !local.IsZero() {
		actorID = local.String()
	}
	caller := filterCaller(r)
	caller.UserID = actorID
	res, err := h.service.BulkByFilter(ctx, finding.BulkByFilterInput{
		Caller: caller, Verb: verb, Spec: spec, ExpectedCount: req.ExpectedCount,
		IdempotencyKey: req.IdempotencyKey, RequestHash: bulkByFilterHash(verb, req),
		Status: finding.BulkUpdateStatusInput{
			Status: req.Status, Resolution: req.Resolution, ClosureReason: req.ClosureReason, ActorID: actorID,
			HasStatusPermission:   middleware.HasPermission(ctx, string(permission.FindingsStatus)),
			HasVerifyPermission:   middleware.HasPermission(ctx, string(permission.FindingsVerify)),
			HasFixApplyPermission: middleware.HasPermission(ctx, string(permission.FindingsFixApply)),
			HasApprovePermission:  middleware.HasPermission(ctx, string(permission.FindingsApprove)),
		},
		AssigneeID: req.UserID,
		Audit:      h.exportAuditContext(r),
	})
	if err != nil {
		h.writeBulkByFilterError(w, err)
		return
	}
	status := http.StatusOK
	if res.Async {
		status = http.StatusAccepted
		w.Header().Set("Location", "/api/v1/operations/"+res.Operation.ID.String())
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(BulkByFilterResponse{Operation: toOperationResponse(res.Operation)})
}

func (h *VulnerabilityHandler) writeBulkByFilterError(w http.ResponseWriter, err error) {
	var changed *finding.SelectionChangedError
	switch {
	case errors.As(err, &changed):
		apierror.New(http.StatusConflict, apierror.CodeSelectionChanged, changed.Error()).
			WithDetails(map[string]int{"count": changed.Count}).WriteJSON(w)
	case errors.Is(err, finding.ErrBulkByFilterTooLarge):
		apierror.New(http.StatusBadRequest, apierror.CodeBulkTooLarge, err.Error()).
			WithDetails(map[string]int{"max": finding.MaxBulkByFilter}).WriteJSON(w)
	case errors.Is(err, finding.ErrBulkByFilterNotAllowed):
		apierror.New(http.StatusBadRequest, apierror.CodeBulkNotAllowed, err.Error()).WriteJSON(w)
	case errors.Is(err, finding.ErrBulkByFilterNote):
		apierror.ValidationFailed(err.Error(), nil).WriteJSON(w)
	case errors.Is(err, finding.ErrBulkByFilterBudget):
		apierror.TooManyRequests(err.Error()).WriteJSON(w)
	case errors.Is(err, finding.ErrBulkByFilterNoUser):
		apierror.Forbidden(err.Error()).WriteJSON(w)
	case errors.Is(err, operation.ErrBusy):
		apierror.New(http.StatusConflict, apierror.CodeOperationRunning, err.Error()).WriteJSON(w)
	case errors.Is(err, operation.ErrIdempotencyMismatch):
		apierror.New(http.StatusUnprocessableEntity, apierror.CodeIdempotencyKeyReused, err.Error()).WriteJSON(w)
	default:
		if _, isFilter := filterspec.AsError(err); isFilter {
			filterquery.WriteError(w, err)
			return
		}
		h.handleServiceError(w, err, "Finding")
	}
}

// bulkByFilterHash identifies a request for idempotency: the verb and every
// field that changes what it does (json.Marshal sorts map keys).
func bulkByFilterHash(verb string, req BulkByFilterRequest) string {
	b, _ := json.Marshal(struct {
		Verb string
		BulkByFilterRequest
	}{verb, BulkByFilterRequest{Filter: req.Filter, ExpectedCount: req.ExpectedCount, Status: req.Status,
		Resolution: req.Resolution, ClosureReason: req.ClosureReason, UserID: req.UserID}})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// GetOperation handles GET /api/v1/operations/{id}
// @Summary      Read an operation
// @Description  A long-running operation the caller started (a bulk change by filter): status, counts and the
// @Description  items that did not succeed (at most 200). Only its creator reads it; anyone else gets 404. A
// @Description  running operation that stopped making progress reads as interrupted.
// @Tags         Operations
// @Produce      json
// @Security     BearerAuth
// @Param        id  path  string  true  "Operation ID"
// @Success      200  {object}  OperationResponse
// @Failure      404  {object}  apierror.Error
// @Router       /operations/{id} [get]
func (h *VulnerabilityHandler) GetOperation(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, err := shared.IDFromString(chi.URLParam(r, "id"))
	if err != nil {
		apierror.NotFound("Operation").WriteJSON(w)
		return
	}
	tenantID, terr := shared.IDFromString(middleware.MustGetTenantID(ctx))
	actor := middleware.GetUserID(ctx)
	if local := middleware.GetLocalUserID(ctx); !local.IsZero() {
		actor = local.String()
	}
	userID, uerr := shared.IDFromString(actor)
	if terr != nil || uerr != nil {
		apierror.NotFound("Operation").WriteJSON(w)
		return
	}
	op, err := h.service.GetOperation(ctx, tenantID, userID, id)
	if err != nil {
		if errors.Is(err, operation.ErrNotFound) {
			apierror.NotFound("Operation").WriteJSON(w)
			return
		}
		h.handleServiceError(w, err, "Operation")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(toOperationResponse(op))
}
