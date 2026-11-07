package handler

// Custom queries (docs/architecture/query-language.md). The tenant, the
// caller and their permissions come from the authenticated context; the
// body carries only the query text.

import (
	"encoding/json"
	"errors"
	"net/http"

	queryapp "github.com/openctemio/openctem/api/internal/app/query"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/filterspec"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/querylang"
)

// maxQueryBody bounds a query request body (the text is at most 4 KB).
const maxQueryBody = 8 << 10

// QueryHandler serves /api/v1/query.
type QueryHandler struct {
	service *queryapp.Service
	logger  *logger.Logger
}

// NewQueryHandler creates a QueryHandler.
func NewQueryHandler(svc *queryapp.Service, log *logger.Logger) *QueryHandler {
	return &QueryHandler{service: svc, logger: log}
}

// QueryRequest is a query to explain or run.
type QueryRequest struct {
	// Query is the query text, e.g. "findings where state = open | count by severity".
	Query string `json:"query"`
}

func queryCaller(r *http.Request) queryapp.Caller {
	ctx := r.Context()
	return queryapp.Caller{
		TenantID: middleware.MustGetTenantID(ctx), UserID: middleware.GetUserID(ctx),
		IsAdmin: middleware.IsAdmin(ctx), APIKey: middleware.ReadsOnOwnScope(ctx),
		Has: func(p string) bool { return middleware.HasPermission(ctx, p) },
	}
}

func (h *QueryHandler) decode(w http.ResponseWriter, r *http.Request) (string, bool) {
	var req QueryRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxQueryBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return "", false
	}
	return req.Query, true
}

func (h *QueryHandler) writeErr(w http.ResponseWriter, err error) {
	if qe, ok := querylang.AsError(err); ok {
		qe.APIError().WriteJSON(w)
		return
	}
	switch {
	case errors.Is(err, queryapp.ErrBusy):
		apierror.TooManyRequests(queryapp.ErrBusy.Error()).WriteJSON(w)
	case errors.Is(err, querylang.ErrTimeout):
		apierror.New(http.StatusUnprocessableEntity, apierror.CodeInvalidQuery,
			"The query took longer than allowed; narrow the filter or group by fewer fields").WriteJSON(w)
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("Entity").WriteJSON(w)
	case errors.Is(err, shared.ErrForbidden):
		apierror.Forbidden("You do not have permission to query this entity").WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest("Invalid request").WriteJSON(w)
	default:
		h.logger.Error("custom query failed", "error", err)
		apierror.InternalServerError("Query failed").WriteJSON(w)
	}
}

func (h *QueryHandler) write(w http.ResponseWriter, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(body)
}

// Explain handles POST /api/v1/query/explain
// @Summary      Check and explain a custom query
// @Description  Parses and checks a query (400 INVALID_QUERY with the byte range, line and column of each problem)
// @Description  and returns its canonical text, a plain-language description, the scope it is computed over
// @Description  (the caller's data scope and the server-side rules), its complexity score, a cost class
// @Description  (low, medium, high) and the query document. Nothing is run. Concurrency per user and tenant is bounded (429).
// @Tags         Query
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        request  body  QueryRequest  true  "Query"
// @Success      200  {object}  queryapp.Explanation
// @Failure      400  {object}  map[string]interface{}
// @Failure      429  {object}  map[string]interface{}
// @Router       /query/explain [post]
func (h *QueryHandler) Explain(w http.ResponseWriter, r *http.Request) {
	text, ok := h.decode(w, r)
	if !ok {
		return
	}
	ex, err := h.service.Explain(r.Context(), queryCaller(r), text)
	if err != nil {
		h.writeErr(w, err)
		return
	}
	h.write(w, ex)
}

// Run handles POST /api/v1/query/run
// @Summary      Run a custom query
// @Description  Runs a query interactively in the caller's scope: a read-only transaction with a 5 second
// @Description  statement timeout (422 on timeout), at most 1000 rows (truncated is set when more existed).
// @Description  Concurrency per user and tenant is bounded (429). Runs are not stored.
// @Tags         Query
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        request  body  QueryRequest  true  "Query"
// @Success      200  {object}  queryapp.RunResult
// @Failure      400  {object}  map[string]interface{}
// @Failure      422  {object}  map[string]interface{}  "Timed out"
// @Failure      429  {object}  map[string]interface{}
// @Router       /query/run [post]
func (h *QueryHandler) Run(w http.ResponseWriter, r *http.Request) {
	text, ok := h.decode(w, r)
	if !ok {
		return
	}
	res, err := h.service.Run(r.Context(), queryCaller(r), text)
	if err != nil {
		h.writeErr(w, err)
		return
	}
	h.write(w, res)
}

// Schema handles GET /api/v1/query/schema
// @Summary      Query fields of an entity
// @Description  The paths, types, operators and enum values the caller may use in queries on an entity, and which
// @Description  can be grouped, aggregated or bucketed. Fields the caller lacks the permission for are left out.
// @Tags         Query
// @Produce      json
// @Security     BearerAuth
// @Param        entity  query  string  true  "Entity (findings, assets)"
// @Success      200  {object}  querylang.Schema
// @Failure      403  {object}  map[string]interface{}
// @Failure      404  {object}  map[string]interface{}
// @Router       /query/schema [get]
func (h *QueryHandler) Schema(w http.ResponseWriter, r *http.Request) {
	s, err := h.service.Schema(r.Context(), queryCaller(r), r.URL.Query().Get("entity"))
	if err != nil {
		h.writeErr(w, err)
		return
	}
	h.write(w, s)
}

// QueryParseRequest is a search box filter to check: exactly one of text,
// document or params, on an entity.
type QueryParseRequest struct {
	// Entity is findings or assets.
	Entity string `json:"entity" example:"findings"`
	// Text is the search box text, short or long form, e.g. "severity>=high kev=true -status:accepted".
	Text string `json:"text,omitempty"`
	// Document is a version 1 FilterDocument to show as text and chips.
	Document map[string]any `json:"document,omitempty"`
	// Params is a list URL's query string ("severity=critical&kev=true").
	Params string `json:"params,omitempty"`
}

// Parse handles POST /api/v1/query/parse
// @Summary      Check a search box filter
// @Description  Parses search box text (the short form "severity>=high kev=true -status:accepted last_seen<7d",
// @Description  or the long form), a filter document or a list's URL params, for the caller's permissions:
// @Description  fields the caller may not use are unknown. Returns the version 1 filter document (relative
// @Description  times kept), the canonical short and long text, the top-level conditions as chips (or one
// @Description  advanced chip), the list's flat params when every chip has one, and the problems with a code,
// @Description  a byte range and suggestions. A problem is 200 with valid false; messages never repeat a value.
// @Description  Nothing reads data. Rate limited per user.
// @Tags         Query
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        request  body  QueryParseRequest  true  "Search box filter"
// @Success      200  {object}  queryapp.ParseResult
// @Failure      400  {object}  map[string]interface{}
// @Failure      403  {object}  map[string]interface{}
// @Failure      404  {object}  map[string]interface{}
// @Failure      429  {object}  map[string]interface{}
// @Router       /query/parse [post]
func (h *QueryHandler) Parse(w http.ResponseWriter, r *http.Request) {
	var req QueryParseRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxQueryBody+filterspecMaxBody))
	dec.DisallowUnknownFields()
	dec.UseNumber()
	if err := dec.Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	res, err := h.service.Parse(r.Context(), queryCaller(r), queryapp.ParseInput{
		Entity: req.Entity, Text: req.Text, Document: req.Document, Params: req.Params,
	})
	if err != nil {
		h.writeErr(w, err)
		return
	}
	h.write(w, res)
}

// filterspecMaxBody is the largest filter document a parse request carries.
const filterspecMaxBody = filterspec.MaxBodyBytes

// Values handles GET /api/v1/query/values
// @Summary      Value completion for a search box
// @Description  The most frequent values (up to 20) of one field, with how many rows have each, under the caller's
// @Description  search box filter (fq, short or long form) minus the field's own conditions. Counted in the caller's
// @Description  data scope with the list's server-side rules; fields the caller may not use, or that cannot be
// @Description  grouped, are unknown (400). Past a 1 second budget the answer has no counts (enum and boolean values
// @Description  are still listed). Answers are cached per caller for 60 seconds. Rate limited per user.
// @Tags         Query
// @Produce      json
// @Security     BearerAuth
// @Param        entity  query  string  true   "Entity (findings)"
// @Param        field   query  string  true   "Field path or short name (severity, tool, asset.type)"
// @Param        prefix  query  string  false  "Value prefix (case-insensitive)"
// @Param        fq      query  string  false  "The search box filter the counts are computed under"
// @Success      200  {object}  queryapp.ValuesResult
// @Failure      400  {object}  map[string]interface{}
// @Failure      403  {object}  map[string]interface{}
// @Failure      404  {object}  map[string]interface{}
// @Failure      429  {object}  map[string]interface{}
// @Router       /query/values [get]
func (h *QueryHandler) Values(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	res, err := h.service.Values(r.Context(), queryCaller(r), queryapp.ValuesInput{
		Entity: q.Get("entity"), Field: q.Get("field"), Prefix: q.Get("prefix"), Filter: q.Get("fq"),
	})
	if err != nil {
		h.writeErr(w, err)
		return
	}
	h.write(w, res)
}
