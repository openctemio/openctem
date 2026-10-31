package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/api/internal/app/contentpin"
	wordlistapp "github.com/openctemio/openctem/api/internal/app/wordlist"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/wordlist"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// maxWordlistBody bounds a create or update request: the list text plus
// the other fields, as JSON.
const maxWordlistBody = wordlist.MaxInputBytes + 64<<10

// WordlistPreviewer counts the label list an enumeration job would carry
// (contentpin.Planner).
type WordlistPreviewer interface {
	Preview(ctx context.Context, tenantID shared.ID, root, depth string) (*contentpin.Preview, error)
}

// WordlistHandler serves an organization's own wordlists (/api/v1/wordlists;
// docs/architecture/wordlists.md). The tenant comes from the JWT; every
// read and write is scoped to it.
type WordlistHandler struct {
	service *wordlistapp.Service
	preview WordlistPreviewer
	logger  *logger.Logger
}

// NewWordlistHandler creates a WordlistHandler. preview may be nil (the
// preview route then answers 404).
func NewWordlistHandler(svc *wordlistapp.Service, preview WordlistPreviewer, log *logger.Logger) *WordlistHandler {
	return &WordlistHandler{service: svc, preview: preview, logger: log.With("handler", "wordlist")}
}

// WordlistResponse is an organization list. Content (one label per line)
// is returned by the single-list read only.
type WordlistResponse struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Purpose     string    `json:"purpose"`
	Enabled     bool      `json:"enabled"`
	Version     int       `json:"version"`
	Lines       int       `json:"lines"`
	SHA256      string    `json:"sha256"`
	Content     string    `json:"content,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// WordlistListResponse is the organization's lists.
type WordlistListResponse struct {
	Items []WordlistResponse `json:"items"`
	// Limit is the most lists an organization may have.
	Limit int `json:"limit"`
}

// WordlistReport says what reading the text kept and dropped.
type WordlistReport struct {
	Kept       int      `json:"kept"`
	Invalid    int      `json:"invalid"`
	Secrets    int      `json:"secrets"`
	Duplicates int      `json:"duplicates"`
	Examples   []string `json:"examples"`
}

// WordlistSaveResponse is a saved list and, when text was sent, the report.
type WordlistSaveResponse struct {
	Wordlist WordlistResponse `json:"wordlist"`
	Report   *WordlistReport  `json:"report,omitempty"`
}

// CreateWordlistRequest creates a list from pasted or uploaded text.
type CreateWordlistRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	// Text is one label per line; blank lines and lines starting with #
	// are ignored.
	Text    string `json:"text"`
	Enabled *bool  `json:"enabled"`
}

// UpdateWordlistRequest changes a list; omitted fields are unchanged.
type UpdateWordlistRequest struct {
	Name        *string `json:"name"`
	Description *string `json:"description"`
	Text        *string `json:"text"`
	Enabled     *bool   `json:"enabled"`
}

// WordlistPreviewList is one organization list in a preview.
type WordlistPreviewList struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Version int    `json:"version"`
}

// WordlistPreviewPack is the platform pack a preview counts.
type WordlistPreviewPack struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Digest  string `json:"digest"`
	Lines   int    `json:"lines"`
}

// WordlistPreviewResponse counts the label list of an enumeration job of
// one root, per source.
type WordlistPreviewResponse struct {
	Root             string                `json:"root"`
	Depth            string                `json:"depth"`
	Pack             *WordlistPreviewPack  `json:"pack"`
	Learned          int                   `json:"learned"`
	Organization     int                   `json:"organization"`
	OrganizationKept int                   `json:"organization_kept"`
	Lists            []WordlistPreviewList `json:"lists"`
	Total            int                   `json:"total"`
}

func toWordlistResponse(w *wordlist.Wordlist, withContent bool) WordlistResponse {
	out := WordlistResponse{ID: w.ID.String(), Name: w.Name, Description: w.Description, Purpose: w.Purpose,
		Enabled: w.Enabled, Version: w.Version, Lines: w.Lines, SHA256: w.SHA256, CreatedAt: w.CreatedAt, UpdatedAt: w.UpdatedAt}
	if withContent {
		out.Content = w.Content
	}
	return out
}

func toWordlistSave(w *wordlist.Wordlist, rep *wordlistapp.Report) WordlistSaveResponse {
	out := WordlistSaveResponse{Wordlist: toWordlistResponse(w, false)}
	if rep != nil {
		ex := rep.Examples
		if ex == nil {
			ex = []string{}
		}
		out.Report = &WordlistReport{Kept: rep.Kept, Invalid: rep.Invalid, Secrets: rep.Secrets, Duplicates: rep.Duplicates, Examples: ex}
	}
	return out
}

// List handles GET /api/v1/wordlists
// @Summary      List organization wordlists
// @Description  The organization's own DNS label lists, joined into its subdomain enumeration jobs when enabled. The labels are not included.
// @Tags         Wordlists
// @Produce      json
// @Success      200  {object}  WordlistListResponse
// @Failure      401  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /wordlists [get]
func (h *WordlistHandler) List(w http.ResponseWriter, r *http.Request) {
	lists, err := h.service.List(r.Context(), buildScanZoneAuditContext(r))
	if err != nil {
		h.handleError(w, err)
		return
	}
	out := WordlistListResponse{Items: make([]WordlistResponse, 0, len(lists)), Limit: wordlist.MaxLists}
	for _, l := range lists {
		out.Items = append(out.Items, toWordlistResponse(l, false))
	}
	writeScanZoneJSON(w, http.StatusOK, out)
}

// Get handles GET /api/v1/wordlists/{id}
// @Summary      Get an organization wordlist
// @Description  One list with its labels (one per line).
// @Tags         Wordlists
// @Produce      json
// @Param        id   path      string  true  "Wordlist ID"
// @Success      200  {object}  WordlistResponse
// @Failure      401  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /wordlists/{id} [get]
func (h *WordlistHandler) Get(w http.ResponseWriter, r *http.Request) {
	l, err := h.service.Get(r.Context(), buildScanZoneAuditContext(r), chi.URLParam(r, "id"))
	if err != nil {
		h.handleError(w, err)
		return
	}
	writeScanZoneJSON(w, http.StatusOK, toWordlistResponse(l, true))
}

// Create handles POST /api/v1/wordlists
// @Summary      Create an organization wordlist
// @Description  text is one DNS label per line (# starts a comment). Lines that are not DNS labels, or look like secrets, are dropped and counted in the report.
// @Tags         Wordlists
// @Accept       json
// @Produce      json
// @Param        body  body      CreateWordlistRequest  true  "Wordlist"
// @Success      201   {object}  WordlistSaveResponse
// @Failure      400   {object}  apierror.Error
// @Failure      401   {object}  apierror.Error
// @Failure      403   {object}  apierror.Error
// @Failure      409   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /wordlists [post]
func (h *WordlistHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req CreateWordlistRequest
	if !decodeWordlistBody(w, r, &req) {
		return
	}
	l, rep, err := h.service.Create(r.Context(), buildScanZoneAuditContext(r), wordlistapp.CreateInput{
		Name: req.Name, Description: req.Description, Text: req.Text, Enabled: req.Enabled})
	if err != nil {
		h.handleError(w, err)
		return
	}
	writeScanZoneJSON(w, http.StatusCreated, toWordlistSave(l, rep))
}

// Update handles PATCH /api/v1/wordlists/{id}
// @Summary      Update an organization wordlist
// @Description  Omitted fields are unchanged. New text replaces the labels and raises the version when they differ.
// @Tags         Wordlists
// @Accept       json
// @Produce      json
// @Param        id    path      string                 true  "Wordlist ID"
// @Param        body  body      UpdateWordlistRequest  true  "Changes"
// @Success      200   {object}  WordlistSaveResponse
// @Failure      400   {object}  apierror.Error
// @Failure      401   {object}  apierror.Error
// @Failure      403   {object}  apierror.Error
// @Failure      404   {object}  apierror.Error
// @Failure      409   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /wordlists/{id} [patch]
func (h *WordlistHandler) Update(w http.ResponseWriter, r *http.Request) {
	var req UpdateWordlistRequest
	if !decodeWordlistBody(w, r, &req) {
		return
	}
	l, rep, err := h.service.Update(r.Context(), buildScanZoneAuditContext(r), chi.URLParam(r, "id"), wordlistapp.UpdateInput{
		Name: req.Name, Description: req.Description, Text: req.Text, Enabled: req.Enabled})
	if err != nil {
		h.handleError(w, err)
		return
	}
	writeScanZoneJSON(w, http.StatusOK, toWordlistSave(l, rep))
}

// Delete handles DELETE /api/v1/wordlists/{id}
// @Summary      Delete an organization wordlist
// @Tags         Wordlists
// @Param        id   path  string  true  "Wordlist ID"
// @Success      204
// @Failure      401  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /wordlists/{id} [delete]
func (h *WordlistHandler) Delete(w http.ResponseWriter, r *http.Request) {
	if err := h.service.Delete(r.Context(), buildScanZoneAuditContext(r), chi.URLParam(r, "id")); err != nil {
		h.handleError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Preview handles GET /api/v1/wordlists/preview
// @Summary      Preview the label list of an enumeration job
// @Description  Counts, per source, the DNS labels a subdomain enumeration job of root would query: the platform pack of the depth, the labels learned from the organization's names (with permutations) and the organization's enabled lists. Nothing is sent to any sensor or resolver.
// @Tags         Wordlists
// @Produce      json
// @Param        root   query     string  true   "Domain, such as example.com"
// @Param        depth  query     string  false  "standard (default) or deep"
// @Success      200    {object}  WordlistPreviewResponse
// @Failure      400    {object}  apierror.Error
// @Failure      401    {object}  apierror.Error
// @Failure      403    {object}  apierror.Error
// @Security     BearerAuth
// @Router       /wordlists/preview [get]
func (h *WordlistHandler) Preview(w http.ResponseWriter, r *http.Request) {
	if h.preview == nil {
		apierror.NotFound("Preview").WriteJSON(w)
		return
	}
	actx := buildScanZoneAuditContext(r)
	tid, err := shared.IDFromString(actx.TenantID)
	if err != nil {
		apierror.BadRequest("Invalid tenant").WriteJSON(w)
		return
	}
	depth := r.URL.Query().Get("depth")
	if depth == "" {
		depth = "standard"
	}
	if depth != "standard" && depth != "deep" {
		apierror.BadRequest("depth must be standard or deep").WriteJSON(w)
		return
	}
	p, err := h.preview.Preview(r.Context(), tid, r.URL.Query().Get("root"), depth)
	if err != nil {
		h.handleError(w, err)
		return
	}
	out := WordlistPreviewResponse{Root: p.Root, Depth: depth, Learned: p.Learned, Organization: p.Organization,
		OrganizationKept: p.OrganizationKept, Lists: make([]WordlistPreviewList, 0, len(p.Lists)), Total: p.Total}
	if p.Pack != nil {
		out.Pack = &WordlistPreviewPack{Name: p.Pack.Name, Version: p.Pack.Version, Digest: p.Pack.Digest, Lines: p.Pack.Lines}
	}
	for _, l := range p.Lists {
		out.Lists = append(out.Lists, WordlistPreviewList{ID: l.ID, Name: l.Name, Version: l.Version})
	}
	writeScanZoneJSON(w, http.StatusOK, out)
}

func decodeWordlistBody(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxWordlistBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			apierror.New(http.StatusRequestEntityTooLarge, apierror.Code(wordlist.ErrTooLarge.Code), wordlist.ErrTooLarge.Message).WriteJSON(w)
			return false
		}
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return false
	}
	return true
}

func (h *WordlistHandler) handleError(w http.ResponseWriter, err error) {
	var de *shared.DomainError
	switch {
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("Wordlist").WriteJSON(w)
	case errors.As(err, &de) && errors.Is(err, shared.ErrConflict):
		apierror.New(http.StatusConflict, apierror.Code(de.Code), de.Message).WriteJSON(w)
	case errors.As(err, &de) && errors.Is(err, shared.ErrValidation):
		apierror.New(http.StatusBadRequest, apierror.Code(de.Code), de.Message).WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest("Invalid wordlist").WriteJSON(w)
	default:
		h.logger.Error("wordlist service error", "error", sanitizeLogField(err.Error()))
		apierror.InternalError(err).WriteJSON(w)
	}
}
