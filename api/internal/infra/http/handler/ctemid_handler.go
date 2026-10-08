package handler

import (
	"encoding/json"
	"net/http"
	"time"

	ctemidapp "github.com/openctemio/openctem/api/internal/app/ctemid"
	"github.com/openctemio/openctem/api/pkg/apierror"
	ctemiddom "github.com/openctemio/openctem/api/pkg/domain/ctemid"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// CTEMIDHandler serves the CTEM-ID catalog: standardized, CVE-like exposure
// identifiers mirrored from an external feed. This is global reference data.
type CTEMIDHandler struct {
	service *ctemidapp.Service
	logger  *logger.Logger
}

// NewCTEMIDHandler creates a new CTEMIDHandler.
func NewCTEMIDHandler(service *ctemidapp.Service, log *logger.Logger) *CTEMIDHandler {
	return &CTEMIDHandler{service: service, logger: log}
}

// CTEMIDResponse is a catalog entry in API responses.
type CTEMIDResponse struct {
	CTEMID      string     `json:"ctem_id"`
	Category    string     `json:"category"`
	Title       string     `json:"title"`
	Description string     `json:"description,omitempty"`
	Severity    string     `json:"severity,omitempty"`
	SourceURL   string     `json:"source_url,omitempty"`
	PublishedAt *time.Time `json:"published_at,omitempty"`
}

func toCTEMIDResponse(e *ctemiddom.CTEMID) CTEMIDResponse {
	return CTEMIDResponse{
		CTEMID:      e.CTEMID(),
		Category:    e.Category().String(),
		Title:       e.Title(),
		Description: e.Description(),
		Severity:    e.Severity(),
		SourceURL:   e.SourceURL(),
		PublishedAt: e.PublishedAt(),
	}
}

// CTEMIDListResponse is the paginated catalog list envelope.
type CTEMIDListResponse struct {
	Items   []CTEMIDResponse `json:"items"`
	Total   int              `json:"total"`
	Page    int              `json:"page"`
	PerPage int              `json:"per_page"`
}

// List handles GET /api/v1/ctem-ids — lists standardized CTEM-ID exposure
// catalog entries (optionally filtered by ?category=), paged with page/per_page.
// Baselined in api/openapi/undocumented-routes.txt.
func (h *CTEMIDHandler) List(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	var category *string
	if c := q.Get("category"); c != "" {
		category = &c
	}
	paging, ok := listPage(w, r, 100)
	if !ok {
		return
	}
	limit, offset := paging.Limit(), paging.Offset()

	entries, total, err := h.service.List(r.Context(), category, limit, offset)
	if err != nil {
		h.logger.Error("failed to list ctem-id catalog", "error", err)
		apierror.InternalServerError("failed to list ctem-id catalog").WriteJSON(w)
		return
	}

	items := make([]CTEMIDResponse, 0, len(entries))
	for _, e := range entries {
		items = append(items, toCTEMIDResponse(e))
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(CTEMIDListResponse{
		Items:   items,
		Total:   total,
		Page:    paging.Page,
		PerPage: paging.PerPage,
	})
}
