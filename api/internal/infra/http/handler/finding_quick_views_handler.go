package handler

// Quick-view counts of the findings list (research 234 D1).

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// FindingQuickViewResponse is one quick view with the caller's count.
type FindingQuickViewResponse struct {
	// Key: active, needs_triage, my_queue, sla_breached, pending_approval,
	// accepted_expiring or closed.
	Key string `json:"key"`
	// Count is the total GET /findings?<params> returns to the same caller.
	Count int64 `json:"count"`
	// Params is the GET /findings query string that lists the view.
	Params string `json:"params"`
}

// FindingQuickViewsResponse is the response of GET /findings/quick-views.
type FindingQuickViewsResponse struct {
	Views []FindingQuickViewResponse `json:"views"`
	AsOf  time.Time                  `json:"as_of"`
}

// FindingQuickViews handles GET /api/v1/findings/quick-views
// @Summary      Findings quick-view counts
// @Description  The built-in quick views of the findings list with the caller's count of each, in display order:
// @Description  active, needs_triage, my_queue, sla_breached, pending_approval, accepted_expiring, closed. Each view
// @Description  carries the GET /findings query string (params) that lists it; its count is that list's total for
// @Description  the same caller (tenant, data scope and pentest membership applied). One statement, 5 s limit
// @Description  (503 when it runs out). Responses may be cached privately for 60 s.
// @Tags         Findings
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  FindingQuickViewsResponse
// @Failure      401  {object}  apierror.Response
// @Failure      403  {object}  apierror.Response
// @Failure      503  {object}  apierror.Response
// @Router       /findings/quick-views [get]
func (h *VulnerabilityHandler) FindingQuickViews(w http.ResponseWriter, r *http.Request) {
	views, err := h.service.CountQuickViews(r.Context(), filterCaller(r))
	if err != nil {
		if errors.Is(err, vulnerability.ErrFindingCountTimeout) {
			apierror.ServiceUnavailable("Counting findings took too long; try again shortly").WriteJSON(w)
			return
		}
		h.logger.Error("failed to count finding quick views", "error", logger.SanitizeError(err))
		apierror.InternalError(err).WriteJSON(w)
		return
	}
	resp := FindingQuickViewsResponse{Views: make([]FindingQuickViewResponse, len(views)), AsOf: time.Now().UTC()}
	for i, v := range views {
		resp.Views[i] = FindingQuickViewResponse{Key: v.Key, Count: v.Count, Params: v.Params}
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "private, max-age=60")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}
