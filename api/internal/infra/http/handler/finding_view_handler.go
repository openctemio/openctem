package handler

import (
	"net/http"

	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// findingViewTenantParts caps the parts one tenant's finding views run at the
// same time, across all its callers. The parts are single-finding reads (an
// indexed lookup each), lighter than the dashboard's aggregates.
const findingViewTenantParts = 8

// findingViewReadCost is what one finding view takes from the caller's
// per-user read budget: three reads for the first screen of a finding,
// instead of the twenty its panels took one by one.
const findingViewReadCost = 3

// FindingViewGate is the finding itself: it is read first, and unless it
// answers 200 the view holds only that part.
func FindingViewGate(id string) string { return "/api/v1/findings/" + id }

// FindingViewParts are the reads the finding page shows on load, by the exact
// URL the web asks for each one (research/335: the page sent about twenty
// requests on every finding). The id has been parsed as a UUID, so a part URL
// never carries text from the request.
func FindingViewParts(id string) []string {
	f := "/api/v1/findings/" + id
	return []string{
		"/api/v1/findings/ai-triage/config",
		f + "/ai-triage",
		f + "/participants",
		f + "/ticket-links",
		f + "/ticket-holds",
		f + "/verification",
		f + "/retest-check",
		f + "/retests",
		f + "/approvals",
		"/api/v1/remediation/tasks?sort=updated&finding_id=" + id + "&page=1&per_page=3",
		f + "/issue-links",
		f + "/identity",
		f + "/imports",
		f + "/activities?page=1&per_page=20",
		f + "/comments",
		f + "/evidence-items",
		f + "/evidence",
	}
}

// FindingViewHandler serves GET /findings/{id}/view: the finding and the
// reads its page shows on load, in one response.
//
// Every part is sent through the API's own router with the caller's
// credentials, so it passes exactly its endpoint's gates (permission, module,
// data scope, the read limit). A part the caller may not read is answered
// with its own status and error code and no data: the page shows that panel
// as absent, never as a failure of the whole page. Only FindingViewParts of
// the parsed id are dispatched; nothing else in the request chooses a path.
type FindingViewHandler struct {
	view *viewParts
}

// NewFindingViewHandler creates the handler. router returns the API's root
// router (read at request time, when every route is registered). A nil log
// logs through the request's logger.
func NewFindingViewHandler(router func() http.Handler, log *logger.Logger) *FindingViewHandler {
	return &FindingViewHandler{view: newViewParts(router, log, viewOptions{
		name: "finding view", tenantParts: findingViewTenantParts, passErrors: true, readCost: findingViewReadCost,
	})}
}

// View handles GET /api/v1/findings/{id}/view
// @Summary      Finding page view
// @Description  The finding and the reads its page shows on load, in one response: each part keyed by the URL of
// @Description  its endpoint, with that endpoint's status and JSON body (on a 4xx, its error body). Every part goes
// @Description  through its own endpoint's permission, module and data-scope gates. The finding is read first;
// @Description  unless it answers 200 (missing, out of scope), the view holds only that part.
// @Tags         Findings
// @Produce      json
// @Security     BearerAuth
// @Param        id   path      string  true  "Finding ID"
// @Success      200  {object}  ViewResponse
// @Failure      400  {object}  apierror.Error
// @Router       /findings/{id}/view [get]
func (h *FindingViewHandler) View(w http.ResponseWriter, r *http.Request) {
	id, err := shared.IDFromString(r.PathValue("id"))
	if err != nil {
		apierror.BadRequest("Invalid finding ID").WriteJSON(w)
		return
	}
	canonical := id.String()
	h.view.serve(w, r, FindingViewGate(canonical), FindingViewParts(canonical))
}
