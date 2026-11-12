package handler

// GET /api/v1/me/inbox/summary: the signed-in person's Inbox counts in one
// call (docs/architecture/my-work.md, "Inbox summary"). Self-scoped: the
// tenant, the user and the permissions come from the authenticated context;
// the request carries no parameter.

import (
	"errors"
	"net/http"

	inboxapp "github.com/openctemio/openctem/api/internal/app/inbox"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// InboxHandler serves the Inbox summary.
type InboxHandler struct {
	service *inboxapp.Service
	logger  *logger.Logger
}

// NewInboxHandler creates an InboxHandler.
func NewInboxHandler(svc *inboxapp.Service, log *logger.Logger) *InboxHandler {
	return &InboxHandler{service: svc, logger: log}
}

// InboxQueuesResponse is the caller's count of each Inbox queue. A queue the
// caller has no permission or module for is absent (its tab is left out),
// never 0.
type InboxQueuesResponse struct {
	// Assigned: open findings related to me (quick view my_queue).
	Assigned *int64 `json:"assigned,omitempty"`
	// Team: open findings of people who share an active group with me (my_team).
	Team *int64 `json:"team,omitempty"`
	// DueSoon: my open findings due within 72 hours, overdue included (my_due_soon).
	DueSoon *int64 `json:"due_soon,omitempty"`
	// Review: pending requests I may still decide (needs findings:approve).
	Review *int64 `json:"review,omitempty"`
	// Requested: my pending requests.
	Requested *int64 `json:"requested,omitempty"`
	// Expiring: my accepted risks ending within 30 days (my_accepted_expiring).
	Expiring *int64 `json:"expiring,omitempty"`
	// Tasks: open remediation tasks assigned to me or my groups (needs
	// findings:remediation:read and the remediation module).
	Tasks *int64 `json:"tasks,omitempty"`
	// ReadyToClose: closure proposals in my scope (needs findings:verify).
	ReadyToClose *int64 `json:"ready_to_close,omitempty"`
}

// InboxSummaryResponse is the response of GET /me/inbox/summary.
type InboxSummaryResponse struct {
	Queues InboxQueuesResponse `json:"queues"`
	// Total is assigned + review + requested + expiring + tasks +
	// ready_to_close over the queues present (team and due_soon excluded).
	Total int64 `json:"total"`
}

// Summary handles GET /api/v1/me/inbox/summary
// @Summary      Inbox summary
// @Description  The signed-in person's Inbox counts in one call: assigned, team, due_soon, review, requested, expiring,
// @Description  tasks and ready_to_close. Each count is the total of the list the queue opens, for the same caller
// @Description  (tenant, data scope and pentest membership applied): the finding queues are the quick views my_queue,
// @Description  my_team, my_due_soon and my_accepted_expiring; review and requested are the queue_counts of
// @Description  GET /approvals?queue=; tasks is GET /remediation/tasks?assignee=me over the open states; ready_to_close
// @Description  is GET /findings/closure/proposals. A queue the caller has no permission or module for is absent:
// @Description  every finding queue needs findings:read, review also findings:approve, ready_to_close also
// @Description  findings:verify, tasks findings:remediation:read and the remediation module. total = assigned + review
// @Description  + requested + expiring + tasks + ready_to_close. An organization API key or a platform caller gets 400.
// @Description  Never cached (Cache-Control: no-store).
// @Tags         Users
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  InboxSummaryResponse
// @Failure      400  {object}  apierror.Error
// @Failure      401  {object}  apierror.Error
// @Failure      503  {object}  apierror.Error
// @Router       /me/inbox/summary [get]
func (h *InboxHandler) Summary(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var memberChoice *bool
	if u := middleware.GetLocalUser(ctx); u != nil {
		memberChoice = u.Preferences().FindingsIncludeInformational
	}
	sum, err := h.service.Summary(ctx, inboxapp.Caller{
		TenantID:            middleware.GetTenantID(ctx),
		UserID:              middleware.GetUserID(ctx),
		IsAdmin:             middleware.IsAdmin(ctx),
		APIKey:              middleware.ReadsOnOwnScope(ctx),
		Has:                 func(p string) bool { return middleware.HasPermission(ctx, p) },
		InformationalChoice: memberChoice,
	})
	if err != nil {
		switch {
		case errors.Is(err, inboxapp.ErrNoPerson):
			apierror.BadRequest("The inbox needs a signed-in person").WriteJSON(w)
		case errors.Is(err, vulnerability.ErrFindingCountTimeout):
			apierror.ServiceUnavailable("Counting findings took too long; try again shortly").WriteJSON(w)
		default:
			h.logger.Error("failed to build inbox summary", "error", logger.SanitizeError(err))
			apierror.InternalServerError("Could not count the inbox").WriteJSON(w)
		}
		return
	}
	q := sum.Queues
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, InboxSummaryResponse{
		Queues: InboxQueuesResponse{
			Assigned: q.Assigned, Team: q.Team, DueSoon: q.DueSoon, Review: q.Review,
			Requested: q.Requested, Expiring: q.Expiring, Tasks: q.Tasks, ReadyToClose: q.ReadyToClose,
		},
		Total: sum.Total,
	})
}
