package handler

// GET /api/v1/commands/{id}/logs: the log lines a sensor sent for any
// command (scan, retest, validate, connector, system), not only the tasks of
// a run (research/62 §4.3). Lines were capped, cleaned and redacted when they
// were stored, on the sensor and again here.
//
// Who may read them: the command's own gate (commands:read). A command about
// a finding (a retest, a validate job) also needs findings:read and the
// finding inside the caller's data scope; otherwise it is not found, never
// forbidden, so its existence is not disclosed.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/api/internal/app/commandlog"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// findingScope checks a finding against the caller's data scope
// (*datascope.Enforcer).
type findingScope interface {
	AssertFinding(ctx context.Context, tenantID, findingID shared.ID) error
}

// SetFindingScope makes the logs of a command about a finding readable only
// to a caller whose data scope holds that finding.
func (h *CommandHandler) SetFindingScope(s findingScope) { h.findingScope = s }

// GetLogs handles GET /api/v1/commands/{id}/logs
// @Summary      A command's logs
// @Description  The log lines the sensor sent for the command, oldest first, at most 5000, for every command kind. Kept 14 days. A command of another organization, or about a finding outside the caller's data scope, is not found.
// @Tags         Commands
// @Produce      json
// @Param        id   path      string  true  "Command ID"
// @Success      200  {object}  RunTaskLogsResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /commands/{id}/logs [get]
func (h *CommandHandler) GetLogs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenantID, err := shared.IDFromString(middleware.GetTenantID(ctx))
	if err != nil {
		apierror.NotFound("Command").WriteJSON(w)
		return
	}
	commandID, err := shared.IDFromString(chi.URLParam(r, "id"))
	if err != nil {
		apierror.BadRequest("invalid command id").WriteJSON(w)
		return
	}
	if h.logs == nil {
		apierror.NotFound("Command").WriteJSON(w)
		return
	}
	subject, err := h.logs.CommandSubject(ctx, tenantID, commandID)
	if err != nil {
		h.logger.Error("failed to read the command's subject", "error", err)
		apierror.InternalServerError("failed to read the command's logs").WriteJSON(w)
		return
	}
	if subject != nil && !h.mayReadFinding(ctx, tenantID, *subject) {
		apierror.NotFound("Command").WriteJSON(w)
		return
	}
	page, err := h.logs.ListForCommand(ctx, tenantID, commandID)
	switch {
	case errors.Is(err, commandlog.ErrNotFound), errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("Command").WriteJSON(w)
		return
	case err != nil:
		h.logger.Error("failed to read command logs", "error", err)
		apierror.InternalServerError("failed to read the command's logs").WriteJSON(w)
		return
	}
	resp := RunTaskLogsResponse{Lines: make([]RunTaskLogLine, 0, len(page.Lines)), Truncated: page.Truncated}
	for _, l := range page.Lines {
		resp.Lines = append(resp.Lines, RunTaskLogLine{TS: l.TS, Level: l.Level, Msg: l.Msg, Source: l.Source, Fields: l.Fields})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// mayReadFinding: findings:read, and the finding in the caller's data
// scope (no enforcer wired: the permission alone). A zero id (an unreadable
// subject) is never readable.
func (h *CommandHandler) mayReadFinding(ctx context.Context, tenantID, findingID shared.ID) bool {
	if findingID.IsZero() || !middleware.HasPermission(ctx, permission.FindingsRead.String()) {
		return false
	}
	if h.findingScope == nil {
		return true
	}
	return h.findingScope.AssertFinding(ctx, tenantID, findingID) == nil
}
