package handler

// POST /api/v2/sensor/commands/{command_id}/logs (RFC-029 §4.4.1): a sensor
// sends the log lines of a task it holds, in numbered batches through its
// outbox. The tenant and the sensor come from the authenticated key; the
// command must be the tenant's and held (or last held) by this sensor.

import (
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/api/internal/app/commandlog"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
)

// CommandLogs handles POST /api/v2/sensor/commands/{command_id}/logs.
//
// Answers: 200 LogsResponse (also for a replayed seq, and with truncated
// when the command reached its log caps: the sensor must not resend);
// 404 command-not-found for a command that is not this sensor's (the same
// answer for another tenant's, another sensor's or an unknown id); 409
// invalid-transition when the command finished more than 24 hours ago;
// 400 invalid-request, 413 content-too-large and 422 too-many-items for a
// malformed batch. Every 4xx is final for the batch.
func (h *SensorControlV2Handler) CommandLogs(w http.ResponseWriter, r *http.Request) {
	s := sensorForV2(w, r)
	if s == nil {
		return
	}
	commandID, err := shared.IDFromString(chi.URLParam(r, "command_id"))
	if err != nil || protov2.ValidateUUID(chi.URLParam(r, "command_id")) != nil {
		protov2.NewProblem(protov2.ProblemInvalidID).Write(w)
		return
	}
	var req protov2.LogsRequest
	if !decodeControl(w, r, protov2.MaxLogsBodyBytes, &req) {
		return
	}
	if req.Seq < 0 || req.Seq >= protov2.MaxLogSeq || len(req.Lines) == 0 {
		protov2.NewProblem(protov2.ProblemInvalidRequest).Write(w)
		return
	}
	if len(req.Lines) > protov2.MaxLogLinesPerBatch {
		protov2.NewProblem(protov2.ProblemTooManyItems).WithLimit(protov2.MaxLogLinesPerBatch).Write(w)
		return
	}
	lines := make([]commandlog.RawLine, len(req.Lines))
	for i, l := range req.Lines {
		lines[i] = commandlog.RawLine{TS: l.TS, Level: l.Level, Msg: l.Msg, Source: l.Source, Fields: l.Fields}
	}
	res, err := h.commands.logs.Append(r.Context(), commandlog.AppendInput{
		TenantID: *s.TenantID, SensorID: s.ID, CommandID: commandID, Seq: req.Seq, Lines: lines,
	})
	switch {
	case errors.Is(err, commandlog.ErrNotFound):
		protov2.NewProblem(protov2.ProblemCommandNotFound).Write(w)
		return
	case errors.Is(err, commandlog.ErrClosed):
		protov2.NewProblem(protov2.ProblemInvalidTransition).WithState("closed").Write(w)
		return
	case errors.Is(err, shared.ErrValidation):
		protov2.NewProblem(protov2.ProblemInvalidRequest).Write(w)
		return
	case err != nil:
		h.internal(w, "logs", err)
		return
	}
	writeV2JSON(w, http.StatusOK, protov2.LogsResponse{Stored: res.Stored, Dropped: res.Dropped, Truncated: res.Truncated})
}
