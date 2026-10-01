package handler

// Sensor protocol v2 results (RFC-026, docs/rfcs/RFC-026-sensor-results-ingest.md).
// The edge chain (internal/infra/http/middleware/ingest_v2.go) has verified
// the request before these handlers run; they only decide what the verified
// bytes may become and answer with the status resource or an RFC 9457
// problem. Every wire string comes from pkg/sensorproto/v2.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/internal/app/ingest"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/internal/metrics"
	"github.com/openctemio/api/pkg/logger"
	protov2 "github.com/openctemio/api/pkg/sensorproto/v2"
)

// SensorResultsV2Handler serves /api/v2/sensor.
type SensorResultsV2Handler struct {
	receiver *ingest.V2Receiver
	sensors  *app.SensorService
	logger   *logger.Logger
}

// NewSensorResultsV2Handler builds the handler.
func NewSensorResultsV2Handler(receiver *ingest.V2Receiver, sensors *app.SensorService, log *logger.Logger) *SensorResultsV2Handler {
	return &SensorResultsV2Handler{receiver: receiver, sensors: sensors, logger: log.With("handler", "sensor-results-v2")}
}

// Limits are the limits the receiver enforces, for the edge chain.
func (h *SensorResultsV2Handler) Limits() protov2.Limits { return h.receiver.Limits() }

// Authenticate is the only authenticator of the v2 route group (RFC-023
// C-2): a sensor key in Authorization: Bearer or X-API-Key. A user JWT, a
// session cookie or an oct_ key is not a sensor key and gets 401. A disabled
// sensor is refused on every v2 route (the v1 doorbell exception does not
// exist here). The refusal is the generic problem; the reason is logged.
func (h *SensorResultsV2Handler) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := extractAPIKey(r)
		if key == "" {
			protov2.NewProblem(protov2.ProblemUnauthenticated).Write(w)
			return
		}
		id, err := h.sensors.AuthenticateIdentity(r.Context(), key)
		if err == nil && id.Paused {
			err = errSensorPaused
		}
		if err != nil || id.Sensor == nil {
			h.logger.Debug("v2 authentication failed", "error", err)
			protov2.NewProblem(protov2.ProblemUnauthenticated).Write(w)
			return
		}
		ctx := context.WithValue(r.Context(), sensorContextKey, id.Sensor)
		ctx = context.WithValue(ctx, sensorIdentityContextKey, id)
		if id.Sensor.TenantID != nil {
			ctx = context.WithValue(ctx, middleware.TenantIDKey, id.Sensor.TenantID.String())
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// SensorKey returns the authenticated sensor's id, for per-sensor limits.
func SensorKey(r *http.Request) string {
	if s := SensorFromContext(r.Context()); s != nil {
		return s.ID.String()
	}
	return ""
}

// target reads the path ids and the sensor; ok is false when a problem was
// written.
func (h *SensorResultsV2Handler) target(w http.ResponseWriter, r *http.Request) (ingest.V2Target, bool) {
	s := SensorFromContext(r.Context())
	if s == nil {
		protov2.NewProblem(protov2.ProblemUnauthenticated).Write(w)
		return ingest.V2Target{}, false
	}
	t := ingest.V2Target{Sensor: s, ReportID: chi.URLParam(r, "report_id"), CommandID: chi.URLParam(r, "command_id"),
		UserAgent: r.UserAgent()}
	if protov2.ValidateUUID(t.ReportID) != nil || (t.CommandID != "" && protov2.ValidateUUID(t.CommandID) != nil) {
		protov2.NewProblem(protov2.ProblemInvalidID).Write(w)
		return ingest.V2Target{}, false
	}
	return t, true
}

// PutReport handles PUT /results/{report_id} and the command-bound form: a
// whole report in one request, committed implicitly.
func (h *SensorResultsV2Handler) PutReport(w http.ResponseWriter, r *http.Request) {
	h.put(w, r, "put_report", 0, true)
}

// PutSegment handles PUT /results/{report_id}/segments/{seq} and the
// command-bound form.
func (h *SensorResultsV2Handler) PutSegment(w http.ResponseWriter, r *http.Request) {
	seq, err := protov2.ParseSegmentSeq(chi.URLParam(r, "seq"), h.receiver.Limits().MaxSegmentsPerReport)
	if err != nil {
		h.fail(w, "put_segment", &ingest.V2ReportError{Problem: protov2.ProblemInvalidID})
		return
	}
	h.put(w, r, "put_segment", seq, false)
}

func (h *SensorResultsV2Handler) put(w http.ResponseWriter, r *http.Request, route string, seq int, whole bool) {
	t, ok := h.target(w, r)
	if !ok {
		return
	}
	body := middleware.V2BodyFromContext(r.Context())
	if body == nil {
		// The edge chain did not run: a wiring fault, never a sensor fault.
		h.logger.Error("v2 results route mounted without the edge chain")
		h.fail(w, route, errors.New("no verified body"))
		return
	}
	metrics.IngestV2Bytes.WithLabelValues("encoded").Observe(float64(len(body.Encoded)))
	metrics.IngestV2Bytes.WithLabelValues("decoded").Observe(float64(len(body.Decoded)))
	res, err := h.receiver.Put(r.Context(), t, seq, whole, ingest.V2Body{Decoded: body.Decoded, Digest: body.Digest})
	if err != nil {
		h.fail(w, route, err)
		return
	}
	h.writeStatus(w, res)
}

// Commit handles POST /results/{report_id}/commit and the command-bound form.
func (h *SensorResultsV2Handler) Commit(w http.ResponseWriter, r *http.Request) {
	const route = "commit"
	t, ok := h.target(w, r)
	if !ok {
		return
	}
	var req protov2.CommitRequest
	raw, err := readSmallBody(r, 1<<20)
	if err != nil || ingest.CheckIJSON(raw, 4) != nil || decodeStrict(raw, &req) != nil {
		h.fail(w, route, &ingest.V2ReportError{Problem: protov2.ProblemInvalidRequest})
		return
	}
	res, err := h.receiver.Commit(r.Context(), t, req)
	if err != nil {
		h.fail(w, route, err)
		return
	}
	h.writeStatus(w, res)
}

// Status handles GET /results/{report_id}.
func (h *SensorResultsV2Handler) Status(w http.ResponseWriter, r *http.Request) {
	const route = "status"
	t, ok := h.target(w, r)
	if !ok {
		return
	}
	st, err := h.receiver.Status(r.Context(), t)
	if err != nil {
		h.fail(w, route, err)
		return
	}
	if !st.State.IsFinal() {
		w.Header().Set(protov2.HeaderRetryAfter, protov2.StatusRetryAfterSeconds)
	}
	h.writeJSON(w, http.StatusOK, st)
}

// Abandon handles DELETE /results/{report_id}.
func (h *SensorResultsV2Handler) Abandon(w http.ResponseWriter, r *http.Request) {
	const route = "abandon"
	t, ok := h.target(w, r)
	if !ok {
		return
	}
	if err := h.receiver.Abandon(r.Context(), t); err != nil {
		h.fail(w, route, err)
		return
	}
	w.Header().Set(protov2.HeaderProtocol, strconv.Itoa(protov2.ProtocolVersion))
	w.WriteHeader(http.StatusNoContent)
}

// Hello handles GET /hello: protocol level, features and limits (RFC-023 C3).
func (h *SensorResultsV2Handler) Hello(w http.ResponseWriter, _ *http.Request) {
	h.writeJSON(w, http.StatusOK, protov2.NewHello(h.receiver.Limits()))
}

func (h *SensorResultsV2Handler) writeStatus(w http.ResponseWriter, res *ingest.PutResult) {
	w.Header().Set("Location", protov2.ReportLocation(res.Status.ReportID))
	code := http.StatusOK
	if res.Created {
		code = http.StatusAccepted
	}
	if !res.Status.State.IsFinal() {
		w.Header().Set(protov2.HeaderRetryAfter, protov2.StatusRetryAfterSeconds)
	}
	h.writeJSON(w, code, res.Status)
}

func (h *SensorResultsV2Handler) writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", protov2.MediaTypeJSON)
	w.Header().Set(protov2.HeaderProtocol, strconv.Itoa(protov2.ProtocolVersion))
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// fail answers an error: a *V2ReportError is its problem; anything else is a
// server fault (500, retryable) and is logged, never echoed.
func (h *SensorResultsV2Handler) fail(w http.ResponseWriter, route string, err error) {
	var re *ingest.V2ReportError
	if errors.As(err, &re) {
		p := protov2.NewProblem(re.Problem).WithErrors(re.Errors)
		if p.Status == http.StatusRequestEntityTooLarge {
			p.WithLimit(h.limitFor(re.Problem))
		}
		p.Write(w)
		return
	}
	h.logger.Error("v2 results request failed", "route", route, "error", sanitizeLogField(err.Error()))
	protov2.NewProblem(protov2.ProblemInternal).Write(w)
}

func (h *SensorResultsV2Handler) limitFor(p protov2.ProblemType) int64 {
	l := h.receiver.Limits()
	if p == protov2.ProblemReportTooLarge {
		return int64(l.MaxFindingsPerSegment)
	}
	return l.MaxContentBytes
}

// readSmallBody reads a small JSON body (the commit request) with a cap.
func readSmallBody(r *http.Request, maxBytes int64) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > maxBytes {
		return nil, errCommitBodyTooLarge
	}
	return raw, nil
}

var errCommitBodyTooLarge = errors.New("commit body too large")

func decodeStrict(raw []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing data")
	}
	return nil
}
