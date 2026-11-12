package handler

// Lookup job routes (docs/architecture/certificate-transparency-monitoring.md),
// under /api/v2/sensor: a platform (instance-scope) sensor asks for its next
// lookup job and reports the answer. An organization's sensor gets 403
// scope-denied on both, whatever it reports.

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/api/internal/app/lookupjob"
	lookupjobdom "github.com/openctemio/openctem/api/pkg/domain/lookupjob"
	"github.com/openctemio/openctem/api/pkg/logger"
	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
)

// LookupJobResultLimit bounds the body of POST done (the answer's own bound
// plus room for the envelope).
const LookupJobResultLimit = lookupjob.MaxResultBytes + 64<<10

// LookupJobHandler serves the lookup job routes.
type LookupJobHandler struct {
	svc    *lookupjob.Service
	logger *logger.Logger
}

// NewLookupJobHandler creates the handler.
func NewLookupJobHandler(svc *lookupjob.Service, log *logger.Logger) *LookupJobHandler {
	return &LookupJobHandler{svc: svc, logger: log.With("handler", "lookup_jobs")}
}

func (h *LookupJobHandler) writeErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, lookupjob.ErrNotEligible):
		protov2.NewProblem(protov2.ProblemScopeDenied).Write(w)
	case errors.Is(err, lookupjobdom.ErrClosed):
		protov2.NewProblem(protov2.ProblemCommandNotFound).Write(w)
	default:
		h.logger.Error("lookup jobs", "error", logger.SanitizeError(err))
		protov2.NewProblem(protov2.ProblemInternal).Write(w)
	}
}

// Next answers GET /api/v2/sensor/lookups/next: 200 with the job and its
// signed statement, 204 with a Retry-After (seconds) when there is none.
func (h *LookupJobHandler) Next(w http.ResponseWriter, r *http.Request) {
	s := SensorFromContext(r.Context())
	if s == nil {
		protov2.NewProblem(protov2.ProblemUnauthenticated).Write(w)
		return
	}
	n, retry, err := h.svc.Next(r.Context(), s)
	if err != nil {
		h.writeErr(w, err)
		return
	}
	if n == nil {
		if retry > 0 {
			w.Header().Set("Retry-After", strconv.Itoa(int(retry/time.Second)))
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(n)
}

// Done answers POST /api/v2/sensor/lookups/{job_id}/done.
func (h *LookupJobHandler) Done(w http.ResponseWriter, r *http.Request) {
	s := SensorFromContext(r.Context())
	if s == nil {
		protov2.NewProblem(protov2.ProblemUnauthenticated).Write(w)
		return
	}
	var res lookupjob.Result
	dec := json.NewDecoder(io.LimitReader(r.Body, LookupJobResultLimit))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&res); err != nil {
		protov2.NewProblem(protov2.ProblemInvalidJSON).Write(w)
		return
	}
	if err := h.svc.Done(r.Context(), s, chi.URLParam(r, "job_id"), res); err != nil {
		h.writeErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
