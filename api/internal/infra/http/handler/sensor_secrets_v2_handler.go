package handler

// Task secrets, sensor side (docs/architecture/task-secrets.md): the sensor
// holding a task of a claimed job fetches the values of the secret refs the
// job's signed payload lists, sealed to a single-use key in its signed
// request. Only a request authenticated by the sensor's key-bound
// signature is answered (a bearer key cannot vouch for the reply key in the
// body); the lease epoch is the one in the signed body (a header is never
// read). Every refusal is command_not_found: the answer never tells another
// tenant's command, a lost lease or an exhausted count from a command that
// does not exist.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/openctemio/contract/secretref"

	tasksecretapp "github.com/openctemio/openctem/api/internal/app/tasksecret"
	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
)

// TaskSecrets answers a fetch (*tasksecretapp.Service).
type TaskSecrets interface {
	Fetch(ctx context.Context, in tasksecretapp.FetchInput) (*secretref.SealedAnswer, error)
}

// SetTaskSecrets wires the task secrets fetch (nil: the route is not
// mounted).
func (h *SensorControlV2Handler) SetTaskSecrets(t TaskSecrets) { h.secrets = t }

// HasTaskSecrets reports whether the task secrets route is served.
func (h *SensorControlV2Handler) HasTaskSecrets() bool { return h.secrets != nil }

// TaskSecrets handles POST /api/v2/sensor/commands/{command_id}/secrets.
func (h *SensorControlV2Handler) TaskSecrets(w http.ResponseWriter, r *http.Request) {
	s := controlSensorForV2(w, r)
	if s == nil {
		return
	}
	notFound := func() {
		w.Header().Set("Cache-Control", "no-store")
		protov2.NewProblem(protov2.ProblemCommandNotFound).Write(w)
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, tasksecretapp.MaxRequestBytes+1))
	if err != nil || len(body) > tasksecretapp.MaxRequestBytes {
		notFound()
		return
	}
	ans, err := h.secrets.Fetch(r.Context(), tasksecretapp.FetchInput{
		Sensor: s, KeyBound: sensorIdentityFromContext(r.Context()).KeyBound(),
		CommandID: chi.URLParam(r, "command_id"), Body: body,
	})
	clear(body)
	if errors.Is(err, tasksecretapp.ErrRefused) {
		notFound()
		return
	}
	if err != nil {
		w.Header().Set("Cache-Control", "no-store")
		h.internal(w, "task_secrets", err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", secretref.ContentType)
	w.Header().Set(protov2.HeaderProtocol, strconv.Itoa(protov2.ProtocolVersion))
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(ans)
}
