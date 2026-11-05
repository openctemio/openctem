package handler

import (
	"context"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	toolsourceapp "github.com/openctemio/openctem/api/internal/app/toolsource"
	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/toolsource"
	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
)

// Tool source keys, sensor side (docs/architecture/tool-source-keys.md): the
// sensor holding a task of a scan job asks for the keys the job's
// organization stored for the job's tool. The organization is the
// command's (an organization sensor's own tenant; for a shared sensor, the
// tenant of the shared job it holds), never named by the sensor. Every
// refusal is command_not_found: the answer never tells another tenant's
// command from one that does not exist.

// ToolKeySource delivers an organization's keys for one task
// (*toolsourceapp.Service).
type ToolKeySource interface {
	ForTask(ctx context.Context, tenantID shared.ID, tool string, d toolsourceapp.Delivery) ([]toolsourceapp.Credential, error)
}

// SensorGrantReader reads an organization sensor's grant.
type SensorGrantReader interface {
	Get(ctx context.Context, tenantID, sensorID shared.ID) (*sensor.Grant, error)
}

// SetToolSources wires the tool source keys (nil: the route is not
// mounted). grants decides whether an organization sensor is trusted with
// keys; nil gives none to organization sensors (fail closed).
func (h *SensorControlV2Handler) SetToolSources(src ToolKeySource, grants SensorGrantReader) {
	h.toolKeys, h.toolGrants = src, grants
}

// HasToolSources reports whether the tool source key route is served.
func (h *SensorControlV2Handler) HasToolSources() bool { return h.toolKeys != nil && h.commands != nil }

// ToolCredentials handles POST /api/v2/sensor/commands/{command_id}/tool-credentials.
func (h *SensorControlV2Handler) ToolCredentials(w http.ResponseWriter, r *http.Request) {
	s := controlSensorForV2(w, r)
	if s == nil {
		return
	}
	commandID := chi.URLParam(r, "command_id")
	if protov2.ValidateUUID(commandID) != nil {
		protov2.NewProblem(protov2.ProblemInvalidID).Write(w)
		return
	}
	var req protov2.ToolCredentialsRequest
	if !decodeControl(w, r, h.limits.MaxControlBodyBytes, &req) {
		return
	}
	cmd, err := h.heldLiveCommand(r, s, commandID)
	if err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			protov2.NewProblem(protov2.ProblemCommandNotFound).Write(w)
			return
		}
		h.internal(w, "tool_credentials", err)
		return
	}
	job := sensor.JobOf(string(cmd.Type), cmd.Payload)
	tool := sensor.CanonicalTool(req.Tool)
	if !toolsource.JobMayUse(job.Tool, job.Capability, tool) {
		protov2.NewProblem(protov2.ProblemCommandNotFound).Write(w)
		return
	}
	out := protov2.ToolCredentialsResponse{Credentials: []protov2.ToolCredential{}, LocalFallback: !s.IsShared()}
	if h.trustedWithKeys(r.Context(), s) {
		creds, err := h.toolKeys.ForTask(r.Context(), cmd.TenantID, tool,
			toolsourceapp.Delivery{SensorID: s.ID, CommandID: cmd.ID})
		if err != nil {
			h.internal(w, "tool_credentials", err)
			return
		}
		for _, c := range creds {
			out.Credentials = append(out.Credentials, protov2.ToolCredential{Name: c.Name, Value: c.Value})
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	writeV2JSON(w, http.StatusOK, out)
}

// heldLiveCommand is the command commandID that sensor s holds now (its id
// and the lease epoch it states), acknowledged or running; shared.ErrNotFound
// for anything else. The command is read in the organization it belongs to:
// an organization sensor's own, or the held shared job's.
func (h *SensorControlV2Handler) heldLiveCommand(r *http.Request, s *sensor.Sensor, commandID string) (*commanddom.Command, error) {
	var (
		cmd *commanddom.Command
		err error
	)
	if s.IsShared() {
		cmd, err = h.commands.service.HeldSharedJob(r.Context(), s, commandID)
	} else {
		cmd, err = h.commands.service.Get(r.Context(), s.TenantID.String(), commandID)
	}
	if err != nil {
		return nil, err
	}
	epoch := leaseEpochHeader(r)
	held := cmd.SensorID != nil && *cmd.SensorID == s.ID && epoch != nil && *epoch == cmd.LeaseEpoch
	live := cmd.Status == commanddom.CommandStatusAcknowledged || cmd.Status == commanddom.CommandStatusRunning
	if !held || !live {
		return nil, shared.ErrNotFound
	}
	return cmd, nil
}

// trustedWithKeys reports whether s may receive an organization's keys: a
// shared sensor is the platform's own; an organization sensor only when its
// grant is trusted (an unreadable grant gives none).
func (h *SensorControlV2Handler) trustedWithKeys(ctx context.Context, s *sensor.Sensor) bool {
	if s.IsShared() {
		return true
	}
	if h.toolGrants == nil || s.TenantID == nil {
		return false
	}
	g, err := h.toolGrants.Get(ctx, *s.TenantID, s.ID)
	if err != nil || g == nil {
		if err != nil {
			h.logger.Warn("cannot read the sensor's grant; no tool source keys delivered", "sensor_id", s.ID.String(), "error", err)
		}
		return false
	}
	return g.Effective().TrustLevel == sensor.TrustTrusted
}
