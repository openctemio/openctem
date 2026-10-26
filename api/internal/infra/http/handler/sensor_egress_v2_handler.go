package handler

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	proxypoolapp "github.com/openctemio/openctem/api/internal/app/proxypool"
	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/proxypool"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
)

// Proxy pools for scan traffic, sensor side (docs/architecture/sensor-proxies.md):
// the leasing sensor fetches its job's pool credentials and reports what it
// saw through each endpoint. Every refusal is command_not_found: the answer
// never tells another tenant's pool or command from one that does not exist.

// SetEgress wires the proxy pool service (nil: the routes are not mounted).
func (h *SensorControlV2Handler) SetEgress(svc *proxypoolapp.Service) { h.egress = svc }

// HasEgress reports whether the proxy pool routes are served.
func (h *SensorControlV2Handler) HasEgress() bool { return h.egress != nil && h.commands != nil }

// egressReportGrace is how long after a job ends its sensor may still send
// the job's egress report.
const egressReportGrace = 15 * time.Minute

// leasedCommand is the command the authenticated organization sensor holds
// under the lease epoch it states, or nil after writing the problem. A
// shared sensor never uses an organization's pool.
func (h *SensorControlV2Handler) leasedCommand(w http.ResponseWriter, r *http.Request, requireLive bool) (*sensor.Sensor, *commanddom.Command) {
	s := controlSensorForV2(w, r)
	if s == nil {
		return nil, nil
	}
	commandID := chi.URLParam(r, "command_id")
	if protov2.ValidateUUID(commandID) != nil {
		protov2.NewProblem(protov2.ProblemInvalidID).Write(w)
		return nil, nil
	}
	if s.IsShared() || s.TenantID == nil {
		protov2.NewProblem(protov2.ProblemCommandNotFound).Write(w)
		return nil, nil
	}
	cmd, err := h.commands.service.Get(r.Context(), s.TenantID.String(), commandID)
	if err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			protov2.NewProblem(protov2.ProblemCommandNotFound).Write(w)
			return nil, nil
		}
		h.internal(w, "egress", err)
		return nil, nil
	}
	epoch := leaseEpochHeader(r)
	held := cmd.SensorID != nil && *cmd.SensorID == s.ID && epoch != nil && *epoch == cmd.LeaseEpoch
	live := cmd.Status == commanddom.CommandStatusAcknowledged || cmd.Status == commanddom.CommandStatusRunning
	// A report may follow the end of the job, but only shortly: an old
	// lease never keeps moving a pool's health.
	recent := live || (cmd.CompletedAt != nil && time.Since(*cmd.CompletedAt) <= egressReportGrace)
	if !held || (requireLive && !live) || !recent {
		protov2.NewProblem(protov2.ProblemCommandNotFound).Write(w)
		return nil, nil
	}
	return s, cmd
}

// EgressCredentials handles POST /api/v2/sensor/commands/{command_id}/egress-credentials:
// the credentials of the proxy pool the sensor's jobs use now, for the
// sensor holding the command's live lease. Never logged, never stored with
// the command.
func (h *SensorControlV2Handler) EgressCredentials(w http.ResponseWriter, r *http.Request) {
	s, cmd := h.leasedCommand(w, r, true)
	if cmd == nil {
		return
	}
	var req protov2.EgressCredentialsRequest
	if !decodeControl(w, r, h.limits.MaxControlBodyBytes, &req) {
		return
	}
	var creds []proxypoolapp.Credential
	var err error
	if cmd.Type == commanddom.CommandTypeProxyTest {
		// A test names its own pool (a draft pool no sensor uses yet); the
		// credentials are those of that pool only, under this command's lease.
		creds, err = h.egress.TestCredentialsFor(r.Context(), cmd, req.PoolID)
	} else {
		creds, err = h.egress.CredentialsFor(r.Context(), *s.TenantID, s.ID, req.PoolID)
	}
	if err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			protov2.NewProblem(protov2.ProblemCommandNotFound).Write(w)
			return
		}
		h.internal(w, "egress_credentials", err)
		return
	}
	out := protov2.EgressCredentialsResponse{Credentials: make([]protov2.EgressCredential, 0, len(creds))}
	for _, c := range creds {
		out.Credentials = append(out.Credentials, protov2.EgressCredential{EndpointID: c.EndpointID, Username: c.Username, Password: c.Password})
	}
	w.Header().Set("Cache-Control", "no-store")
	writeV2JSON(w, http.StatusOK, out)
}

// EgressReport handles POST /api/v2/sensor/commands/{command_id}/egress-report:
// the sensor's per-endpoint report of the job, folded into the endpoints'
// health. Accepted from the sensor holding the command (also just after it
// ended); the pool must be the tenant's.
func (h *SensorControlV2Handler) EgressReport(w http.ResponseWriter, r *http.Request) {
	s, cmd := h.leasedCommand(w, r, false)
	if cmd == nil {
		return
	}
	var req protov2.EgressReportRequest
	if !decodeControl(w, r, h.limits.MaxControlBodyBytes, &req) {
		return
	}
	if len(req.Endpoints) > protov2.MaxEgressReportEndpoints {
		protov2.NewProblem(protov2.ProblemInvalidRequest).Write(w)
		return
	}
	rep := proxypoolapp.Report{PoolID: req.PoolID, Endpoints: make(map[string]proxypool.Signal, len(req.Endpoints))}
	for _, e := range req.Endpoints {
		rep.Endpoints[e.EndpointID] = proxypool.Signal{OK: e.OK, ProxyDown: e.ProxyDown, ProxyAuth: e.ProxyAuth,
			TargetUnreachable: e.TargetUnreachable, TargetRefused: e.TargetRefused,
			HandshakeMsP50: e.HandshakeMsP50, HandshakeMsP95: e.HandshakeMsP95, LastError: e.LastError}
	}
	var err error
	if cmd.Type == commanddom.CommandTypeProxyTest {
		// The attempts of a test move the health of the pool it names.
		err = h.egress.ApplyTestReport(r.Context(), cmd, s.ID, rep)
	} else {
		err = h.egress.ApplyReport(r.Context(), *s.TenantID, s.ID, rep)
	}
	if err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			protov2.NewProblem(protov2.ProblemCommandNotFound).Write(w)
			return
		}
		h.internal(w, "egress_report", err)
		return
	}
	w.Header().Set(protov2.HeaderProtocol, strconv.Itoa(protov2.ProtocolVersion))
	w.WriteHeader(http.StatusNoContent)
}
