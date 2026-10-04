package handler

// Sensor protocol v2 control plane (RFC-029,
// docs/rfcs/RFC-029-sensor-protocol-v2-and-sdk-stability.md): heartbeat,
// commands, suppressions, fingerprint queries and key renewal under
// /api/v2/sensor. Each handler calls the same application service as its
// protocol v1 counterpart; only the wire differs. Identity is the sensor key
// (the v2 authenticator put the sensor in the context); no request header or
// body field can name another sensor or tenant.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/api/internal/app"
	"github.com/openctemio/openctem/api/internal/app/command"
	"github.com/openctemio/openctem/api/internal/app/ingest"
	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
)

// SensorControlV2Handler serves the v2 control-plane routes. Any of its
// collaborators may be nil; Features lists only what is wired.
type SensorControlV2Handler struct {
	ingest              *IngestHandler
	commands            *CommandHandler
	suppressions        *SuppressionHandler
	suppressionsEnabled func(ctx context.Context, tenantID string) bool
	limits              protov2.Limits
	logger              *logger.Logger
}

// NewSensorControlV2Handler builds the handler. suppressionsEnabled reports
// whether the suppressions module is on for a tenant (nil: always on).
func NewSensorControlV2Handler(ih *IngestHandler, ch *CommandHandler, sh *SuppressionHandler,
	suppressionsEnabled func(ctx context.Context, tenantID string) bool, log *logger.Logger,
) *SensorControlV2Handler {
	return &SensorControlV2Handler{
		ingest: ih, commands: ch, suppressions: sh, suppressionsEnabled: suppressionsEnabled,
		limits: protov2.DefaultLimits(), logger: log.With("handler", "sensor-control-v2"),
	}
}

// Features are the RFC-029 features this handler can serve, in hello order.
func (h *SensorControlV2Handler) Features() []string {
	var out []string
	if h.ingest != nil {
		out = append(out, protov2.FeatureHeartbeat)
	}
	if h.commands != nil {
		out = append(out, protov2.FeatureCommands)
	}
	if h.suppressions != nil {
		out = append(out, protov2.FeatureSuppressions)
	}
	if h.ingest != nil {
		out = append(out, protov2.FeatureFingerprints, protov2.FeatureKeys, protov2.FeatureLoad)
	}
	if h.commands != nil {
		out = append(out, protov2.FeatureRelease)
	}
	if h.ingest != nil && h.ingest.sensorService.SupportsManifests() {
		out = append(out, protov2.FeatureManifest)
	}
	if h.ingest != nil {
		out = append(out, protov2.FeatureLocalPolicy)
	}
	if h.commands != nil {
		out = append(out, protov2.FeatureCapacity)
	}
	return out
}

// HasIngest, HasCommands and HasSuppressions tell route registration which
// routes to mount.
func (h *SensorControlV2Handler) HasIngest() bool { return h.ingest != nil }

// HasCommands reports whether the command routes are served.
func (h *SensorControlV2Handler) HasCommands() bool { return h.commands != nil }

// HasSuppressions reports whether the suppressions route is served.
func (h *SensorControlV2Handler) HasSuppressions() bool { return h.suppressions != nil }

// sensorForV2 returns the authenticated tenant sensor, or writes 401 / 403
// scope-denied (a tenant-less platform sensor, RFC-026 §10.1) and returns nil.
func sensorForV2(w http.ResponseWriter, r *http.Request) *sensor.Sensor {
	s := SensorFromContext(r.Context())
	if s == nil {
		protov2.NewProblem(protov2.ProblemUnauthenticated).Write(w)
		return nil
	}
	if s.TenantID == nil {
		protov2.NewProblem(protov2.ProblemScopeDenied).Write(w)
		return nil
	}
	return s
}

// decodeControl reads a control-plane JSON body of at most maxBytes into v.
// An empty body leaves v at its zero value. Decoding is lenient: unknown
// members are ignored (RFC-029 D4). It writes the problem and returns false
// on a refused body.
func decodeControl(w http.ResponseWriter, r *http.Request, maxBytes int64, v any) bool {
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxBytes+1))
	if err != nil {
		protov2.NewProblem(protov2.ProblemInvalidRequest).Write(w)
		return false
	}
	if int64(len(raw)) > maxBytes {
		protov2.NewProblem(protov2.ProblemContentTooLarge).WithLimit(maxBytes).Write(w)
		return false
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return true
	}
	if ct := r.Header.Get("Content-Type"); ct != "" {
		mt, _, err := mime.ParseMediaType(ct)
		if err != nil || mt != protov2.MediaTypeJSON {
			protov2.NewProblem(protov2.ProblemUnsupportedMediaType).WithAccept(protov2.MediaTypeJSON).Write(w)
			return false
		}
	}
	if err := json.Unmarshal(raw, v); err != nil {
		protov2.NewProblem(protov2.ProblemInvalidRequest).Write(w)
		return false
	}
	return true
}

func writeV2JSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", protov2.MediaTypeJSON)
	w.Header().Set(protov2.HeaderProtocol, strconv.Itoa(protov2.ProtocolVersion))
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func (h *SensorControlV2Handler) internal(w http.ResponseWriter, route string, err error) {
	h.logger.Error("v2 sensor request failed", "route", route, "error", sanitizeLogField(err.Error()))
	protov2.NewProblem(protov2.ProblemInternal).Write(w)
}

// =============================================================================
// Heartbeat
// =============================================================================

// Heartbeat handles POST /api/v2/sensor/heartbeat (RFC-029 §4.3). The body is
// the v1 heartbeat body; the doorbell is always on. A disabled sensor reaches
// here only on this route (the v2 authenticator lets it through as paused)
// and is told to pause; nothing is written for it.
func (h *SensorControlV2Handler) Heartbeat(w http.ResponseWriter, r *http.Request) {
	s := sensorForV2(w, r)
	if s == nil {
		return
	}
	var req HeartbeatRequest
	if !decodeControl(w, r, h.limits.MaxControlBodyBytes, &req) {
		return
	}
	start := time.Now()
	defer func() { h.ingest.observeHeartbeat(time.Since(start)) }()
	id := sensorIdentityFromContext(r.Context())
	// The doorbell rings first so the write stores the deadline of the
	// interval just advised (RFC-035 §5.6); a v2 sensor always follows it.
	var hints sensor.HeartbeatHints
	if h.ingest.doorbell != nil {
		hints = h.ingest.doorbell.Ring(r.Context(), app.DoorbellRequest{Identity: id, Aware: true})
	}
	if !id.Paused {
		data := heartbeatData(r, &req, 2)
		data.AdvisedSeconds, data.DoorbellAware = hints.NextHeartbeatSeconds, true
		if err := h.ingest.sensorService.UpdateHeartbeat(r.Context(), s.ID, data); err != nil {
			// As v1: the heartbeat answers even when the write failed.
			h.logger.Error("failed to update sensor heartbeat", "error", err, "sensor_id", s.ID)
		}
	}

	resp := protov2.HeartbeatResponse{
		SensorID: s.ID.String(), TenantID: s.TenantID.String(),
		Status: protov2.HeartbeatStatusOK, Actions: []string{}, CancelCommandIDs: []string{},
	}
	if id.Paused {
		resp.Status = protov2.HeartbeatStatusPaused
	}
	if h.ingest.doorbell != nil {
		resp.PendingJobs = hints.PendingJobs
		resp.ConfigVersion = hints.ConfigVersion
		resp.NextHeartbeatSeconds = hints.NextHeartbeatSeconds
		for _, a := range hints.Actions {
			resp.Actions = append(resp.Actions, string(a))
		}
	}
	if ids := h.ingest.commandsToCancel(r.Context(), s, &req); len(ids) > 0 {
		resp.CancelCommandIDs = ids
		resp.Actions = append(resp.Actions, protov2.ActionCancel)
	}
	// RFC-033: a sensor that registers manifests and echoes a digest the
	// platform does not have as current is asked to send it again.
	// With slim heartbeats switched off (SENSOR_SLIM_HEARTBEAT=false), a
	// slim one is asked for the manifest too: the answer says
	// omit_inventory false and the sensor goes back to full heartbeats.
	if d := manifestDigestFor(&req, 2); !id.Paused && d != "" && h.ingest.sensorService.SupportsManifests() &&
		(d != s.ManifestDigest || (req.Tools == nil && !h.ingest.sensorService.SlimHeartbeat())) {
		resp.Actions = append(resp.Actions, protov2.ActionSendManifest)
	}
	writeV2JSON(w, http.StatusOK, resp)
}

// PutManifest handles PUT /api/v2/sensor/manifest (RFC-033): the sensor
// registers what it is. The body is a JSON manifest (schema 1, at most
// sensor.MaxManifestBytes); unknown members and unknown tools or
// capabilities are ignored and listed, never an error.
func (h *SensorControlV2Handler) PutManifest(w http.ResponseWriter, r *http.Request) {
	s := sensorForV2(w, r)
	if s == nil {
		return
	}
	if ct := r.Header.Get("Content-Type"); ct != "" {
		mt, _, err := mime.ParseMediaType(ct)
		if err != nil || mt != protov2.MediaTypeJSON {
			protov2.NewProblem(protov2.ProblemUnsupportedMediaType).WithAccept(protov2.MediaTypeJSON).Write(w)
			return
		}
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, sensor.MaxManifestBytes+1))
	if err != nil {
		protov2.NewProblem(protov2.ProblemInvalidRequest).Write(w)
		return
	}
	if len(raw) > sensor.MaxManifestBytes {
		protov2.NewProblem(protov2.ProblemContentTooLarge).WithLimit(sensor.MaxManifestBytes).Write(w)
		return
	}
	res, err := h.ingest.sensorService.RegisterManifest(r.Context(), s, raw)
	switch {
	case err == nil:
	case errors.Is(err, sensor.ErrManifestTooLarge):
		protov2.NewProblem(protov2.ProblemContentTooLarge).WithLimit(sensor.MaxManifestBytes).Write(w)
		return
	case errors.Is(err, sensor.ErrManifestSchemaUnsupported):
		protov2.NewProblem(protov2.ProblemManifestSchemaUnsupported).Write(w)
		return
	case errors.Is(err, sensor.ErrManifestInvalid):
		protov2.NewProblem(protov2.ProblemManifestInvalid).Write(w)
		return
	case errors.Is(err, app.ErrManifestSensorInactive):
		protov2.NewProblem(protov2.ProblemScopeDenied).Write(w)
		return
	case errors.Is(err, app.ErrManifestUnavailable):
		h.logger.Warn("sensor manifest not stored", "sensor_id", s.ID, "error", err)
		protov2.NewProblem(protov2.ProblemUnavailable).Write(w)
		return
	default:
		h.logger.Error("failed to register sensor manifest", "sensor_id", s.ID, "error", err)
		protov2.NewProblem(protov2.ProblemInternal).Write(w)
		return
	}
	out := protov2.ManifestResponse{
		ManifestDigest: res.Digest,
		Changed:        res.Changed,
		Policy:         manifestPolicyOut(res.Policy),
		Heartbeat:      protov2.ManifestHeartbeat{OmitInventory: res.OmitInventory},
		Accepted: protov2.ManifestAccepted{
			Tools:        nonNilStrings(res.AcceptedTools),
			Capabilities: nonNilStrings(res.AcceptedCapabilities),
		},
		Ignored: make([]protov2.ManifestIgnored, 0, len(res.Ignored)),
	}
	for _, i := range res.Ignored {
		out.Ignored = append(out.Ignored, protov2.ManifestIgnored{Path: i.Path, Value: i.Value, Reason: i.Reason})
	}
	writeV2JSON(w, http.StatusOK, out)
}

// GetManifest handles GET /api/v2/sensor/manifest (RFC-033 §6.12): the
// current manifest digest and the policy as it stands now, which the sensor
// re-reads when its heartbeat's config_version changes. 404
// manifest-not-found when it registered none.
func (h *SensorControlV2Handler) GetManifest(w http.ResponseWriter, r *http.Request) {
	s := sensorForV2(w, r)
	if s == nil {
		return
	}
	res, err := h.ingest.sensorService.ManifestState(s)
	if err != nil {
		protov2.NewProblem(protov2.ProblemManifestNotFound).Write(w)
		return
	}
	writeV2JSON(w, http.StatusOK, protov2.ManifestStateResponse{
		ManifestDigest: res.Digest,
		Policy:         manifestPolicyOut(res.Policy),
		Heartbeat:      protov2.ManifestHeartbeat{OmitInventory: res.OmitInventory},
	})
}

func manifestPolicyOut(p sensor.ManifestPolicy) protov2.ManifestPolicy {
	return protov2.ManifestPolicy{
		AllowedTools:        nonNilStrings(p.AllowedTools),
		AllowedCapabilities: nonNilStrings(p.AllowedCapabilities),
		MaxJobs:             p.MaxJobs,
	}
}

func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// freeSlotsNow is how many scan commands the poll may offer the sensor: its
// free slots (effective capacity minus the commands it holds, narrowed by a
// fresh load report). The sensor was read when it authenticated, so the
// count is that of this request.
func freeSlotsNow(s *sensor.Sensor) *int {
	n := s.FreeSlots(time.Now())
	return &n
}

// heartbeatData maps a heartbeat body (v1 and v2 share it) to the service
// input, with the protocol the heartbeat arrived on and the client's
// User-Agent for the fleet's protocol telemetry (RFC-029 §5.3).
func heartbeatData(r *http.Request, req *HeartbeatRequest, protocol int) app.SensorHeartbeatData {
	return app.SensorHeartbeatData{
		Version:    req.Version,
		Hostname:   req.Hostname,
		InstanceID: req.InstanceID,
		// The connection's address under the trusted-proxy rule, so a sensor
		// cannot claim someone else's address.
		IPAddress:     getClientIP(r),
		CPUPercent:    req.CPUPercent,
		MemoryPercent: req.MemoryPercent,
		CurrentJobs:   req.ActiveJobs,
		Region:        req.Region,
		DiskReadMBPS:  req.DiskReadMBPS,
		DiskWriteMBPS: req.DiskWriteMBPS,
		NetworkRxMBPS: req.NetworkRxMBPS,
		NetworkTxMBPS: req.NetworkTxMBPS,
		Outbox:        req.Outbox.toOutboxStats(),
		UptimeSeconds: req.Uptime,
		Protocol:      protocol,
		UserAgent:     r.UserAgent(),
		Report:        req.capabilityReport(),
		Load:          req.loadReport(),
		// The SDK that reports its queue lists what it runs ("running",
		// left out when empty); one that does not renews everything it holds.
		Running:         req.Running,
		RunningReported: req.Queue != nil,
		Build:           req.buildReport(),
		// v1 has no manifest: its heartbeat is always the source.
		ManifestDigest: manifestDigestFor(req, protocol),
		Content:        slimContentFor(req, protocol),
		Control:        sensor.ParseControlReport(req.Control),
		// Untrusted; sanitized by the service before it is stored.
		LocalPolicy: req.LocalPolicy,
	}
}

// slimContentFor is a v2 heartbeat's content block, bounded; nil on v1.
func slimContentFor(req *HeartbeatRequest, protocol int) []sensor.ReportedContent {
	if protocol < 2 || req.Content == nil {
		return nil
	}
	return req.Content[:min(len(req.Content), sensor.MaxReportedTools*sensor.MaxReportedContentPerTool)]
}

// manifestDigestFor is the manifest digest a v2 heartbeat echoes, bounded;
// "" on v1.
func manifestDigestFor(req *HeartbeatRequest, protocol int) string {
	if protocol < 2 || len(req.ManifestDigest) > maxManifestDigestLen {
		return ""
	}
	return req.ManifestDigest
}

// maxManifestDigestLen is "sha256:" + 64 hex characters.
const maxManifestDigestLen = 71

// =============================================================================
// Commands
// =============================================================================

// PollCommands handles GET /api/v2/sensor/commands?limit=n: the commands this
// sensor may claim now, by the v1 poll's predicate, in the fair dispatch
// order. With the capacity feature they come back already claimed (claim-N).
func (h *SensorControlV2Handler) PollCommands(w http.ResponseWriter, r *http.Request) {
	s := sensorForV2(w, r)
	if s == nil {
		return
	}
	limit := parseQueryInt(r.URL.Query().Get("limit"), 10)
	var (
		cmds []*commanddom.Command
		err  error
	)
	if protov2.HasFeature(r.Header.Values(protov2.HeaderSensorFeatures), protov2.FeatureCapacity) {
		// Claim-N: the listed commands are claimed for this sensor.
		cmds, err = h.commands.service.Claim(r.Context(), command.ClaimInput{
			TenantID: s.TenantID.String(), SensorID: s.ID.String(),
			Capabilities: s.EffectiveCapabilities(), Limit: limit,
			MaxJobs: s.EffectiveMaxConcurrentJobs(), ReportedFree: freeSlotsNow(s),
		})
	} else {
		cmds, err = h.commands.service.Poll(r.Context(), command.PollInput{
			TenantID: s.TenantID.String(), SensorID: s.ID.String(),
			Capabilities: s.EffectiveCapabilities(), Limit: limit,
			MaxScanCommands: freeSlotsNow(s),
		})
	}
	if err != nil {
		h.internal(w, "commands", err)
		return
	}
	out := protov2.CommandList{Commands: make([]protov2.Command, 0, len(cmds))}
	for _, c := range cmds {
		out.Commands = append(out.Commands, toV2Command(c))
	}
	writeV2JSON(w, http.StatusOK, out)
}

// ClaimCommand handles POST /api/v2/sensor/commands/{command_id}/claim.
func (h *SensorControlV2Handler) ClaimCommand(w http.ResponseWriter, r *http.Request) {
	h.transition(w, r, command.TransitionClaim)
}

// StartCommand handles POST /api/v2/sensor/commands/{command_id}/start.
func (h *SensorControlV2Handler) StartCommand(w http.ResponseWriter, r *http.Request) {
	h.transition(w, r, command.TransitionStart)
}

// CompleteCommand handles POST /api/v2/sensor/commands/{command_id}/complete.
func (h *SensorControlV2Handler) CompleteCommand(w http.ResponseWriter, r *http.Request) {
	h.transition(w, r, command.TransitionComplete)
}

// ReleaseCommand handles POST /api/v2/sensor/commands/{command_id}/release
// (RFC-030 §5.12): the sensor that holds a claimed or running command hands
// it back, and it returns to the queue at once (pending, unpinned, zone kept)
// instead of waiting for the reaper. A draining sensor releases what it will
// not finish. A repeat of a release that already happened answers the
// command as it is now.
func (h *SensorControlV2Handler) ReleaseCommand(w http.ResponseWriter, r *http.Request) {
	s := sensorForV2(w, r)
	if s == nil {
		return
	}
	commandID := chi.URLParam(r, "command_id")
	if protov2.ValidateUUID(commandID) != nil {
		protov2.NewProblem(protov2.ProblemInvalidID).Write(w)
		return
	}
	var req protov2.ReleaseRequest
	if !decodeControl(w, r, h.limits.MaxControlBodyBytes, &req) {
		return
	}
	res, err := h.commands.service.Release(r.Context(), command.ReleaseInput{
		TenantID: s.TenantID.String(), SensorID: s.ID.String(), CommandID: commandID, Reason: req.Reason,
	})
	if err != nil {
		h.transitionFailed(w, "release", err)
		return
	}
	writeV2JSON(w, http.StatusOK, toV2Command(res.Command))
}

// FailCommand handles POST /api/v2/sensor/commands/{command_id}/fail.
func (h *SensorControlV2Handler) FailCommand(w http.ResponseWriter, r *http.Request) {
	h.transition(w, r, command.TransitionFail)
}

func (h *SensorControlV2Handler) transition(w http.ResponseWriter, r *http.Request, t command.Transition) {
	s := sensorForV2(w, r)
	if s == nil {
		return
	}
	commandID := chi.URLParam(r, "command_id")
	if protov2.ValidateUUID(commandID) != nil {
		protov2.NewProblem(protov2.ProblemInvalidID).Write(w)
		return
	}
	in := command.TransitionInput{TenantID: s.TenantID.String(), SensorID: s.ID.String(), CommandID: commandID,
		LeaseEpoch: leaseEpochHeader(r)}
	switch t {
	case command.TransitionComplete:
		var req protov2.CompleteRequest
		if !decodeControl(w, r, protov2.MaxCompleteBodyBytes, &req) {
			return
		}
		in.Result = req.Result
	case command.TransitionFail:
		var req protov2.FailRequest
		if !decodeControl(w, r, h.limits.MaxControlBodyBytes, &req) {
			return
		}
		in.ErrorMessage = req.ErrorMessage
	default:
		var ignored struct{}
		if !decodeControl(w, r, h.limits.MaxControlBodyBytes, &ignored) {
			return
		}
	}

	res, err := h.commands.service.Transition(r.Context(), t, in)
	if err != nil {
		h.transitionFailed(w, string(t), err)
		return
	}
	// Side effects run on the real transition only, never on a replay.
	if !res.Replayed {
		switch t {
		case command.TransitionStart:
			h.commands.triggerPipelineStarted(r.Context(), res.Command)
		case command.TransitionComplete:
			h.commands.triggerPipelineProgression(r.Context(), res.Command)
			h.commands.triggerValidationEvidence(res.Command)
			h.commands.triggerSimulationFinalize(res.Command)
			h.commands.triggerCoverageAutoResolve(res.Command)
		case command.TransitionFail:
			h.commands.triggerPipelineFailed(r.Context(), res.Command, in.ErrorMessage)
		}
	}
	writeV2JSON(w, http.StatusOK, toV2Command(res.Command))
}

func (h *SensorControlV2Handler) transitionFailed(w http.ResponseWriter, route string, err error) {
	var invalid *command.InvalidTransitionError
	switch {
	case errors.Is(err, shared.ErrNotFound):
		protov2.NewProblem(protov2.ProblemCommandNotFound).Write(w)
	case errors.As(err, &invalid):
		protov2.NewProblem(protov2.ProblemInvalidTransition).WithState(invalid.State).Write(w)
	case errors.Is(err, command.ErrCommandClaimed):
		protov2.NewProblem(protov2.ProblemCommandClaimed).Write(w)
	case errors.Is(err, command.ErrTransitionConflict):
		protov2.NewProblem(protov2.ProblemTransitionConflict).Write(w)
	default:
		h.internal(w, route, err)
	}
}

// leaseEpochHeader is the lease epoch a sensor states it holds the command
// under (X-OpenCTEM-Lease-Epoch, the lease_epoch it was given); nil when
// absent or not a number.
func leaseEpochHeader(r *http.Request) *int {
	v := strings.TrimSpace(r.Header.Get(protov2.HeaderLeaseEpoch))
	if v == "" {
		return nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return nil
	}
	return &n
}

// toV2Command is the v2 representation of a command.
func toV2Command(c *commanddom.Command) protov2.Command {
	out := protov2.Command{
		ID:             c.ID.String(),
		Type:           string(c.Type),
		Priority:       string(c.Priority),
		Status:         string(c.Status),
		Payload:        rawOrNull(c.Payload),
		CreatedAt:      c.CreatedAt.UTC(),
		ExpiresAt:      utcPtr(c.ExpiresAt),
		AcknowledgedAt: utcPtr(c.AcknowledgedAt),
		StartedAt:      utcPtr(c.StartedAt),
		CompletedAt:    utcPtr(c.CompletedAt),
		ErrorMessage:   c.ErrorMessage,
		Result:         rawOrNull(c.Result),
		LeaseEpoch:     c.LeaseEpoch,
		LeaseExpiresAt: utcPtr(c.LeaseExpiresAt),
	}
	if c.SensorID != nil {
		id := c.SensorID.String()
		out.SensorID = &id
	}
	return out
}

func rawOrNull(b json.RawMessage) json.RawMessage {
	if len(strings.TrimSpace(string(b))) == 0 {
		return json.RawMessage("null")
	}
	return b
}

func utcPtr(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	u := t.UTC()
	return &u
}

// =============================================================================
// Suppressions
// =============================================================================

// Suppressions handles GET /api/v2/sensor/suppressions (RFC-029 §4.5): the
// v1 document with a strong ETag; If-None-Match with it answers 304.
func (h *SensorControlV2Handler) Suppressions(w http.ResponseWriter, r *http.Request) {
	s := sensorForV2(w, r)
	if s == nil {
		return
	}
	list := protov2.SuppressionList{Rules: []protov2.SuppressionRule{}}
	if h.suppressionsEnabled == nil || h.suppressionsEnabled(r.Context(), s.TenantID.String()) {
		rules, err := h.suppressions.service.ListActiveRules(r.Context(), *s.TenantID)
		if err != nil {
			h.internal(w, "suppressions", err)
			return
		}
		for _, rule := range rules {
			item := protov2.SuppressionRule{RuleID: rule.RuleID(), ToolName: rule.ToolName(), PathPattern: rule.PathPattern()}
			if rule.AssetID() != nil {
				a := rule.AssetID().String()
				item.AssetID = &a
			}
			if rule.ExpiresAt() != nil {
				e := rule.ExpiresAt().UTC().Format(time.RFC3339)
				item.ExpiresAt = &e
			}
			list.Rules = append(list.Rules, item)
		}
	}
	list.Count = len(list.Rules)

	body, err := json.Marshal(list)
	if err != nil {
		h.internal(w, "suppressions", err)
		return
	}
	sum := sha256.Sum256(body)
	etag := `"` + hex.EncodeToString(sum[:8]) + `"`
	w.Header().Set("ETag", etag)
	w.Header().Set(protov2.HeaderProtocol, strconv.Itoa(protov2.ProtocolVersion))
	if etagMatches(r.Header.Get("If-None-Match"), etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", protov2.MediaTypeJSON)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(append(body, '\n'))
}

// etagMatches implements the If-None-Match comparison for a strong tag: "*"
// or any listed tag equal to etag (a weak W/ prefix compares weakly).
func etagMatches(header, etag string) bool {
	for _, v := range strings.Split(header, ",") {
		v = strings.TrimPrefix(strings.TrimSpace(v), "W/")
		if v == "*" || v == etag {
			return true
		}
	}
	return false
}

// =============================================================================
// Fingerprint queries
// =============================================================================

// CheckFingerprints handles POST /api/v2/sensor/fingerprints/check.
func (h *SensorControlV2Handler) CheckFingerprints(w http.ResponseWriter, r *http.Request) {
	s := sensorForV2(w, r)
	if s == nil {
		return
	}
	var req protov2.FingerprintsCheckRequest
	if !decodeControl(w, r, h.limits.MaxControlBodyBytes*8, &req) || !h.withinFingerprintLimit(w, len(req.Fingerprints)) {
		return
	}
	resp := protov2.FingerprintsCheckResponse{Existing: []string{}, Missing: []string{}}
	if len(req.Fingerprints) > 0 {
		out, err := h.ingest.ingestService.CheckFingerprints(r.Context(), s, ingest.CheckFingerprintsInput{Fingerprints: req.Fingerprints})
		if err != nil {
			h.internal(w, "fingerprints_check", err)
			return
		}
		resp.Existing, resp.Missing = nonNil(out.Existing), nonNil(out.Missing)
	}
	writeV2JSON(w, http.StatusOK, resp)
}

// BaselineDiff handles POST /api/v2/sensor/fingerprints/baseline-diff.
func (h *SensorControlV2Handler) BaselineDiff(w http.ResponseWriter, r *http.Request) {
	s := sensorForV2(w, r)
	if s == nil {
		return
	}
	var req protov2.BaselineDiffRequest
	if !decodeControl(w, r, h.limits.MaxControlBodyBytes*8, &req) || !h.withinFingerprintLimit(w, len(req.Fingerprints)) {
		return
	}
	resp := protov2.BaselineDiffResponse{NewFingerprints: []string{}, PreExistingFingerprints: []string{}}
	if len(req.Fingerprints) > 0 {
		out, err := h.ingest.ingestService.BaselineDiff(r.Context(), s, ingest.BaselineDiffInput{
			Repository: req.Repository, BaseBranch: req.BaseBranch, Fingerprints: req.Fingerprints,
		})
		if err != nil {
			h.internal(w, "baseline_diff", err)
			return
		}
		resp.NewFingerprints, resp.PreExistingFingerprints = nonNil(out.New), nonNil(out.PreExisting)
		resp.BaseBranchScanned = out.BaseBranchKnown
	}
	writeV2JSON(w, http.StatusOK, resp)
}

func (h *SensorControlV2Handler) withinFingerprintLimit(w http.ResponseWriter, n int) bool {
	if n > h.limits.MaxFingerprintsPerRequest {
		protov2.NewProblem(protov2.ProblemTooManyItems).WithLimit(int64(h.limits.MaxFingerprintsPerRequest)).Write(w)
		return false
	}
	return true
}

// =============================================================================
// Key renewal
// =============================================================================

// RenewKey handles POST /api/v2/sensor/keys (RFC-029 §4.7): a fresh key for
// the calling sensor, shown once.
func (h *SensorControlV2Handler) RenewKey(w http.ResponseWriter, r *http.Request) {
	s := sensorForV2(w, r)
	if s == nil {
		return
	}
	var ignored struct{}
	if !decodeControl(w, r, h.limits.MaxControlBodyBytes, &ignored) {
		return
	}
	// The identity says which key was presented; renewal retires that key.
	key, expiresAt, err := h.ingest.sensorService.RenewAPIKey(r.Context(), sensorIdentityFromContext(r.Context()))
	if err != nil {
		if errors.Is(err, shared.ErrForbidden) {
			h.logger.Debug("sensor key renewal refused", "sensor_id", s.ID.String(), "error", err)
			protov2.NewProblem(protov2.ProblemRenewalRefused).Write(w)
			return
		}
		h.internal(w, "keys", err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeV2JSON(w, http.StatusCreated, protov2.KeyResponse{APIKey: key, ExpiresAt: utcPtr(expiresAt)})
}
