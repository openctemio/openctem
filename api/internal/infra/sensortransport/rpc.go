package sensortransport

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"connectrpc.com/connect"

	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
	sensorv3 "github.com/openctemio/openctem/api/pkg/sensorproto/v3"
)

// maxClaimLimit bounds ClaimCommands.limit.
const maxClaimLimit = 100

// maxFeatures bounds ClaimCommands.features.
const maxFeatures = 16

// maxRunningCached bounds the running list kept per sensor for cancels.
const maxRunningCached = 1000

func jsonHeader() http.Header {
	return http.Header{"Content-Type": []string{protov2.MediaTypeJSON}}
}

// Hello answers the v2 hello document and the v3 endpoints.
func (s *Server) Hello(ctx context.Context, _ *connect.Request[sensorv3.HelloRequest]) (*connect.Response[sensorv3.HelloResponse], error) {
	a, err := s.serveV2(ctx, v2Call{method: http.MethodGet, path: protov2.HelloPath})
	if err != nil {
		return nil, err
	}
	if err := a.ok(false); err != nil {
		return nil, err
	}
	return connect.NewResponse(&sensorv3.HelloResponse{
		Protocol:     ProtocolVersion,
		HelloJson:    a.body,
		GrpcEndpoint: s.grpcEndpoint(),
		Binding:      BindingFrom(ctx),
	}), nil
}

// heartbeatRunning is the part of a heartbeat body the control stream keeps:
// the commands the sensor runs (for cancel ids). The SDK that reports its
// queue lists them in "running".
type heartbeatRunning struct {
	Running []string        `json:"running"`
	Queue   json.RawMessage `json:"queue"`
}

// Heartbeat records a heartbeat (POST /heartbeat).
func (s *Server) Heartbeat(ctx context.Context, req *connect.Request[sensorv3.HeartbeatRequest]) (*connect.Response[sensorv3.HeartbeatResponse], error) {
	body := req.Msg.GetHeartbeatJson()
	served := handler.ServedTransport{Binding: "https", FallbackReason: req.Msg.GetTransport().GetFallbackReason()}
	if BindingFrom(ctx) == sensorv3.Binding_BINDING_GRPC {
		served.Binding = "grpc"
	}
	a, err := s.serveV2(handler.WithServedTransport(ctx, served), v2Call{method: http.MethodPost, path: protov2.HeartbeatPath, header: jsonHeader(), body: body})
	if err != nil {
		return nil, err
	}
	if err := a.ok(false); err != nil {
		return nil, err
	}
	s.rememberRunning(ctx, body)
	return connect.NewResponse(&sensorv3.HeartbeatResponse{HeartbeatJson: a.body}), nil
}

// rememberRunning keeps the sensor's running list for control-stream
// cancels. A sensor that does not report its queue has none.
func (s *Server) rememberRunning(ctx context.Context, body []byte) {
	id, ok := handler.SensorIdentityFrom(ctx)
	if !ok {
		return
	}
	var hb heartbeatRunning
	if json.Unmarshal(body, &hb) != nil || len(hb.Queue) == 0 {
		s.running.Delete(id.Sensor.ID.String())
		return
	}
	running := make([]string, 0, min(len(hb.Running), maxRunningCached))
	for _, r := range hb.Running {
		if len(running) == maxRunningCached {
			break
		}
		if validID(r) {
			running = append(running, r)
		}
	}
	s.running.Store(id.Sensor.ID.String(), running)
}

func (s *Server) runningOf(sensorID string) []string {
	v, ok := s.running.Load(sensorID)
	if !ok {
		return nil
	}
	r, _ := v.([]string)
	return r
}

// ClaimCommands claims commands (GET /commands, claim-N).
func (s *Server) ClaimCommands(ctx context.Context, req *connect.Request[sensorv3.ClaimCommandsRequest]) (*connect.Response[sensorv3.ClaimCommandsResponse], error) {
	limit := int(req.Msg.GetLimit())
	if limit <= 0 || limit > maxClaimLimit {
		return nil, invalid("limit")
	}
	if len(req.Msg.GetFeatures()) > maxFeatures {
		return nil, invalid("features")
	}
	// The RPC always claims: the capacity feature is what makes the v2
	// poll claim-N.
	features := []string{protov2.FeatureCapacity}
	for _, f := range req.Msg.GetFeatures() {
		if !featureToken(f) {
			return nil, invalid("features")
		}
		if f != protov2.FeatureCapacity {
			features = append(features, f)
		}
	}
	h := http.Header{}
	h.Set(protov2.HeaderSensorFeatures, strings.Join(features, ","))
	a, err := s.serveV2(ctx, v2Call{method: http.MethodGet, path: protov2.CommandsPath,
		query: url.Values{"limit": []string{strconv.Itoa(limit)}}, header: h})
	if err != nil {
		return nil, err
	}
	if err := a.ok(false); err != nil {
		return nil, err
	}
	return connect.NewResponse(&sensorv3.ClaimCommandsResponse{CommandsJson: a.body}), nil
}

var transitionPaths = map[sensorv3.CommandTransition]string{
	sensorv3.CommandTransition_COMMAND_TRANSITION_CLAIM:    "claim",
	sensorv3.CommandTransition_COMMAND_TRANSITION_START:    "start",
	sensorv3.CommandTransition_COMMAND_TRANSITION_COMPLETE: "complete",
	sensorv3.CommandTransition_COMMAND_TRANSITION_FAIL:     "fail",
	sensorv3.CommandTransition_COMMAND_TRANSITION_RELEASE:  "release",
}

// TransitionCommand moves a command (POST /commands/{id}/{transition}).
func (s *Server) TransitionCommand(ctx context.Context, req *connect.Request[sensorv3.TransitionCommandRequest]) (*connect.Response[sensorv3.TransitionCommandResponse], error) {
	m := req.Msg
	if !validID(m.GetCommandId()) {
		return nil, invalid("command_id")
	}
	action, ok := transitionPaths[m.GetTransition()]
	if !ok {
		return nil, invalid("transition")
	}
	h := jsonHeader()
	if m.LeaseEpoch != nil {
		if m.GetLeaseEpoch() < 0 {
			return nil, invalid("lease_epoch")
		}
		h.Set(protov2.HeaderLeaseEpoch, strconv.FormatInt(m.GetLeaseEpoch(), 10))
	}
	a, err := s.serveV2(ctx, v2Call{method: http.MethodPost,
		path: protov2.CommandsPath + "/" + m.GetCommandId() + "/" + action, header: h, body: m.GetBodyJson()})
	if err != nil {
		return nil, err
	}
	if err := a.ok(false); err != nil {
		return nil, err
	}
	return connect.NewResponse(&sensorv3.TransitionCommandResponse{CommandJson: a.body}), nil
}

// AppendCommandLogs appends task logs (POST /commands/{id}/logs).
func (s *Server) AppendCommandLogs(ctx context.Context, req *connect.Request[sensorv3.AppendCommandLogsRequest]) (*connect.Response[sensorv3.AppendCommandLogsResponse], error) {
	if !validID(req.Msg.GetCommandId()) {
		return nil, invalid("command_id")
	}
	a, err := s.serveV2(ctx, v2Call{method: http.MethodPost,
		path: protov2.CommandsPath + "/" + req.Msg.GetCommandId() + "/logs", header: jsonHeader(), body: req.Msg.GetBodyJson()})
	if err != nil {
		return nil, err
	}
	if err := a.ok(false); err != nil {
		return nil, err
	}
	return connect.NewResponse(&sensorv3.AppendCommandLogsResponse{ResponseJson: a.body}), nil
}

// resultPath is the v2 path of a report: command-bound or not.
func resultPath(reportID, commandID string) (string, error) {
	if !validID(reportID) {
		return "", invalid("report_id")
	}
	if commandID == "" {
		return protov2.ResultsPath + "/" + reportID, nil
	}
	if !validID(commandID) {
		return "", invalid("command_id")
	}
	return protov2.CommandsPath + "/" + commandID + protov2.ResultsPath + "/" + reportID, nil
}

// PutResult uploads a report or a segment (PUT /results/{report}[/segments/{n}]).
func (s *Server) PutResult(ctx context.Context, req *connect.Request[sensorv3.PutResultRequest]) (*connect.Response[sensorv3.PutResultResponse], error) {
	m := req.Msg
	path, err := resultPath(m.GetReportId(), m.GetCommandId())
	if err != nil {
		return nil, err
	}
	if m.Segment != nil {
		path += "/segments/" + strconv.FormatUint(uint64(m.GetSegment()), 10)
	}
	h := http.Header{}
	h.Set("Content-Type", m.GetContentType())
	if enc := m.GetContentEncoding(); enc != "" {
		h.Set("Content-Encoding", enc)
	}
	if d := m.GetContentDigest(); d != "" {
		h.Set(protov2.HeaderContentDigest, d)
	}
	a, err := s.serveV2(ctx, v2Call{method: http.MethodPut, path: path, header: h, body: m.GetContent()})
	if err != nil {
		return nil, err
	}
	if err := a.ok(false); err != nil {
		return nil, err
	}
	return connect.NewResponse(&sensorv3.PutResultResponse{
		Created: a.status == http.StatusAccepted, StatusJson: a.body, RetryAfterSeconds: a.retryAfter(),
	}), nil
}

// CommitResult commits a segmented report (POST .../commit).
func (s *Server) CommitResult(ctx context.Context, req *connect.Request[sensorv3.CommitResultRequest]) (*connect.Response[sensorv3.CommitResultResponse], error) {
	path, err := resultPath(req.Msg.GetReportId(), req.Msg.GetCommandId())
	if err != nil {
		return nil, err
	}
	a, err := s.serveV2(ctx, v2Call{method: http.MethodPost, path: path + "/commit", header: jsonHeader(), body: req.Msg.GetBodyJson()})
	if err != nil {
		return nil, err
	}
	if err := a.ok(false); err != nil {
		return nil, err
	}
	return connect.NewResponse(&sensorv3.CommitResultResponse{
		Created: a.status == http.StatusAccepted, StatusJson: a.body, RetryAfterSeconds: a.retryAfter(),
	}), nil
}

// GetResultStatus reads a report's status (GET /results/{report}).
func (s *Server) GetResultStatus(ctx context.Context, req *connect.Request[sensorv3.GetResultStatusRequest]) (*connect.Response[sensorv3.GetResultStatusResponse], error) {
	path, err := resultPath(req.Msg.GetReportId(), "")
	if err != nil {
		return nil, err
	}
	a, err := s.serveV2(ctx, v2Call{method: http.MethodGet, path: path})
	if err != nil {
		return nil, err
	}
	if err := a.ok(false); err != nil {
		return nil, err
	}
	return connect.NewResponse(&sensorv3.GetResultStatusResponse{StatusJson: a.body, RetryAfterSeconds: a.retryAfter()}), nil
}

// AbandonResult drops an uncommitted report (DELETE /results/{report}).
func (s *Server) AbandonResult(ctx context.Context, req *connect.Request[sensorv3.AbandonResultRequest]) (*connect.Response[sensorv3.AbandonResultResponse], error) {
	path, err := resultPath(req.Msg.GetReportId(), "")
	if err != nil {
		return nil, err
	}
	a, err := s.serveV2(ctx, v2Call{method: http.MethodDelete, path: path})
	if err != nil {
		return nil, err
	}
	if err := a.ok(false); err != nil {
		return nil, err
	}
	return connect.NewResponse(&sensorv3.AbandonResultResponse{}), nil
}

// jsonCall runs one JSON resource call and returns the answer body.
func (s *Server) jsonCall(ctx context.Context, method, path string, body []byte) ([]byte, error) {
	var h http.Header
	if body != nil {
		h = jsonHeader()
	}
	a, err := s.serveV2(ctx, v2Call{method: method, path: path, header: h, body: body})
	if err != nil {
		return nil, err
	}
	if err := a.ok(false); err != nil {
		return nil, err
	}
	return a.body, nil
}

// PutManifest registers the manifest (PUT /manifest).
func (s *Server) PutManifest(ctx context.Context, req *connect.Request[sensorv3.PutManifestRequest]) (*connect.Response[sensorv3.PutManifestResponse], error) {
	b, err := s.jsonCall(ctx, http.MethodPut, protov2.ManifestPath, nonNilBody(req.Msg.GetManifestJson()))
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&sensorv3.PutManifestResponse{ResponseJson: b}), nil
}

// GetManifest reads the manifest state (GET /manifest).
func (s *Server) GetManifest(ctx context.Context, _ *connect.Request[sensorv3.GetManifestRequest]) (*connect.Response[sensorv3.GetManifestResponse], error) {
	b, err := s.jsonCall(ctx, http.MethodGet, protov2.ManifestPath, nil)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&sensorv3.GetManifestResponse{ResponseJson: b}), nil
}

// PutConfigReport stores the config report (PUT /config-report).
func (s *Server) PutConfigReport(ctx context.Context, req *connect.Request[sensorv3.PutConfigReportRequest]) (*connect.Response[sensorv3.PutConfigReportResponse], error) {
	b, err := s.jsonCall(ctx, http.MethodPut, protov2.ConfigReportPath, nonNilBody(req.Msg.GetReportJson()))
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&sensorv3.PutConfigReportResponse{ResponseJson: b}), nil
}

// GetSuppressions reads the suppression rules (GET /suppressions).
func (s *Server) GetSuppressions(ctx context.Context, req *connect.Request[sensorv3.GetSuppressionsRequest]) (*connect.Response[sensorv3.GetSuppressionsResponse], error) {
	h := http.Header{}
	if et := req.Msg.GetEtag(); et != "" {
		if len(et) > 128 || strings.ContainsAny(et, "\r\n") {
			return nil, invalid("etag")
		}
		h.Set("If-None-Match", et)
	}
	a, err := s.serveV2(ctx, v2Call{method: http.MethodGet, path: protov2.SuppressionsPath, header: h})
	if err != nil {
		return nil, err
	}
	if err := a.ok(true); err != nil {
		return nil, err
	}
	out := &sensorv3.GetSuppressionsResponse{Etag: a.header.Get("ETag")}
	if a.status == http.StatusNotModified {
		out.NotModified = true
	} else {
		out.SuppressionsJson = a.body
	}
	return connect.NewResponse(out), nil
}

// CheckFingerprints asks which fingerprints exist (POST /fingerprints/check).
func (s *Server) CheckFingerprints(ctx context.Context, req *connect.Request[sensorv3.CheckFingerprintsRequest]) (*connect.Response[sensorv3.CheckFingerprintsResponse], error) {
	b, err := s.jsonCall(ctx, http.MethodPost, protov2.FingerprintsCheckPath, nonNilBody(req.Msg.GetRequestJson()))
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&sensorv3.CheckFingerprintsResponse{ResponseJson: b}), nil
}

// BaselineDiff splits fingerprints against a base branch.
func (s *Server) BaselineDiff(ctx context.Context, req *connect.Request[sensorv3.BaselineDiffRequest]) (*connect.Response[sensorv3.BaselineDiffResponse], error) {
	b, err := s.jsonCall(ctx, http.MethodPost, protov2.BaselineDiffPath, nonNilBody(req.Msg.GetRequestJson()))
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&sensorv3.BaselineDiffResponse{ResponseJson: b}), nil
}

// IssueCertificate issues a client certificate for the sensor's key.
func (s *Server) IssueCertificate(ctx context.Context, _ *connect.Request[sensorv3.IssueCertificateRequest]) (*connect.Response[sensorv3.IssueCertificateResponse], error) {
	if s.issuer == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, errors.New("certificates are not issued by this platform"))
	}
	id, ok := handler.SensorIdentityFrom(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errNoIdentity)
	}
	if id.Paused {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("sensor is paused"))
	}
	out, err := s.issuer.Issue(ctx, id)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(out), nil
}

// nonNilBody turns an empty document into an empty JSON body ("{}" is not
// assumed: v2 decides what an empty body means).
func nonNilBody(b []byte) []byte {
	if b == nil {
		return []byte{}
	}
	return b
}
