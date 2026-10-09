package handler

// Protocol v3 bridge (docs/rfcs/RFC-059-sensor-transport-v3.md). The v3
// server authenticates a sensor (client certificate on the gRPC binding,
// RFC 9421 signature on the HTTPS binding), puts the identity in the context
// with WithSensorIdentity and serves each call through the protocol v2 route
// group, mounted in-process behind AuthenticateInProcess. Everything after
// authentication (edge chain, limits, services, side effects) is the v2 code.

import (
	"context"
	"errors"
	"net/http"
	"time"

	sensorapp "github.com/openctemio/openctem/api/internal/app/sensor"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
)

// sensorPeerContextKey carries the address and User-Agent of the connection
// a v3 call arrived on.
const sensorPeerContextKey contextKey = "sensor_peer"

// servedTransportContextKey carries the binding a v3 heartbeat arrived on
// and the sensor's fallback reason.
const servedTransportContextKey contextKey = "served_transport"

// ServedTransport is the transport of a v3 heartbeat.
type ServedTransport struct {
	// Binding is grpc or https, decided by the listener the call came on.
	Binding string
	// FallbackReason is the sensor's report (untrusted).
	FallbackReason string
}

// WithServedTransport marks a v3 heartbeat with its transport.
func WithServedTransport(ctx context.Context, t ServedTransport) context.Context {
	return context.WithValue(ctx, servedTransportContextKey, t)
}

func servedTransportFrom(ctx context.Context) (ServedTransport, bool) {
	t, ok := ctx.Value(servedTransportContextKey).(ServedTransport)
	return t, ok
}

// SensorPeer is where a v3 call came from.
type SensorPeer struct {
	// IP is the client address (the trusted-proxy rule already applied).
	IP string
	// UserAgent is the sensor's User-Agent.
	UserAgent string
}

// WithSensorIdentity returns ctx carrying an authenticated sensor identity,
// exactly as the v2 authenticator stores it.
func WithSensorIdentity(ctx context.Context, id sensorapp.SensorIdentity) context.Context {
	ctx = context.WithValue(ctx, sensorContextKey, id.Sensor)
	ctx = context.WithValue(ctx, sensorIdentityContextKey, id)
	if id.Sensor != nil && id.Sensor.TenantID != nil {
		ctx = context.WithValue(ctx, middleware.TenantIDKey, id.Sensor.TenantID.String())
	}
	return ctx
}

// SensorIdentityFrom returns the identity WithSensorIdentity stored; false
// when there is none.
func SensorIdentityFrom(ctx context.Context) (sensorapp.SensorIdentity, bool) {
	id, ok := ctx.Value(sensorIdentityContextKey).(sensorapp.SensorIdentity)
	return id, ok && id.Sensor != nil
}

// WithSensorPeer returns ctx carrying the peer of a v3 call.
func WithSensorPeer(ctx context.Context, p SensorPeer) context.Context {
	return context.WithValue(ctx, sensorPeerContextKey, p)
}

// SensorPeerFrom returns the peer WithSensorPeer stored.
func SensorPeerFrom(ctx context.Context) SensorPeer {
	p, _ := ctx.Value(sensorPeerContextKey).(SensorPeer)
	return p
}

// AuthenticateInProcess is the authenticator of the in-process v2 route
// group that serves protocol v3. The v3 server authenticated the sensor
// before the call; this only applies the rules every v2 route applies to an
// identity: none is 401, a paused (disabled) sensor reaches only the
// heartbeat and hello. The group is never mounted on a listener, so no
// request from the network reaches it.
func AuthenticateInProcess(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := SensorIdentityFrom(r.Context())
		if !ok || (id.Paused && !isV2HeartbeatRequest(r) && !isV2HelloRequest(r)) {
			protov2.NewProblem(protov2.ProblemUnauthenticated).Write(w)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// AuthenticateInProcessWithPolicies is AuthenticateInProcess plus the key
// policies the v2 listener applies after authentication (the organization's
// "OIDC required for CI" rule), so protocol v3, on either binding, is
// refused what protocol v2 refuses.
func (h *SensorResultsV2Handler) AuthenticateInProcessWithPolicies(next http.Handler) http.Handler {
	return AuthenticateInProcess(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, _ := SensorIdentityFrom(r.Context())
		peer := SensorPeerFrom(r.Context())
		if h.ciKeys != nil && id.Sensor != nil && h.ciKeys.Refused(r.Context(), id.Sensor, peer.IP, peer.UserAgent) {
			protov2.NewProblem(protov2.ProblemCIOIDCRequired).Write(w)
			return
		}
		next.ServeHTTP(w, r)
	}))
}

// errBearerOnV3 refuses a bearer key on protocol v3: v3 needs a key-bound
// sensor (RFC-052).
var errBearerOnV3 = errors.New("protocol v3 needs a key-bound sensor")

// AuthenticateV3 authenticates a call on the v3 HTTPS binding: an RFC 9421
// signature with the sensor's registered key, nothing else. A bearer key, a
// user token or an unsigned request is 401; the reason is logged at debug
// level only. The identity (paused included; the v2 rules apply per call)
// and the peer go into the context.
func (h *SensorResultsV2Handler) AuthenticateV3(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := getClientIP(r)
		id, signed, err := authenticateSigned(r, h.sensors, ip, time.Now())
		if errors.Is(err, errNotSigned) {
			err = errBearerOnV3
		}
		if err != nil || id.Sensor == nil {
			h.logger.Debug("v3 authentication failed", "error", err)
			protov2.NewProblem(protov2.ProblemUnauthenticated).Write(w)
			return
		}
		ctx := WithSensorIdentity(signed.Context(), id)
		ctx = WithSensorPeer(ctx, SensorPeer{IP: ip, UserAgent: r.UserAgent()})
		next.ServeHTTP(w, signed.WithContext(ctx))
	})
}

// ErrSensorIdentityGone is returned by Reauthenticate when the identity no
// longer holds (key revoked, sensor revoked or deleted).
var ErrSensorIdentityGone = errors.New("sensor identity no longer valid")

// Reauthenticate resolves a key-bound identity again from the store: the
// sensor's current row and status, its key still active. A long-lived v3
// connection calls it to notice a revocation.
func (h *SensorResultsV2Handler) Reauthenticate(ctx context.Context, id sensorapp.SensorIdentity) (sensorapp.SensorIdentity, error) {
	thumb := id.KeyThumbprint()
	if thumb == "" || id.Sensor == nil {
		return sensorapp.SensorIdentity{}, ErrSensorIdentityGone
	}
	fresh, _, err := h.sensors.SigningIdentity(ctx, thumb, true)
	if err != nil || fresh.Sensor == nil || fresh.Sensor.ID != id.Sensor.ID {
		return sensorapp.SensorIdentity{}, ErrSensorIdentityGone
	}
	return fresh, nil
}

// StreamHints is the doorbell of a v3 control-stream event: what a heartbeat
// answer would say now, without recording a heartbeat.
type StreamHints struct {
	Status           string
	PendingJobs      int
	Actions          []string
	CancelCommandIDs []string
	ConfigVersion    string
}

// StreamHints computes the doorbell for the sensor in ctx with the same code
// as the heartbeat (RFC-035). running is the sensor's last reported running
// list, for the cancel ids. It never fails: without the doorbell it answers
// the status only.
func (h *SensorControlV2Handler) StreamHints(ctx context.Context, running []string) StreamHints {
	out := StreamHints{Status: protov2.HeartbeatStatusOK, Actions: []string{}, CancelCommandIDs: []string{}}
	id, ok := SensorIdentityFrom(ctx)
	if !ok || h.ingest == nil {
		return out
	}
	if id.Paused {
		out.Status = protov2.HeartbeatStatusPaused
	}
	if h.ingest.doorbell != nil {
		hints := h.ingest.doorbell.Ring(ctx, sensorapp.DoorbellRequest{Identity: id, Aware: true})
		out.PendingJobs = hints.PendingJobs
		out.ConfigVersion = hints.ConfigVersion
		for _, a := range hints.Actions {
			out.Actions = append(out.Actions, string(a))
		}
	}
	if !id.Paused && len(running) > 0 {
		if ids := h.ingest.sensorService.CommandsToCancel(ctx, id.Sensor, running); len(ids) > 0 {
			out.CancelCommandIDs = ids
			out.Actions = append(out.Actions, protov2.ActionCancel)
		}
	}
	return out
}

// TenantSensor reports whether s may use the sensor control plane: a
// tenant-less (platform) sensor may not, on v3 as on v2.
func TenantSensor(s *sensor.Sensor) bool { return s != nil && s.TenantID != nil }
