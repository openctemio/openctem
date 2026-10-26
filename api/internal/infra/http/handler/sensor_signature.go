package handler

// Signed sensor requests (docs/rfcs/RFC-052-sensor-pairing-and-authorization.md
// §4.3): the verifier both sensor authenticators (v1 AuthenticateSource, v2
// Authenticate) run before the bearer-key path. A request with signature
// headers is decided here and never falls back to a bearer key.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/openctemio/openctem/api/internal/app/sensor"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/sensorproto/relay"
	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
	"github.com/openctemio/openctem/api/pkg/sensorsig"
)

// maxSignedBodyBytes bounds the body read to check Content-Digest: above the
// largest sensor route limit (v1 ingest 50 MB). It is read only after the
// signature verified, so only an authenticated sensor can make the API
// buffer it, within its own rate limits.
const maxSignedBodyBytes = 64 << 20

// errNotSigned: the request has no signature headers (the bearer path
// decides).
var errNotSigned = errors.New("request not signed")

// errSignedRefused is every refusal of a signed request; the reason is
// logged at debug level only, except a clock skew (clockSkewError), which
// is answered and logged as such.
var errSignedRefused = errors.New("signed request refused")

// clockSkewError is the refusal of a request whose signature verifies with
// the key it names but whose time lies outside the clock tolerance: the
// signer's clock or this server's is wrong. It is an errSignedRefused.
type clockSkewError struct {
	now      time.Time
	offset   time.Duration
	keyID    string
	sensorID string
}

func (e *clockSkewError) Error() string {
	return "signed request refused: clock skew " + e.offset.Round(time.Second).String()
}

func (e *clockSkewError) Unwrap() error { return errSignedRefused }

// asClockSkew returns the clock-skew refusal inside err, logged at WARN
// with the offset (nothing secret: the key thumbprint and sensor id are
// identifiers), or nil when err is any other refusal.
func asClockSkew(err error, log *logger.Logger, r *http.Request) *clockSkewError {
	var ce *clockSkewError
	if !errors.As(err, &ce) {
		return nil
	}
	if log != nil {
		log.Warn("sensor request signature outside the clock tolerance: the sensor's or the server's clock is wrong",
			"offset_seconds", int64(ce.offset/time.Second), "server_time", ce.now.UTC().Format(time.RFC3339),
			"key_id", ce.keyID, "sensor_id", ce.sensorID, "path", r.URL.Path, "client_ip", getClientIP(r))
	}
	return ce
}

// writeClockSkew answers a clock-skew refusal with its v2 problem and
// reports whether err was one.
func writeClockSkew(w http.ResponseWriter, r *http.Request, err error, log *logger.Logger) bool {
	ce := asClockSkew(err, log, r)
	if ce == nil {
		return false
	}
	protov2.NewProblem(protov2.ProblemClockSkew).WithClock(ce.now, ce.offset).Write(w)
	return true
}

// signedAuthenticator is what the verifier needs from the sensor service.
type signedAuthenticator interface {
	SigningIdentity(ctx context.Context, keyID string, allowPaused bool) (sensor.SensorIdentity, ed25519.PublicKey, error)
	UseNonce(ctx context.Context, keyID, nonce string) error
	RecordSignedUse(id sensor.SensorIdentity, clientIP string)
}

// authenticateSigned verifies a signed sensor request. It returns
// errNotSigned when the request carries no signature headers, and
// errSignedRefused for anything else that is wrong. On success the returned
// request carries the verified body (already read and checked against
// Content-Digest). A disabled sensor is returned with Paused set; the caller
// decides what a paused sensor may reach, as for a bearer key.
func authenticateSigned(r *http.Request, svc signedAuthenticator, clientIP string, now time.Time) (sensor.SensorIdentity, *http.Request, error) {
	p, err := sensorsig.Parse(r.Header)
	if errors.Is(err, sensorsig.ErrMissing) {
		return sensor.SensorIdentity{}, nil, errNotSigned
	}
	if err != nil {
		return sensor.SensorIdentity{}, nil, errSignedRefused
	}
	// A window outside the profile is refused at once; a window outside the
	// clock tolerance is reported only after the signature verified with
	// the registered key, so the clock-skew answer goes to the key's holder
	// alone (a replayed old request gets it too, which tells the replayer
	// nothing it did not know: the server's time is in every Date header).
	windowErr := p.CheckWindow(now)
	if windowErr != nil && !errors.Is(windowErr, sensorsig.ErrExpired) {
		return sensor.SensorIdentity{}, nil, errSignedRefused
	}
	id, pub, err := svc.SigningIdentity(r.Context(), p.Params.KeyID, true)
	if err != nil {
		return sensor.SensorIdentity{}, nil, errSignedRefused
	}
	if err := p.Verify(r, pub); err != nil {
		return sensor.SensorIdentity{}, nil, errSignedRefused
	}
	if windowErr != nil {
		ce := &clockSkewError{now: now, offset: p.ClockOffset(now), keyID: p.Params.KeyID}
		if id.Sensor != nil {
			ce.sensorID = id.Sensor.ID.String()
		}
		return sensor.SensorIdentity{}, nil, ce
	}
	// Relayed request: the connector names the sensor of the route it
	// arrived on. A different signing sensor means an envelope crossed
	// routes; refuse (defense in depth, the connector already seals routes).
	if want := r.Header.Get(relay.HeaderRelaySensor); want != "" && (id.Sensor == nil || want != id.Sensor.ID.String()) {
		return sensor.SensorIdentity{}, nil, errSignedRefused
	}
	if err := svc.UseNonce(r.Context(), p.Params.KeyID, p.Params.Nonce); err != nil {
		return sensor.SensorIdentity{}, nil, errSignedRefused
	}
	body, err := readSignedBody(r, p)
	if err != nil {
		return sensor.SensorIdentity{}, nil, errSignedRefused
	}
	r2 := r.Clone(r.Context())
	r2.Body = io.NopCloser(bytes.NewReader(body))
	r2.ContentLength = int64(len(body))
	r2.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
	svc.RecordSignedUse(id, clientIP)
	return id, r2, nil
}

// readSignedBody reads the whole body (bounded) and checks it against the
// covered Content-Digest. A body without a covered digest is refused.
func readSignedBody(r *http.Request, p *sensorsig.Parsed) ([]byte, error) {
	var body []byte
	if r.Body != nil && r.Body != http.NoBody {
		b, err := io.ReadAll(io.LimitReader(r.Body, maxSignedBodyBytes+1))
		_ = r.Body.Close()
		if err != nil || len(b) > maxSignedBodyBytes {
			return nil, errSignedRefused
		}
		body = b
	}
	if !p.CoversDigest() {
		if len(body) > 0 {
			return nil, errSignedRefused
		}
		return body, nil
	}
	if err := sensorsig.VerifyContentDigest(r.Header.Get(sensorsig.HeaderContentDigest), body); err != nil {
		return nil, errSignedRefused
	}
	return body, nil
}
