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
// logged at debug level only.
var errSignedRefused = errors.New("signed request refused")

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
	if err := p.CheckWindow(now); err != nil {
		return sensor.SensorIdentity{}, nil, errSignedRefused
	}
	id, pub, err := svc.SigningIdentity(r.Context(), p.Params.KeyID, true)
	if err != nil {
		return sensor.SensorIdentity{}, nil, errSignedRefused
	}
	if err := p.Verify(r, pub); err != nil {
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
