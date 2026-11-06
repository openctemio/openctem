package handler

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/sensor"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/sensorproto/relay"
	"github.com/openctemio/openctem/api/pkg/sensorsig"
)

type fakeSigned struct {
	pub    ed25519.PublicKey
	keyID  string
	nonces map[string]bool
	used   int
	// fixedID, when set, is the sensor id every identity gets.
	fixedID shared.ID
}

func (f *fakeSigned) SigningIdentity(_ context.Context, keyID string, _ bool) (sensor.SensorIdentity, ed25519.PublicKey, error) {
	if keyID != f.keyID {
		return sensor.SensorIdentity{}, nil, errors.New("unknown")
	}
	id := shared.NewID()
	if !f.fixedID.IsZero() {
		id = f.fixedID
	}
	return sensor.SensorIdentity{Sensor: &sensordom.Sensor{ID: id, AuthKind: sensordom.AuthKindKeyBound}}, f.pub, nil
}

func (f *fakeSigned) UseNonce(_ context.Context, keyID, nonce string) error {
	k := keyID + nonce
	if f.nonces[k] {
		return errors.New("replay")
	}
	f.nonces[k] = true
	return nil
}

func (f *fakeSigned) RecordSignedUse(sensor.SensorIdentity, string) { f.used++ }

func newSignedFixture(t *testing.T) (*fakeSigned, *sensorsig.Signer) {
	t.Helper()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{4}, 32))
	s, err := sensorsig.NewSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := key.Public().(ed25519.PublicKey)
	return &fakeSigned{pub: pub, keyID: s.KeyID(), nonces: map[string]bool{}}, s
}

func signedRequest(t *testing.T, s *sensorsig.Signer, method, target, body string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(method, target, strings.NewReader(body))
	if err := s.Sign(r, []byte(body)); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestAuthenticateSigned_Accepts(t *testing.T) {
	f, s := newSignedFixture(t)
	r := signedRequest(t, s, http.MethodPost, "/api/v2/sensor/heartbeat", `{"status":"ok"}`)
	id, r2, err := authenticateSigned(r, f, "192.0.2.1", time.Now())
	if err != nil || id.Sensor == nil {
		t.Fatalf("valid request refused: %v", err)
	}
	body, _ := io.ReadAll(r2.Body)
	if string(body) != `{"status":"ok"}` {
		t.Fatalf("body not passed on: %q", body)
	}
	if f.used != 1 {
		t.Fatal("use not recorded")
	}
}

func TestAuthenticateSigned_RelayedSensorMustMatch(t *testing.T) {
	f, s := newSignedFixture(t)
	f.fixedID = shared.NewID()
	r := signedRequest(t, s, http.MethodGet, "/api/v2/sensor/hello", "")
	r.Header.Set(relay.HeaderRelaySensor, f.fixedID.String())
	if _, _, err := authenticateSigned(r, f, "", time.Now()); err != nil {
		t.Fatalf("matching relayed sensor refused: %v", err)
	}
	r = signedRequest(t, s, http.MethodGet, "/api/v2/sensor/hello", "")
	r.Header.Set(relay.HeaderRelaySensor, shared.NewID().String())
	if _, _, err := authenticateSigned(r, f, "", time.Now()); !errors.Is(err, errSignedRefused) {
		t.Fatalf("relayed request for another sensor: %v", err)
	}
}

func TestAuthenticateSigned_NotSigned(t *testing.T) {
	f, _ := newSignedFixture(t)
	r := httptest.NewRequest(http.MethodGet, "/api/v2/sensor/hello", nil)
	r.Header.Set("Authorization", "Bearer octs_x")
	if _, _, err := authenticateSigned(r, f, "", time.Now()); !errors.Is(err, errNotSigned) {
		t.Fatalf("bearer-only request: %v", err)
	}
}

func TestAuthenticateSigned_Refusals(t *testing.T) {
	cases := map[string]func(t *testing.T, f *fakeSigned, s *sensorsig.Signer) *http.Request{
		"replay": func(t *testing.T, f *fakeSigned, s *sensorsig.Signer) *http.Request {
			r := signedRequest(t, s, http.MethodPost, "/api/v2/sensor/heartbeat", `{}`)
			if _, _, err := authenticateSigned(r, f, "", time.Now()); err != nil {
				t.Fatal(err)
			}
			r2 := httptest.NewRequest(http.MethodPost, "/api/v2/sensor/heartbeat", strings.NewReader(`{}`))
			r2.Header = r.Header.Clone()
			return r2
		},
		"changed body": func(t *testing.T, _ *fakeSigned, s *sensorsig.Signer) *http.Request {
			r := signedRequest(t, s, http.MethodPost, "/api/v2/sensor/heartbeat", `{"a":1}`)
			r.Body = io.NopCloser(strings.NewReader(`{"a":2}`))
			return r
		},
		"body without digest": func(t *testing.T, _ *fakeSigned, s *sensorsig.Signer) *http.Request {
			r := signedRequest(t, s, http.MethodGet, "/api/v2/sensor/commands", "")
			r.Body = io.NopCloser(strings.NewReader(`smuggled`))
			return r
		},
		"other path": func(t *testing.T, _ *fakeSigned, s *sensorsig.Signer) *http.Request {
			r := signedRequest(t, s, http.MethodGet, "/api/v2/sensor/commands", "")
			r.URL.Path = "/api/v2/sensor/suppressions"
			return r
		},
		"unknown key": func(t *testing.T, f *fakeSigned, s *sensorsig.Signer) *http.Request {
			f.keyID = "other"
			return signedRequest(t, s, http.MethodGet, "/api/v2/sensor/hello", "")
		},
		"expired": func(t *testing.T, _ *fakeSigned, s *sensorsig.Signer) *http.Request {
			s.Now = func() time.Time { return time.Now().Add(-time.Hour) }
			return signedRequest(t, s, http.MethodGet, "/api/v2/sensor/hello", "")
		},
		"outside the profile": func(t *testing.T, _ *fakeSigned, s *sensorsig.Signer) *http.Request {
			r := signedRequest(t, s, http.MethodGet, "/api/v2/sensor/hello", "")
			r.Header.Set(sensorsig.HeaderSignatureInput, strings.Replace(r.Header.Get(sensorsig.HeaderSignatureInput), "ed25519", "rsa-pss-sha512", 1))
			return r
		},
	}
	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			f, s := newSignedFixture(t)
			r := build(t, f, s)
			if _, _, err := authenticateSigned(r, f, "", time.Now()); !errors.Is(err, errSignedRefused) {
				t.Fatalf("want refusal, got %v", err)
			}
		})
	}
}

// A request whose signature verifies with its key but whose time is outside
// the clock tolerance is a clock skew, with the offset; the nonce is not
// spent, so the same sensor succeeds once its clock is right.
func TestAuthenticateSigned_ClockSkew(t *testing.T) {
	f, s := newSignedFixture(t)
	now := time.Now()
	s.Now = func() time.Time { return now.Add(4 * time.Hour) }
	r := signedRequest(t, s, http.MethodPost, "/api/v2/sensor/heartbeat", `{}`)
	_, _, err := authenticateSigned(r, f, "", now)
	var ce *clockSkewError
	if !errors.As(err, &ce) || !errors.Is(err, errSignedRefused) {
		t.Fatalf("want a clock-skew refusal, got %v", err)
	}
	if d := ce.offset - 4*time.Hour; d < -2*time.Second || d > 2*time.Second {
		t.Fatalf("offset %v, want about 4h", ce.offset)
	}
	if ce.sensorID == "" || ce.keyID != f.keyID {
		t.Fatalf("clock-skew error lacks its sensor: %+v", ce)
	}
	if len(f.nonces) != 0 || f.used != 0 {
		t.Fatal("a refused request spent a nonce or recorded a use")
	}
	rec := httptest.NewRecorder()
	if !writeClockSkew(rec, r, err, nil) {
		t.Fatal("clock skew not answered")
	}
	body := rec.Body.String()
	if rec.Code != http.StatusUnauthorized || !strings.Contains(body, "/clock-skew") ||
		!strings.Contains(body, `"server_time":"`) || !strings.Contains(body, `"clock_offset_seconds":14`) {
		t.Fatalf("clock-skew answer %d %s", rec.Code, body)
	}
	s.Now = time.Now
	if _, _, err := authenticateSigned(signedRequest(t, s, http.MethodPost, "/api/v2/sensor/heartbeat", `{}`), f, "", now); err != nil {
		t.Fatalf("request with the right clock refused: %v", err)
	}
}

// The clock-skew answer is given only for a signature that verifies with the
// key it names: an unknown key, a forged signature or a window outside the
// profile is the generic refusal, whatever the time.
func TestAuthenticateSigned_ClockSkewOnlyForValidSignatures(t *testing.T) {
	skewed := func(s *sensorsig.Signer) { s.Now = func() time.Time { return time.Now().Add(-3 * time.Hour) } }
	cases := map[string]func(t *testing.T, f *fakeSigned, s *sensorsig.Signer) *http.Request{
		"unknown key": func(t *testing.T, f *fakeSigned, s *sensorsig.Signer) *http.Request {
			f.keyID = "other"
			skewed(s)
			return signedRequest(t, s, http.MethodGet, "/api/v2/sensor/hello", "")
		},
		"forged signature": func(t *testing.T, _ *fakeSigned, s *sensorsig.Signer) *http.Request {
			skewed(s)
			r := signedRequest(t, s, http.MethodGet, "/api/v2/sensor/commands", "")
			r.URL.Path = "/api/v2/sensor/suppressions"
			return r
		},
		"key of another sensor": func(t *testing.T, f *fakeSigned, _ *sensorsig.Signer) *http.Request {
			other, err := sensorsig.NewSigner(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32)))
			if err != nil {
				t.Fatal(err)
			}
			skewed(other)
			r := signedRequest(t, other, http.MethodGet, "/api/v2/sensor/hello", "")
			// Claim the registered key id: the signature does not verify.
			r.Header.Set(sensorsig.HeaderSignatureInput, strings.Replace(r.Header.Get(sensorsig.HeaderSignatureInput), other.KeyID(), f.keyID, 1))
			return r
		},
	}
	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			f, s := newSignedFixture(t)
			r := build(t, f, s)
			_, _, err := authenticateSigned(r, f, "", time.Now())
			var ce *clockSkewError
			if !errors.Is(err, errSignedRefused) || errors.As(err, &ce) {
				t.Fatalf("want the generic refusal, got %v", err)
			}
			if writeClockSkew(httptest.NewRecorder(), r, err, nil) {
				t.Fatal("generic refusal answered as a clock skew")
			}
		})
	}
}
