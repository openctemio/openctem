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

	"github.com/openctemio/openctem/api/internal/app"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/sensorsig"
)

type fakeSigned struct {
	pub    ed25519.PublicKey
	keyID  string
	nonces map[string]bool
	used   int
}

func (f *fakeSigned) SigningIdentity(_ context.Context, keyID string, _ bool) (app.SensorIdentity, ed25519.PublicKey, error) {
	if keyID != f.keyID {
		return app.SensorIdentity{}, nil, errors.New("unknown")
	}
	return app.SensorIdentity{Sensor: &sensordom.Sensor{ID: shared.NewID(), AuthKind: sensordom.AuthKindKeyBound}}, f.pub, nil
}

func (f *fakeSigned) UseNonce(_ context.Context, keyID, nonce string) error {
	k := keyID + nonce
	if f.nonces[k] {
		return errors.New("replay")
	}
	f.nonces[k] = true
	return nil
}

func (f *fakeSigned) RecordSignedUse(app.SensorIdentity, string) { f.used++ }

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
