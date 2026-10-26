package handler

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/sensorproto/pairing"
	"github.com/openctemio/openctem/api/pkg/sensorsig"
)

type memNonces map[string]bool

func (m memNonces) UseNonce(_ context.Context, keyID, nonce string) error {
	m[keyID+nonce] = true
	return nil
}

type refuseBudget struct {
	got []string
}

func (b *refuseBudget) ChargeStart(_ *http.Request, credential string) (time.Duration, bool) {
	b.got = append(b.got, credential)
	return 90 * time.Second, false
}

func pairingStart(t *testing.T, signer, inBody *sensorsig.Signer, code string) *http.Request {
	t.Helper()
	body, _ := json.Marshal(pairing.StartRequest{Protocol: pairing.Version, PublicKey: pairing.Encode(inBody.PublicKey()),
		Commitment: pairing.Encode(pairing.Commit(bytes.Repeat([]byte{7}, 32))), Code: code, Host: pairing.HostFacts{Hostname: "h"}})
	r := httptest.NewRequest(http.MethodPost, "/api/v2/sensor/pairings", bytes.NewReader(body))
	if err := signer.Sign(r, body); err != nil {
		t.Fatal(err)
	}
	return r
}

func newPairingSigner(t *testing.T, skew time.Duration) *sensorsig.Signer {
	t.Helper()
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := sensorsig.NewSigner(k)
	if err != nil {
		t.Fatal(err)
	}
	s.Now = func() time.Time { return time.Now().Add(skew) }
	return s
}

// A pairing start signed by the key in its body on a clock 4 h ahead is
// answered with the clock-skew problem (before any work), not the generic
// 401; nothing is spent: no nonce, no budget.
func TestPairingStart_ClockSkew(t *testing.T) {
	nonces := memNonces{}
	budget := &refuseBudget{}
	h := NewSensorPairingHandler(nil, nonces, logger.NewNop())
	h.SetStartBudget(budget)
	s := newPairingSigner(t, 4*time.Hour)
	rec := httptest.NewRecorder()
	h.Start(rec, pairingStart(t, s, s, ""))
	body := rec.Body.String()
	if rec.Code != http.StatusUnauthorized || !strings.Contains(body, "/clock-skew") || !strings.Contains(body, `"clock_offset_seconds":14`) {
		t.Fatalf("skewed start: %d %s", rec.Code, body)
	}
	if len(nonces) != 0 || len(budget.got) != 0 {
		t.Fatalf("a refused start spent a nonce (%d) or budget (%v)", len(nonces), budget.got)
	}
}

// A skewed start that is not signed by the key in its body gets the generic
// 401: the clock answer is only for the key's holder.
func TestPairingStart_ClockSkewNeedsTheKey(t *testing.T) {
	h := NewSensorPairingHandler(nil, memNonces{}, logger.NewNop())
	a, b := newPairingSigner(t, -3*time.Hour), newPairingSigner(t, -3*time.Hour)
	for name, r := range map[string]*http.Request{
		"signed by another key": pairingStart(t, b, a, ""),
		"body changed after signing": func() *http.Request {
			r := pairingStart(t, a, a, "")
			r.Header.Set(sensorsig.HeaderContentDigest, sensorsig.ContentDigest([]byte("{}")))
			return r
		}(),
	} {
		rec := httptest.NewRecorder()
		h.Start(rec, r)
		if rec.Code != http.StatusUnauthorized || strings.Contains(rec.Body.String(), "clock") {
			t.Fatalf("%s: %d %s", name, rec.Code, rec.Body.String())
		}
	}
}

// A verified start is charged to the budget by what it presents (the code in
// canonical form, the token, or nothing); a refused charge is a 429 with a
// Retry-After from the budget, before the service is reached.
func TestPairingStart_BudgetByCredential(t *testing.T) {
	budget := &refuseBudget{}
	h := NewSensorPairingHandler(nil, memNonces{}, logger.NewNop())
	h.SetStartBudget(budget)
	for _, code := range []string{"", "k7qm-4ztd"} {
		s := newPairingSigner(t, 0)
		rec := httptest.NewRecorder()
		h.Start(rec, pairingStart(t, s, s, code))
		if rec.Code != http.StatusTooManyRequests {
			t.Fatalf("code %q: %d %s", code, rec.Code, rec.Body.String())
		}
		if ra, err := strconv.Atoi(rec.Header().Get("Retry-After")); err != nil || ra < 90 || ra > 135 {
			t.Fatalf("Retry-After %q, want 90..135", rec.Header().Get("Retry-After"))
		}
	}
	if len(budget.got) != 2 || budget.got[0] != "" || budget.got[1] != "code:K7QM4ZTD" {
		t.Fatalf("charged %v", budget.got)
	}
}
