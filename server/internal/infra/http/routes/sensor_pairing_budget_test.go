package routes

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	infrahttp "github.com/openctemio/openctem/api/internal/infra/http"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/sensorproto/pairing"
	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
)

func testBudget(t *testing.T) *pairingStartBudget {
	t.Helper()
	b := newPairingStartBudget(logger.NewNop())
	t.Cleanup(func() { b.codeless.Stop(); b.credentialIP.Stop(); b.credential.Stop() })
	return b
}

// Every start, refused or not, spends the per-address entry budget (burst
// 10): a caller sending unverifiable starts is still capped.
func TestPairingStartEntryBudget(t *testing.T) {
	deny := func(http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusUnauthorized) })
	}
	router := infrahttp.NewChiRouter()
	registerSensorPairingRoutes(router, handler.NewSensorPairingHandler(nil, nil, logger.NewNop()), deny, deny, logger.NewNop())
	h := router.Handler()
	_, k, _ := ed25519.GenerateKey(rand.Reader)
	body, _ := json.Marshal(pairing.StartRequest{Protocol: pairing.Version, PublicKey: pairing.Encode(k.Public().(ed25519.PublicKey)),
		Commitment: pairing.Encode(pairing.Commit(make([]byte, 32)))})
	codes := map[int]int{}
	for range pairingStartPerIPBurst + 2 {
		r := httptest.NewRequest(http.MethodPost, protov2.PathPrefix+"/pairings", bytes.NewReader(body))
		r.RemoteAddr = "203.0.113.50:1000"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		codes[rec.Code]++
	}
	if codes[http.StatusUnauthorized] != pairingStartPerIPBurst || codes[http.StatusTooManyRequests] != 2 {
		t.Fatalf("unsigned starts: %v", codes)
	}
}

func budgetRequest(remote string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/api/v2/sensor/pairings", nil)
	r.RemoteAddr = remote
	return r
}

// Verified starts without a code keep the per-address limit (burst 3).
func TestPairingStartBudget_CodelessPerAddress(t *testing.T) {
	b := testBudget(t)
	for i := range pairingCodelessPerIPBurst {
		if _, ok := b.ChargeStart(budgetRequest("203.0.113.7:1000"), ""); !ok {
			t.Fatalf("codeless start %d refused", i+1)
		}
	}
	wait, ok := b.ChargeStart(budgetRequest("203.0.113.7:1000"), "")
	if ok || wait <= 0 {
		t.Fatalf("codeless start beyond the burst: ok=%v wait=%v", ok, wait)
	}
	if _, ok := b.ChargeStart(budgetRequest("203.0.113.8:1000"), ""); !ok {
		t.Fatal("another address shares the budget")
	}
}

// A site behind one address pairs several sensors, each with its own code,
// after its codeless budget is spent: starts with a code are budgeted by the
// code (burst 3 each) under a wider per-address cap (burst 10).
func TestPairingStartBudget_ByCodeNotOnlyAddress(t *testing.T) {
	b := testBudget(t)
	ip := "198.51.100.4:1000"
	for range pairingCodelessPerIPBurst + 1 {
		b.ChargeStart(budgetRequest(ip), "")
	}
	for i := range pairingCredentialPerIPBurst {
		if _, ok := b.ChargeStart(budgetRequest(ip), fmt.Sprintf("code:K7QM%04d", i)); !ok {
			t.Fatalf("start with code %d refused after the codeless budget was spent", i)
		}
	}
	if _, ok := b.ChargeStart(budgetRequest(ip), "code:ZZZZ0000"); ok {
		t.Fatal("per-address cap on starts with a code not enforced")
	}
}

// One code (or token) gets a bounded number of starts, from any address.
func TestPairingStartBudget_PerCredentialBound(t *testing.T) {
	b := testBudget(t)
	for i := range pairingPerCredentialBurst {
		if _, ok := b.ChargeStart(budgetRequest(fmt.Sprintf("192.0.2.%d:1000", i+1)), "token:octe_abc"); !ok {
			t.Fatalf("token start %d refused", i+1)
		}
	}
	if _, ok := b.ChargeStart(budgetRequest("192.0.2.99:1000"), "token:octe_abc"); ok {
		t.Fatal("per-token bound not enforced across addresses")
	}
	if _, ok := b.ChargeStart(budgetRequest("192.0.2.99:1000"), "code:K7QM4ZTD"); !ok {
		t.Fatal("another credential shares the token's budget")
	}
}
