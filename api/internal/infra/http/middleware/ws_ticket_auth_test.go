package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/pkg/logger"
)

// F-8: the ticket middleware is the only authenticator on /ws when
// Redis is available. These tests lock in its contract:
//   - missing ticket -> 401
//   - invalid ticket -> 401 (no leak of why)
//   - valid ticket -> downstream sees user+tenant in context
//   - replay after successful redemption -> second request rejected
//     (covered by the service-level test but checked end-to-end here too)

type fakeRedeemer struct {
	claims *app.WSTicketClaims
	err    error
	// usedOnce toggles to true after first successful redemption.
	usedOnce bool
}

func (f *fakeRedeemer) RedeemTicket(_ context.Context, _ string) (*app.WSTicketClaims, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.usedOnce {
		return nil, app.ErrTicketNotFound
	}
	f.usedOnce = true
	return f.claims, nil
}

func TestWSTicketAuth_MissingTicket_Rejects(t *testing.T) {
	log := logger.NewNop()
	mw := WSTicketAuth(&fakeRedeemer{err: app.ErrTicketNotFound}, log)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/ws/", nil)
	rec := httptest.NewRecorder()
	mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("handler must not run without a ticket")
	})).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestWSTicketAuth_InvalidTicket_Rejects(t *testing.T) {
	log := logger.NewNop()
	mw := WSTicketAuth(&fakeRedeemer{err: app.ErrTicketNotFound}, log)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/ws/?ticket=abcdef", nil)
	rec := httptest.NewRecorder()
	mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("handler must not run for invalid ticket")
	})).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestWSTicketAuth_OtherError_Rejects(t *testing.T) {
	log := logger.NewNop()
	mw := WSTicketAuth(&fakeRedeemer{err: errors.New("redis down")}, log)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/ws/?ticket=abcdef", nil)
	rec := httptest.NewRecorder()
	mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("handler must not run when redeem errors")
	})).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (fail-closed on any error)", rec.Code)
	}
}

func TestWSTicketAuth_Valid_SetsContextKeys(t *testing.T) {
	log := logger.NewNop()
	mw := WSTicketAuth(&fakeRedeemer{
		claims: &app.WSTicketClaims{UserID: "u-1", TenantID: "t-1", IssuedAt: 1},
	}, log)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/ws/?ticket=somestring", nil)
	rec := httptest.NewRecorder()

	var gotUser, gotTenant string
	mw(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		gotUser = GetUserID(r.Context())
		gotTenant = GetTenantID(r.Context())
	})).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if gotUser != "u-1" {
		t.Fatalf("user = %q, want u-1", gotUser)
	}
	if gotTenant != "t-1" {
		t.Fatalf("tenant = %q, want t-1", gotTenant)
	}
}

func TestWSTicketAuth_Replay_Rejected(t *testing.T) {
	// End-to-end replay check: fake redeemer flips usedOnce after first
	// success. Middleware must reject the second call.
	log := logger.NewNop()
	r := &fakeRedeemer{claims: &app.WSTicketClaims{UserID: "u", TenantID: "t"}}
	mw := WSTicketAuth(r, log)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/ws/?ticket=samestring", nil)

	rec1 := httptest.NewRecorder()
	mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rec1, req)
	if rec1.Code != http.StatusOK {
		t.Fatalf("first call status = %d, want 200", rec1.Code)
	}

	rec2 := httptest.NewRecorder()
	mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("handler must not run on replay")
	})).ServeHTTP(rec2, req)
	if rec2.Code != http.StatusUnauthorized {
		t.Fatalf("replay status = %d, want 401", rec2.Code)
	}
}
