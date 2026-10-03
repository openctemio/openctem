package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openctemio/openctem/api/internal/app"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
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
	mw := WSTicketAuth(&fakeRedeemer{err: app.ErrTicketNotFound}, nil, log)

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
	mw := WSTicketAuth(&fakeRedeemer{err: app.ErrTicketNotFound}, nil, log)

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
	mw := WSTicketAuth(&fakeRedeemer{err: errors.New("redis down")}, nil, log)

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
	}, nil, log)

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
	mw := WSTicketAuth(r, nil, log)

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

// fakeMembers serves one membership (or an error) to the upgrade re-check.
type fakeMembers struct {
	m   *tenant.Membership
	err error
}

func (f fakeMembers) GetMembership(_ context.Context, userID, tenantID shared.ID) (*tenant.Membership, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.m == nil || f.m.UserID() != userID || f.m.TenantID() != tenantID {
		return nil, shared.ErrNotFound
	}
	return f.m, nil
}

// The ticket is bound to a user and tenant; at upgrade the membership is
// checked again so a member suspended or removed after issue gets nothing.
func TestWSTicketAuth_RechecksMembershipAtUpgrade(t *testing.T) {
	userID, tenantID := shared.NewID(), shared.NewID()
	active, err := tenant.NewMembership(userID, tenantID, tenant.RoleMember, nil)
	if err != nil {
		t.Fatal(err)
	}
	suspended, _ := tenant.NewMembership(userID, tenantID, tenant.RoleMember, nil)
	if err := suspended.Suspend(shared.NewID()); err != nil {
		t.Fatal(err)
	}
	otherTenant, _ := tenant.NewMembership(userID, shared.NewID(), tenant.RoleMember, nil)

	cases := []struct {
		name    string
		members MembershipReader
		claims  app.WSTicketClaims
		want    int
	}{
		{"active member", fakeMembers{m: active}, app.WSTicketClaims{UserID: userID.String(), TenantID: tenantID.String()}, http.StatusOK},
		{"suspended member", fakeMembers{m: suspended}, app.WSTicketClaims{UserID: userID.String(), TenantID: tenantID.String()}, http.StatusForbidden},
		{"removed member", fakeMembers{}, app.WSTicketClaims{UserID: userID.String(), TenantID: tenantID.String()}, http.StatusForbidden},
		{"member of another tenant only", fakeMembers{m: otherTenant}, app.WSTicketClaims{UserID: userID.String(), TenantID: tenantID.String()}, http.StatusForbidden},
		{"lookup error fails closed", fakeMembers{err: errors.New("db down")}, app.WSTicketClaims{UserID: userID.String(), TenantID: tenantID.String()}, http.StatusInternalServerError},
		{"malformed ids", fakeMembers{m: active}, app.WSTicketClaims{UserID: "u", TenantID: "t"}, http.StatusUnauthorized},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			claims := tc.claims
			mw := WSTicketAuth(&fakeRedeemer{claims: &claims}, tc.members, logger.NewNop())
			req := httptest.NewRequest(http.MethodGet, "/api/v1/ws/?ticket=x", nil)
			rec := httptest.NewRecorder()
			reached := false
			mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				reached = true
				if GetUserID(r.Context()) != claims.UserID || GetTenantID(r.Context()) != claims.TenantID {
					t.Errorf("context identity = %s/%s, want the ticket's", GetUserID(r.Context()), GetTenantID(r.Context()))
				}
				w.WriteHeader(http.StatusOK)
			})).ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d (%s)", rec.Code, tc.want, rec.Body.String())
			}
			if reached != (tc.want == http.StatusOK) {
				t.Fatalf("handler reached = %v, want %v", reached, tc.want == http.StatusOK)
			}
		})
	}
}
