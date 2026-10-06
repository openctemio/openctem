package middleware

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"

	"github.com/openctemio/openctem/api/pkg/keycloak"
)

type stubRecentAuth struct {
	at    time.Time
	err   error
	calls []string
}

func (s *stubRecentAuth) RecentAuthAt(_ context.Context, userID, sessionID string) (time.Time, error) {
	s.calls = append(s.calls, userID+"/"+sessionID)
	return s.at, s.err
}

func TestRequireRecentAuth(t *testing.T) {
	const window = 10 * time.Minute
	session := func(ctx context.Context) context.Context {
		ctx = context.WithValue(ctx, UserIDKey, "u1")
		return context.WithValue(ctx, SessionIDKey, "s1")
	}
	now := time.Now()
	for _, tc := range []struct {
		name     string
		checker  RecentAuthChecker
		ctx      func(context.Context) context.Context
		wantCode int
		wantErr  string
	}{
		{"fresh sign-in or step-up passes", &stubRecentAuth{at: now.Add(-time.Minute)}, session, http.StatusOK, ""},
		{"just inside the window passes", &stubRecentAuth{at: now.Add(-window + 5*time.Second)}, session, http.StatusOK, ""},
		{"expired window is refused", &stubRecentAuth{at: now.Add(-window - time.Second)}, session, http.StatusForbidden, "STEP_UP_REQUIRED"},
		{"never authenticated (zero time) is refused", &stubRecentAuth{}, session, http.StatusForbidden, "STEP_UP_REQUIRED"},
		{"a time in the future is refused", &stubRecentAuth{at: now.Add(time.Hour)}, session, http.StatusForbidden, "STEP_UP_REQUIRED"},
		{"unknown, revoked or foreign session is refused", &stubRecentAuth{err: ErrNoRecentAuth}, session, http.StatusForbidden, "STEP_UP_REQUIRED"},
		{"a lookup error fails closed", &stubRecentAuth{err: errors.New("db down")}, session, http.StatusInternalServerError, ""},
		{"no checker fails closed", nil, session, http.StatusForbidden, "STEP_UP_UNAVAILABLE"},
		{"no session id (OIDC token) cannot step up", &stubRecentAuth{at: now},
			func(ctx context.Context) context.Context { return context.WithValue(ctx, UserIDKey, "u1") },
			http.StatusForbidden, "STEP_UP_UNAVAILABLE"},
		{"an API key cannot step up", &stubRecentAuth{at: now},
			func(ctx context.Context) context.Context { return context.WithValue(session(ctx), APIKeyIDKey, "k1") },
			http.StatusForbidden, "STEP_UP_UNAVAILABLE"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := RequireRecentAuth(tc.checker, window)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))
			req := httptest.NewRequest(http.MethodPost, "/x", nil)
			req = req.WithContext(tc.ctx(req.Context()))
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tc.wantCode {
				t.Fatalf("status %d, want %d (%s)", rec.Code, tc.wantCode, rec.Body.String())
			}
			if tc.wantErr != "" {
				var body struct {
					Code string `json:"code"`
				}
				_ = json.Unmarshal(rec.Body.Bytes(), &body)
				if body.Code != tc.wantErr {
					t.Fatalf("code %q, want %q", body.Code, tc.wantErr)
				}
			}
		})
	}

	t.Run("the check is made for the caller's own user and session", func(t *testing.T) {
		st := &stubRecentAuth{at: now}
		h := RequireRecentAuth(st, window)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		req := httptest.NewRequest(http.MethodPost, "/x", nil)
		h.ServeHTTP(httptest.NewRecorder(), req.WithContext(session(req.Context())))
		if len(st.calls) != 1 || st.calls[0] != "u1/s1" {
			t.Fatalf("calls %v", st.calls)
		}
	})
}

// A token from the external OIDC provider has no platform session; its
// recent authentication is the provider's signed auth_time claim.
func TestRequireRecentAuth_ExternalProviderToken(t *testing.T) {
	const window = 10 * time.Minute
	now := time.Now()
	provider := func(authTime *jwtv5.NumericDate) func(context.Context) context.Context {
		return func(ctx context.Context) context.Context {
			ctx = context.WithValue(ctx, UserIDKey, "kc-user")
			ctx = context.WithValue(ctx, AuthProviderKey, AuthProviderOIDC)
			return context.WithValue(ctx, ClaimsKey, &keycloak.Claims{AuthTime: authTime})
		}
	}
	for _, tc := range []struct {
		name     string
		ctx      func(context.Context) context.Context
		wantCode int
		wantErr  string
	}{
		{"signed in at the provider a minute ago", provider(jwtv5.NewNumericDate(now.Add(-time.Minute))), http.StatusOK, ""},
		{"signed in at the provider an hour ago", provider(jwtv5.NewNumericDate(now.Add(-time.Hour))), http.StatusForbidden, "STEP_UP_REQUIRED"},
		{"auth_time in the future", provider(jwtv5.NewNumericDate(now.Add(time.Hour))), http.StatusForbidden, "STEP_UP_REQUIRED"},
		{"no auth_time", provider(nil), http.StatusForbidden, "STEP_UP_UNAVAILABLE"},
		{"no claims", func(ctx context.Context) context.Context {
			return context.WithValue(context.WithValue(ctx, UserIDKey, "kc-user"), AuthProviderKey, AuthProviderOIDC)
		}, http.StatusForbidden, "STEP_UP_UNAVAILABLE"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// The session checker is never consulted for a provider token.
			st := &stubRecentAuth{at: now}
			h := RequireRecentAuth(st, window)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))
			req := httptest.NewRequest(http.MethodPost, "/x", nil)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req.WithContext(tc.ctx(req.Context())))
			if rec.Code != tc.wantCode {
				t.Fatalf("status %d, want %d (%s)", rec.Code, tc.wantCode, rec.Body.String())
			}
			var body struct {
				Code string `json:"code"`
			}
			_ = json.Unmarshal(rec.Body.Bytes(), &body)
			if body.Code != tc.wantErr {
				t.Fatalf("code %q, want %q", body.Code, tc.wantErr)
			}
			if len(st.calls) != 0 {
				t.Fatal("a provider token was checked against a platform session")
			}
		})
	}
}

// RecentAuthGate is the same check for a service: it judges only the user
// making the request, and answers with CheckRecentAuth's errors.
func TestRecentAuthGate(t *testing.T) {
	const window = 10 * time.Minute
	now := time.Now()
	session := func(ctx context.Context) context.Context {
		ctx = context.WithValue(ctx, UserIDKey, "u1")
		return context.WithValue(ctx, SessionIDKey, "s1")
	}
	dbDown := errors.New("db down")
	for _, tc := range []struct {
		name        string
		checker     RecentAuthChecker
		ctx         func(context.Context) context.Context
		actor       string
		want        error
		wantChecked bool
	}{
		{"fresh session of the actor", &stubRecentAuth{at: now.Add(-time.Minute)}, session, "u1", nil, true},
		{"stale session of the actor", &stubRecentAuth{at: now.Add(-time.Hour)}, session, "u1", ErrStepUpRequired, true},
		{"actor is not the request's user (an accepted invitation)", &stubRecentAuth{at: now.Add(-time.Hour)}, session, "inviter", nil, false},
		{"no request user (a system path)", &stubRecentAuth{}, func(ctx context.Context) context.Context { return ctx }, "u1", nil, false},
		{"empty actor", &stubRecentAuth{}, session, "", nil, false},
		{"API key of the actor", &stubRecentAuth{at: now},
			func(ctx context.Context) context.Context { return context.WithValue(session(ctx), APIKeyIDKey, "k1") }, "u1", ErrStepUpUnavailable, false},
		{"no checker wired", nil, session, "u1", ErrStepUpUnavailable, false},
		{"lookup error fails closed", &stubRecentAuth{err: dbDown}, session, "u1", dbDown, true},
		{"external provider token signed in an hour ago", &stubRecentAuth{at: now}, func(ctx context.Context) context.Context {
			ctx = context.WithValue(ctx, UserIDKey, "u1")
			ctx = context.WithValue(ctx, AuthProviderKey, AuthProviderOIDC)
			return context.WithValue(ctx, ClaimsKey, &keycloak.Claims{AuthTime: jwtv5.NewNumericDate(now.Add(-time.Hour))})
		}, "u1", ErrStepUpRequired, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st, _ := tc.checker.(*stubRecentAuth)
			err := RecentAuthGate{Checker: tc.checker, Window: window}.RequireRecentAuth(tc.ctx(context.Background()), tc.actor)
			if !errors.Is(err, tc.want) || (tc.want == nil && err != nil) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
			if st != nil && (len(st.calls) > 0) != tc.wantChecked {
				t.Fatalf("session checked = %v, want %v", len(st.calls) > 0, tc.wantChecked)
			}
		})
	}
}
