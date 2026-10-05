package middleware

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
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
