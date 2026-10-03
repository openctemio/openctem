package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

var (
	depAt    = time.Date(2026, time.November, 1, 0, 0, 0, 0, time.UTC)
	sunsetAt = time.Date(2027, time.January, 15, 0, 0, 0, 0, time.UTC)
)

func TestDeprecated_HeadersOnEveryAnswer(t *testing.T) {
	mw := Deprecated(Deprecation{
		Plane: "self", Route: "users_me_sessions_test", Successor: "/api/v1/me/sessions",
		DeprecatedAt: depAt, SunsetAt: sunsetAt,
	})
	for _, status := range []int{http.StatusOK, http.StatusUnauthorized, http.StatusInternalServerError} {
		h := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(status)
		}))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/users/me/sessions", nil))

		if rec.Code != status {
			t.Fatalf("status changed: %d, want %d", rec.Code, status)
		}
		if got := rec.Header().Get("Deprecation"); got != "@1793491200" {
			t.Errorf("Deprecation = %q, want @1793491200", got)
		}
		if got := rec.Header().Get("Sunset"); got != "Fri, 15 Jan 2027 00:00:00 GMT" {
			t.Errorf("Sunset = %q", got)
		}
	}
}

func TestDeprecated_SuccessorLinkKeptWhenHandlerAddsLinks(t *testing.T) {
	mw := Deprecated(Deprecation{
		Plane: "user", Route: "succ_func_test",
		SuccessorFunc: func(r *http.Request) string { return "/api/v1/organization/members/" + r.URL.Query().Get("id") },
		DeprecatedAt:  depAt, SunsetAt: sunsetAt,
	})
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Add("Link", "</next>; rel=\"next\"")
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x?id=42", nil))
	links := rec.Header().Values("Link")
	if len(links) != 2 || links[0] != "</api/v1/organization/members/42>; rel=\"successor-version\"" {
		t.Fatalf("Link = %q", links)
	}
}

func TestDeprecated_CountsByClient(t *testing.T) {
	mw := Deprecated(Deprecation{
		Plane: "auth", Route: "count_test", Successor: "/new",
		DeprecatedAt: depAt, SunsetAt: sunsetAt,
	})
	h := mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	for _, set := range []func(*http.Request){
		func(r *http.Request) { r.Header.Set("Authorization", "Bearer oct_abc") },
		func(r *http.Request) { r.Header.Set("X-API-Key", "oct_abc") },
		func(r *http.Request) { r.Header.Set("X-API-Key", "octs_abc") },
		func(r *http.Request) { r.Header.Set("Authorization", "Bearer eyJhbGciOi") },
		func(r *http.Request) { r.AddCookie(&http.Cookie{Name: DefaultAccessTokenCookieName, Value: "x"}) },
		func(r *http.Request) { r.AddCookie(&http.Cookie{Name: AdminSessionCookie, Value: "x"}) },
		func(*http.Request) {},
	} {
		req := httptest.NewRequest(http.MethodPost, "/old", nil)
		set(req)
		h.ServeHTTP(httptest.NewRecorder(), req)
	}
	for client, want := range map[string]float64{"oct_key": 2, "sensor": 1, "web": 2, "admin": 1, "anonymous": 1} {
		if got := testutil.ToFloat64(DeprecatedRouteRequests.WithLabelValues("auth", "count_test", client)); got != want {
			t.Errorf("client %s counted %v, want %v", client, got, want)
		}
	}
}

func TestDeprecated_InvalidDescriptionPanics(t *testing.T) {
	for name, d := range map[string]Deprecation{
		"no route":           {Plane: "user", Successor: "/x", DeprecatedAt: depAt, SunsetAt: sunsetAt},
		"no successor":       {Plane: "user", Route: "r", DeprecatedAt: depAt, SunsetAt: sunsetAt},
		"no dates":           {Plane: "user", Route: "r", Successor: "/x"},
		"sunset before dep.": {Plane: "user", Route: "r", Successor: "/x", DeprecatedAt: sunsetAt, SunsetAt: depAt},
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s: no panic", name)
				}
			}()
			Deprecated(d)
		}()
	}
}
