package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/sensorkey"
)

// A sensor key (octs_, legacy rda_) or an enrollment token (octe_) presented
// as a bearer token is never routed to user / MCP API-key authentication,
// which owns the "oct_" prefix. octs_ shares the "oct" letters, so this
// pins that the routing matches "oct_" exactly.
func TestSensorCredentialsAreNeverUserAPIKeys(t *testing.T) {
	octs, err := sensorkey.New(sensorkey.PrefixSensorKey)
	if err != nil {
		t.Fatal(err)
	}
	octe, err := sensorkey.New(sensorkey.PrefixEnrollmentToken)
	if err != nil {
		t.Fatal(err)
	}
	tokens := map[string]string{
		"octs_ sensor key":       octs,
		"octe_ enrollment token": octe,
		"legacy rda_ key":        "rda_" + "0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f",
	}
	for name, tok := range tokens {
		r := httptest.NewRequest(http.MethodGet, "/api/v1/assets", nil)
		r.Header.Set("Authorization", "Bearer "+tok)
		if got := extractAPIKeyToken(r); got != "" {
			t.Errorf("%s: extracted as a user API key", name)
		}
		if hasAPIKeyCredential(r) {
			t.Errorf("%s: treated as a user API-key credential", name)
		}
		if _, ok := restAPIKeyToken(r); ok {
			t.Errorf("%s: accepted as a REST user API key", name)
		}

		// The REST chain sends it to the JWT path, never the key authenticator.
		fa := &fakeAuthenticator{}
		h := newRESTHarness(fa)
		h.serve(http.MethodGet, "/api/v1/assets", map[string]string{"Authorization": "Bearer " + tok})
		if fa.calls != 0 || !h.jwtCalled {
			t.Errorf("%s: key authenticator calls %d, jwt path %v", name, fa.calls, h.jwtCalled)
		}

		// The MCP chain (keys only) refuses it without a key lookup.
		fa = &fakeAuthenticator{}
		rec := httptest.NewRecorder()
		APIKeyAuth(fa, logger.NewNop())(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			t.Errorf("%s: reached the MCP handler", name)
		})).ServeHTTP(rec, r)
		if fa.calls != 0 || rec.Code != http.StatusUnauthorized {
			t.Errorf("%s: MCP chain code %d, key authenticator calls %d", name, rec.Code, fa.calls)
		}
	}
}
