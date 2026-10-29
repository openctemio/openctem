package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type factorStub struct {
	err   error
	calls int
}

func (f *factorStub) CheckCredentialFactor(context.Context, string, string, string) error {
	f.calls++
	return f.err
}

func serveFactor(c CredentialFactorChecker, r *http.Request) (*httptest.ResponseRecorder, bool) {
	reached := false
	h := RequireCredentialFactor(c)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec, reached
}

func TestRequireCredentialFactor(t *testing.T) {
	req := func() *http.Request { return httptest.NewRequest(http.MethodPost, "/api/v1/api-keys", nil) }

	t.Run("a caller with the factor passes", func(t *testing.T) {
		stub := &factorStub{}
		rec, reached := serveFactor(stub, req())
		if !reached || rec.Code != http.StatusOK || stub.calls != 1 {
			t.Fatalf("reached %v code %d calls %d", reached, rec.Code, stub.calls)
		}
	})
	t.Run("a caller without it gets 403 MFA_ENROLLMENT_REQUIRED and the handler never runs", func(t *testing.T) {
		rec, reached := serveFactor(&factorStub{err: ErrCredentialFactorRequired}, req())
		if reached || rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "MFA_ENROLLMENT_REQUIRED") {
			t.Fatalf("reached %v code %d body %s", reached, rec.Code, rec.Body.String())
		}
	})
	t.Run("a provider that must prove a factor says so", func(t *testing.T) {
		rec, reached := serveFactor(&factorStub{err: ErrCredentialProofRequired}, req())
		if reached || rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "identity provider") {
			t.Fatalf("reached %v code %d body %s", reached, rec.Code, rec.Body.String())
		}
	})
	t.Run("a failed check fails closed", func(t *testing.T) {
		rec, reached := serveFactor(&factorStub{err: errors.New("db down")}, req())
		if reached || rec.Code != http.StatusInternalServerError {
			t.Fatalf("reached %v code %d", reached, rec.Code)
		}
	})
	t.Run("no checker wired lets the request through", func(t *testing.T) {
		if _, reached := serveFactor(nil, req()); !reached {
			t.Fatal("a nil checker must not block (tests without the auth service)")
		}
	})
}
