package middleware

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openctemio/api/pkg/logger"
)

// F-1 / F-314: unit tests for VerifyHMAC. These cover the full threat
// model of the Jira webhook endpoint:
//   - no signature header -> 401 (prevents unsigned forgery)
//   - no secret configured -> 401 (fail closed, never silently skip)
//   - bad signature -> 401
//   - body rewritten for downstream handler so JSON decode still works
//   - sha256= prefix accepted (GitHub/Jira-style)
//   - body-size cap enforced

func validSig(body []byte, secret string) string {
	m := hmac.New(sha256.New, []byte(secret))
	_, _ = m.Write(body)
	return hex.EncodeToString(m.Sum(nil))
}

// downstream is a no-op handler that also reads the body so we can assert
// the middleware rewound it correctly.
func downstream(t *testing.T, wantBody []byte) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("downstream read body: %v", err)
		}
		if !bytes.Equal(got, wantBody) {
			t.Fatalf("downstream body = %q, want %q", got, wantBody)
		}
		w.WriteHeader(http.StatusOK)
	})
}

func runMW(t *testing.T, mw func(http.Handler) http.Handler, handler http.Handler, body []byte, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/hook", bytes.NewReader(body))
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	mw(handler).ServeHTTP(rec, req)
	return rec
}

func TestVerifyHMAC_MissingSignature_Rejects(t *testing.T) {
	log := logger.NewNop()
	secret := "s3cr3t-pepper-32-bytes-xxxxxxxxxxxx"
	mw := VerifyHMAC("X-OpenCTEM-Signature", func(*http.Request) (string, bool) {
		return secret, true
	}, log)
	rec := runMW(t, mw, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatalf("handler must not be reached without signature")
	}), []byte(`{"a":1}`), nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestVerifyHMAC_EmptySecret_FailsClosed(t *testing.T) {
	log := logger.NewNop()
	mw := VerifyHMAC("X-OpenCTEM-Signature", func(*http.Request) (string, bool) {
		return "", false
	}, log)
	body := []byte(`{"a":1}`)
	rec := runMW(t, mw, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatalf("handler must not run when secret is missing")
	}), body, map[string]string{
		"X-OpenCTEM-Signature": validSig(body, "any-secret"),
	})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (fail-closed)", rec.Code)
	}
}

func TestVerifyHMAC_BadSignature_Rejects(t *testing.T) {
	log := logger.NewNop()
	secret := "correct-secret"
	mw := VerifyHMAC("X-OpenCTEM-Signature", func(*http.Request) (string, bool) {
		return secret, true
	}, log)
	body := []byte(`{"a":1}`)
	// Signature computed with DIFFERENT secret.
	badSig := validSig(body, "wrong-secret")
	rec := runMW(t, mw, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatalf("handler must not run on bad sig")
	}), body, map[string]string{
		"X-OpenCTEM-Signature": badSig,
	})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestVerifyHMAC_ValidSignature_PassesAndRewinds(t *testing.T) {
	log := logger.NewNop()
	secret := "correct-secret"
	body := []byte(`{"hello":"world"}`)
	mw := VerifyHMAC("X-OpenCTEM-Signature", func(*http.Request) (string, bool) {
		return secret, true
	}, log)
	rec := runMW(t, mw, downstream(t, body), body, map[string]string{
		"X-OpenCTEM-Signature": validSig(body, secret),
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestVerifyHMAC_AcceptsSha256Prefix(t *testing.T) {
	log := logger.NewNop()
	secret := "correct-secret"
	body := []byte(`{"hello":"world"}`)
	mw := VerifyHMAC("X-OpenCTEM-Signature", func(*http.Request) (string, bool) {
		return secret, true
	}, log)
	rec := runMW(t, mw, downstream(t, body), body, map[string]string{
		"X-OpenCTEM-Signature": "sha256=" + validSig(body, secret),
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (sha256= prefix)", rec.Code)
	}
}

func TestVerifyHMAC_CaseInsensitiveHex(t *testing.T) {
	log := logger.NewNop()
	secret := "correct-secret"
	body := []byte(`x`)
	mw := VerifyHMAC("X-OpenCTEM-Signature", func(*http.Request) (string, bool) {
		return secret, true
	}, log)
	rec := runMW(t, mw, downstream(t, body), body, map[string]string{
		"X-OpenCTEM-Signature": strings.ToUpper(validSig(body, secret)),
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (upper-case hex)", rec.Code)
	}
}

func TestVerifyHMAC_MalformedHex_Rejects(t *testing.T) {
	log := logger.NewNop()
	mw := VerifyHMAC("X-OpenCTEM-Signature", func(*http.Request) (string, bool) {
		return "secret", true
	}, log)
	rec := runMW(t, mw, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatalf("handler must not run on malformed sig")
	}), []byte(`{}`), map[string]string{
		"X-OpenCTEM-Signature": "not-a-hex-string",
	})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestVerifyHMAC_BodyTooLarge_Rejects(t *testing.T) {
	log := logger.NewNop()
	mw := VerifyHMAC("X-OpenCTEM-Signature", func(*http.Request) (string, bool) {
		return "s", true
	}, log)
	// 2 MiB + 1 should trigger the size check. Content doesn't matter
	// because the middleware rejects on length before signature work.
	big := make([]byte, 2*1024*1024+1)
	rec := runMW(t, mw, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatalf("handler must not run on oversized body")
	}), big, map[string]string{
		"X-OpenCTEM-Signature": validSig(big, "s"),
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}
