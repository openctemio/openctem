package unit

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/openctemio/api/internal/config"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/logger"
)

func newTestCSRFConfig() middleware.CSRFConfig {
	log := logger.NewDevelopment()
	return middleware.CSRFConfig{
		Secure:   false,
		Domain:   "",
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
		TTL:      24 * time.Hour,
		Logger:   log,
	}
}

func TestGenerateCSRFToken_Success(t *testing.T) {
	token, err := middleware.GenerateCSRFToken()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if token == "" {
		t.Fatal("expected non-empty token")
	}
	// Token should be base64 encoded, minimum length check
	if len(token) < 32 {
		t.Errorf("expected token length >= 32, got %d", len(token))
	}
}

func TestGenerateCSRFToken_Unique(t *testing.T) {
	tokens := make(map[string]bool)
	for i := 0; i < 100; i++ {
		token, err := middleware.GenerateCSRFToken()
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if tokens[token] {
			t.Fatal("generated duplicate token")
		}
		tokens[token] = true
	}
}

func TestSetCSRFTokenCookie_Success(t *testing.T) {
	cfg := newTestCSRFConfig()
	rec := httptest.NewRecorder()
	token := "test-csrf-token"

	middleware.SetCSRFTokenCookie(rec, token, cfg)

	result := rec.Result()
	defer result.Body.Close()

	cookies := result.Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}

	cookie := cookies[0]
	if cookie.Name != middleware.CSRFTokenCookieName {
		t.Errorf("expected cookie name %s, got %s", middleware.CSRFTokenCookieName, cookie.Name)
	}
	if cookie.Value != token {
		t.Errorf("expected cookie value %s, got %s", token, cookie.Value)
	}
	if cookie.HttpOnly {
		t.Error("expected HttpOnly to be false (CSRF cookie must be readable by JavaScript)")
	}
}

func TestClearCSRFTokenCookie_Success(t *testing.T) {
	cfg := newTestCSRFConfig()
	rec := httptest.NewRecorder()

	middleware.ClearCSRFTokenCookie(rec, cfg)

	result := rec.Result()
	defer result.Body.Close()

	cookies := result.Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}

	cookie := cookies[0]
	if cookie.MaxAge != -1 {
		t.Errorf("expected MaxAge -1, got %d", cookie.MaxAge)
	}
}

func TestCSRFMiddleware_SafeMethods(t *testing.T) {
	cfg := newTestCSRFConfig()
	csrfMiddleware := middleware.CSRF(cfg)

	handler := csrfMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Safe methods should pass without CSRF token
	safeMethods := []string{http.MethodGet, http.MethodHead, http.MethodOptions}
	for _, method := range safeMethods {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/api/v1/test", nil)
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Errorf("expected status 200, got %d", rec.Code)
			}
		})
	}
}

func TestCSRFMiddleware_MissingCookie(t *testing.T) {
	cfg := newTestCSRFConfig()
	csrfMiddleware := middleware.CSRF(cfg)

	handler := csrfMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected status 403, got %d", rec.Code)
	}
}

func TestCSRFMiddleware_MissingHeader(t *testing.T) {
	cfg := newTestCSRFConfig()
	csrfMiddleware := middleware.CSRF(cfg)

	handler := csrfMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/test", nil)
	req.AddCookie(&http.Cookie{
		Name:  middleware.CSRFTokenCookieName,
		Value: "test-token",
	})
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected status 403, got %d", rec.Code)
	}
}

func TestCSRFMiddleware_TokenMismatch(t *testing.T) {
	cfg := newTestCSRFConfig()
	csrfMiddleware := middleware.CSRF(cfg)

	handler := csrfMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/test", nil)
	req.AddCookie(&http.Cookie{
		Name:  middleware.CSRFTokenCookieName,
		Value: "cookie-token",
	})
	req.Header.Set(middleware.CSRFHeaderName, "header-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected status 403, got %d", rec.Code)
	}
}

func TestCSRFMiddleware_ValidToken(t *testing.T) {
	cfg := newTestCSRFConfig()
	csrfMiddleware := middleware.CSRF(cfg)

	handler := csrfMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	token := "matching-csrf-token"
	req := httptest.NewRequest(http.MethodPost, "/api/v1/test", nil)
	req.AddCookie(&http.Cookie{
		Name:  middleware.CSRFTokenCookieName,
		Value: token,
	})
	req.Header.Set(middleware.CSRFHeaderName, token)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
}

func TestCSRFOptional_NoCookie(t *testing.T) {
	cfg := newTestCSRFConfig()
	csrfMiddleware := middleware.CSRFOptional(cfg)

	handler := csrfMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// POST without cookie should pass (assumes token in body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200 (no cookie = skip validation), got %d", rec.Code)
	}
}

func TestCSRFOptional_CookiePresentRequiresHeader(t *testing.T) {
	cfg := newTestCSRFConfig()
	csrfMiddleware := middleware.CSRFOptional(cfg)

	handler := csrfMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// POST with cookie but no header should fail
	req := httptest.NewRequest(http.MethodPost, "/api/v1/test", nil)
	req.AddCookie(&http.Cookie{
		Name:  middleware.CSRFTokenCookieName,
		Value: "test-token",
	})
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected status 403, got %d", rec.Code)
	}
}

func TestNewCSRFConfig_FromAuthConfig(t *testing.T) {
	log := logger.NewDevelopment()
	authCfg := config.AuthConfig{
		CookieSecure:         true,
		CookieDomain:         "example.com",
		CookieSameSite:       "strict",
		RefreshTokenDuration: 7 * 24 * time.Hour,
	}

	cfg := middleware.NewCSRFConfig(authCfg, log)

	if !cfg.Secure {
		t.Error("expected Secure to be true")
	}
	if cfg.Domain != authCfg.CookieDomain {
		t.Errorf("expected domain %s, got %s", authCfg.CookieDomain, cfg.Domain)
	}
	if cfg.SameSite != http.SameSiteStrictMode {
		t.Errorf("expected SameSiteStrictMode, got %v", cfg.SameSite)
	}
	if cfg.TTL != authCfg.RefreshTokenDuration {
		t.Errorf("expected TTL %v, got %v", authCfg.RefreshTokenDuration, cfg.TTL)
	}
}
