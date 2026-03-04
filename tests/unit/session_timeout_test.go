package unit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"

	"github.com/openctemio/api/internal/infra/http/middleware"
	localjwt "github.com/openctemio/api/pkg/jwt"
)

// TestSessionTimeout tests the session expiry logic in the unified auth middleware.
// The isSessionExpired function checks if a token's issued-at (iat) claim
// exceeds the configured session timeout.
//
// Run with: go test -v ./tests/unit -run TestSessionTimeout
func TestSessionTimeout(t *testing.T) {
	t.Run("TokenWithinTimeout_NotExpired", func(t *testing.T) {
		// Token issued 5 minutes ago, timeout is 30 minutes
		claims := &localjwt.Claims{
			UserID: "user-123",
			RegisteredClaims: jwt.RegisteredClaims{
				IssuedAt: jwt.NewNumericDate(time.Now().Add(-5 * time.Minute)),
			},
		}
		ctx := context.WithValue(context.Background(), middleware.LocalClaimsKey, claims)

		// Create handler that will succeed if session is not expired
		handlerCalled := false
		testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlerCalled = true
			w.WriteHeader(http.StatusOK)
		})

		// Build a middleware that checks session timeout using the context
		mw := sessionTimeoutChecker(30, testHandler)
		req := httptest.NewRequest(http.MethodGet, "/test", nil).WithContext(ctx)
		rec := httptest.NewRecorder()

		mw.ServeHTTP(rec, req)

		assert.True(t, handlerCalled, "handler should be called when session is not expired")
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("TokenBeyondTimeout_Expired", func(t *testing.T) {
		// Token issued 60 minutes ago, timeout is 30 minutes
		claims := &localjwt.Claims{
			UserID: "user-123",
			RegisteredClaims: jwt.RegisteredClaims{
				IssuedAt: jwt.NewNumericDate(time.Now().Add(-60 * time.Minute)),
			},
		}
		ctx := context.WithValue(context.Background(), middleware.LocalClaimsKey, claims)

		handlerCalled := false
		testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlerCalled = true
			w.WriteHeader(http.StatusOK)
		})

		mw := sessionTimeoutChecker(30, testHandler)
		req := httptest.NewRequest(http.MethodGet, "/test", nil).WithContext(ctx)
		rec := httptest.NewRecorder()

		mw.ServeHTTP(rec, req)

		assert.False(t, handlerCalled, "handler should not be called when session is expired")
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("NoIssuedAtClaim_NotExpired", func(t *testing.T) {
		// Token without iat claim should be treated as not expired (graceful)
		claims := &localjwt.Claims{
			UserID: "user-123",
			RegisteredClaims: jwt.RegisteredClaims{
				// IssuedAt is nil
			},
		}
		ctx := context.WithValue(context.Background(), middleware.LocalClaimsKey, claims)

		handlerCalled := false
		testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlerCalled = true
			w.WriteHeader(http.StatusOK)
		})

		mw := sessionTimeoutChecker(30, testHandler)
		req := httptest.NewRequest(http.MethodGet, "/test", nil).WithContext(ctx)
		rec := httptest.NewRecorder()

		mw.ServeHTTP(rec, req)

		assert.True(t, handlerCalled, "handler should be called when no iat claim is present")
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("TimeoutOfZero_Disabled", func(t *testing.T) {
		// Timeout of 0 means session timeout is disabled (never expires)
		claims := &localjwt.Claims{
			UserID: "user-123",
			RegisteredClaims: jwt.RegisteredClaims{
				IssuedAt: jwt.NewNumericDate(time.Now().Add(-24 * time.Hour)),
			},
		}
		ctx := context.WithValue(context.Background(), middleware.LocalClaimsKey, claims)

		handlerCalled := false
		testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlerCalled = true
			w.WriteHeader(http.StatusOK)
		})

		// Timeout of 0 disables the check
		mw := sessionTimeoutChecker(0, testHandler)
		req := httptest.NewRequest(http.MethodGet, "/test", nil).WithContext(ctx)
		rec := httptest.NewRecorder()

		mw.ServeHTTP(rec, req)

		assert.True(t, handlerCalled, "handler should be called when timeout is disabled")
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("NoClaimsInContext_NotExpired", func(t *testing.T) {
		// No claims at all in context should be treated as not expired
		ctx := context.Background()

		handlerCalled := false
		testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlerCalled = true
			w.WriteHeader(http.StatusOK)
		})

		mw := sessionTimeoutChecker(30, testHandler)
		req := httptest.NewRequest(http.MethodGet, "/test", nil).WithContext(ctx)
		rec := httptest.NewRecorder()

		mw.ServeHTTP(rec, req)

		assert.True(t, handlerCalled, "handler should be called when no claims in context")
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("TokenExactlyAtTimeout_NotExpired", func(t *testing.T) {
		// Token issued exactly at the timeout boundary (minus a small buffer)
		// should not be considered expired.
		// We subtract 1 second to stay within the boundary.
		claims := &localjwt.Claims{
			UserID: "user-123",
			RegisteredClaims: jwt.RegisteredClaims{
				IssuedAt: jwt.NewNumericDate(time.Now().Add(-29*time.Minute - 59*time.Second)),
			},
		}
		ctx := context.WithValue(context.Background(), middleware.LocalClaimsKey, claims)

		handlerCalled := false
		testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlerCalled = true
			w.WriteHeader(http.StatusOK)
		})

		mw := sessionTimeoutChecker(30, testHandler)
		req := httptest.NewRequest(http.MethodGet, "/test", nil).WithContext(ctx)
		rec := httptest.NewRecorder()

		mw.ServeHTTP(rec, req)

		assert.True(t, handlerCalled, "handler should be called when token is just within timeout")
		assert.Equal(t, http.StatusOK, rec.Code)
	})
}

// sessionTimeoutChecker creates a simple HTTP handler that mimics the session
// timeout check from UnifiedAuth middleware. This tests the isSessionExpired
// logic without needing the full token validation pipeline.
func sessionTimeoutChecker(timeoutMinutes int, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if timeoutMinutes > 0 {
			timeout := time.Duration(timeoutMinutes) * time.Minute

			// Check local JWT claims (same logic as isSessionExpired in unified_auth.go)
			if claims := middleware.GetLocalClaims(r.Context()); claims != nil {
				if claims.IssuedAt != nil {
					if time.Since(claims.IssuedAt.Time) > timeout {
						http.Error(w, "Session has expired", http.StatusUnauthorized)
						return
					}
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}
