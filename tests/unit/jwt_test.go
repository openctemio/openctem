package unit

import (
	"testing"
	"time"

	"github.com/openctemio/api/pkg/jwt"
)

func TestGenerateToken_Success(t *testing.T) {
	token, err := jwt.GenerateToken("user123", "admin", "secret-key", time.Hour)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if token == "" {
		t.Fatal("expected non-empty token")
	}
}

func TestGenerateToken_EmptyUserID(t *testing.T) {
	_, err := jwt.GenerateToken("", "admin", "secret-key", time.Hour)
	if err == nil {
		t.Fatal("expected error for empty user_id")
	}
	if err != jwt.ErrEmptyUserID {
		t.Fatalf("expected ErrEmptyUserID, got %v", err)
	}
}

func TestValidateToken_Success(t *testing.T) {
	secret := "test-secret"
	userID := "user456"
	role := "user"

	token, err := jwt.GenerateToken(userID, role, secret, time.Hour)
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	claims, err := jwt.ValidateToken(token, secret)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if claims.UserID != userID {
		t.Errorf("expected user_id %s, got %s", userID, claims.UserID)
	}
	if claims.Role != role {
		t.Errorf("expected role %s, got %s", role, claims.Role)
	}
}

func TestValidateToken_Expired(t *testing.T) {
	secret := "test-secret"

	// Generate token with negative expiry (already expired)
	token, err := jwt.GenerateTokenWithExpiry("user123", "admin", secret, time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	_, err = jwt.ValidateToken(token, secret)
	if err == nil {
		t.Fatal("expected error for expired token")
	}
	if err != jwt.ErrExpiredToken {
		t.Fatalf("expected ErrExpiredToken, got %v", err)
	}
}

func TestValidateToken_InvalidSignature(t *testing.T) {
	token, err := jwt.GenerateToken("user123", "admin", "secret-1", time.Hour)
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	// Validate with different secret
	_, err = jwt.ValidateToken(token, "secret-2")
	if err == nil {
		t.Fatal("expected error for invalid signature")
	}
	if err != jwt.ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken, got %v", err)
	}
}

func TestValidateToken_MalformedToken(t *testing.T) {
	_, err := jwt.ValidateToken("not.a.valid.token", "secret")
	if err == nil {
		t.Fatal("expected error for malformed token")
	}
	if err != jwt.ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken, got %v", err)
	}
}

func TestValidateToken_EmptyToken(t *testing.T) {
	_, err := jwt.ValidateToken("", "secret")
	if err == nil {
		t.Fatal("expected error for empty token")
	}
}
