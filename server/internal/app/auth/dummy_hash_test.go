package auth

import (
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/password"
)

// The constant-time paths verify against a hash generated at runtime with the
// service's own hasher (no hash literal in the source): it must be a real
// bcrypt hash at the hasher's cost, made once, and never match a password.
func TestDummyPasswordHash(t *testing.T) {
	s := &AuthService{passwordHasher: password.New(password.WithCost(bcrypt.MinCost + 1)), logger: logger.NewNop()}
	h := s.dummyPasswordHash()
	cost, err := bcrypt.Cost([]byte(h))
	if err != nil {
		t.Fatalf("not a bcrypt hash: %q (%v)", h, err)
	}
	if cost != bcrypt.MinCost+1 {
		t.Errorf("cost %d, want the hasher's %d", cost, bcrypt.MinCost+1)
	}
	if again := s.dummyPasswordHash(); again != h {
		t.Error("the dummy hash is regenerated on each call")
	}
	if s.passwordHasher.Verify("password123!", h) == nil {
		t.Error("a login password matched the dummy hash")
	}
}
