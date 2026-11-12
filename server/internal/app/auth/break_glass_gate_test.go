package auth

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	userdom "github.com/openctemio/openctem/api/pkg/domain/user"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type bgIDs map[string]bool

func (g bgIDs) IsBreakGlass(_ context.Context, id shared.ID) bool { return g[id.String()] }

// refuseBreakGlass refuses only a break-glass account; a regular platform
// administrator's account (not flagged) and a missing gate pass.
func TestRefuseBreakGlass(t *testing.T) {
	glass, _ := userdom.NewLocalUser("glass@example.com", "G", "h")
	admin, _ := userdom.NewLocalUser("admin@example.com", "A", "h")
	gate := bgIDs{glass.ID().String(): true}
	log := logger.NewNop()
	for _, tc := range []struct {
		name string
		g    BreakGlassGate
		u    *userdom.User
		want bool
	}{
		{"break-glass refused", gate, glass, true},
		{"regular admin allowed", gate, admin, false},
		{"no gate wired", nil, glass, false},
		{"nil user", gate, nil, false},
	} {
		if got := refuseBreakGlass(context.Background(), tc.g, log, tc.u, "test"); got != tc.want {
			t.Errorf("%s: got %v want %v", tc.name, got, tc.want)
		}
	}
}

// The SSO session path answers the generic exchange failure for break-glass,
// before any session state is touched.
func TestSSOCreateSession_BreakGlassRefused(t *testing.T) {
	glass, _ := userdom.NewLocalUser("glass@example.com", "G", "h")
	s := &SSOService{logger: logger.NewNop()}
	s.SetBreakGlassGate(bgIDs{glass.ID().String(): true})
	if _, err := s.createSession(context.Background(), glass, "", shared.ID{}, federatedBinding{}); !errors.Is(err, ErrSSOExchangeFailed) {
		t.Fatalf("got %v, want ErrSSOExchangeFailed", err)
	}
}
