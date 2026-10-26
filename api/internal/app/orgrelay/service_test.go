package orgrelay

import (
	"context"
	"errors"
	"testing"

	cst "github.com/openctemio/openctem/api/internal/app/consolesetting/consolesettingtest"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	emailpkg "github.com/openctemio/openctem/api/pkg/email"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func newSvc(managed bool, env string) (*Service, *cst.Audit) {
	audit := &cst.Audit{}
	return NewService(cst.NewRepo(), cst.Recorder(audit, &cst.Notifier{}), managed, env, logger.NewNop()), audit
}

// Defaults: on for a self-managed install, verified sender for a managed
// service, the environment value when valid; a stored value wins at once.
func TestModeDefaultsAndChange(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		managed bool
		env     string
		want    emailpkg.RelayMode
	}{
		{false, "", emailpkg.RelayModeOn},
		{true, "", emailpkg.RelayModeVerifiedSender},
		{true, "off", emailpkg.RelayModeOff},
		{false, " Verified_Sender ", emailpkg.RelayModeVerifiedSender},
		{true, "bogus", emailpkg.RelayModeVerifiedSender},
	} {
		svc, _ := newSvc(tc.managed, tc.env)
		if got := svc.RelayMode(ctx); got != tc.want {
			t.Errorf("managed %v env %q: mode %q, want %q", tc.managed, tc.env, got, tc.want)
		}
	}

	svc, audit := newSvc(true, "")
	if _, err := svc.Update(ctx, cst.SuperAdmin(t), "off", "free tier abuse", 0, "", ""); err != nil {
		t.Fatal(err)
	}
	if svc.RelayMode(ctx) != emailpkg.RelayModeOff {
		t.Fatal("the stored mode must apply at once")
	}
	if len(audit.Entries) != 1 || audit.Entries[0].Action != ActionChanged {
		t.Fatalf("audit entries = %d", len(audit.Entries))
	}
	if _, err := svc.Update(ctx, cst.SuperAdmin(t), "on", "x", 0, "", ""); err == nil {
		t.Fatal("a stale version must be refused")
	}
}

func TestUpdateRefusals(t *testing.T) {
	ctx := context.Background()
	svc, _ := newSvc(false, "")
	if _, err := svc.Update(ctx, nil, "on", "r", 0, "", ""); !errors.Is(err, ErrNoActor) {
		t.Fatalf("no actor: %v", err)
	}
	if _, err := svc.Update(ctx, cst.SuperAdmin(t), "sometimes", "r", 0, "", ""); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("bad mode: %v", err)
	}
	if _, err := svc.Update(ctx, cst.SuperAdmin(t), "off", "  ", 0, "", ""); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("no reason: %v", err)
	}
}
