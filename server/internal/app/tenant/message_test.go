package tenant

import (
	"context"
	"testing"

	notificationdom "github.com/openctemio/openctem/server/pkg/domain/notification"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/server/pkg/domain/tenant"
	"github.com/openctemio/openctem/server/pkg/logger"
)

type msgTenantRepo struct {
	tenantdom.Repository
	t *tenantdom.Tenant
}

func (r msgTenantRepo) GetByID(context.Context, shared.ID) (*tenantdom.Tenant, error) {
	return r.t, nil
}

func TestSSODomainVerificationLost_MessageCode(t *testing.T) {
	for _, tc := range []struct {
		enforced bool
		code     string
	}{{false, "sso.domain_verification_lost"}, {true, "sso.domain_verification_lost_enforced"}} {
		ten, err := tenantdom.NewTenant("Acme", "acme-msg", shared.NewID().String())
		if err != nil {
			t.Fatal(err)
		}
		st := ten.TypedSettings()
		st.Security.SSOEnforced = tc.enforced
		if err := ten.UpdateSettings(st); err != nil {
			t.Fatal(err)
		}
		rec := &recordingNotifier{}
		svc := &TenantService{
			repo:              msgTenantRepo{t: ten},
			lifecycle:         fixedAdmins{ids: []shared.ID{shared.NewID()}},
			lifecycleNotifier: rec,
			logger:            logger.NewNop(),
		}
		svc.SSODomainVerificationLost(context.Background(), ten.ID(), "acme.example.com")
		if len(rec.got) != 1 {
			t.Fatalf("enforced=%v: %d notices", tc.enforced, len(rec.got))
		}
		m := rec.got[0].params.Message
		if m == nil || m.Code != tc.code || m.Params["domain"] != "acme.example.com" {
			t.Errorf("enforced=%v: message = %+v", tc.enforced, m)
		}
	}
}

func TestNotifyAdminsMsgAndNotifyUser_CarryMessage(t *testing.T) {
	rec := &recordingNotifier{}
	svc := &TenantService{
		lifecycle:         fixedAdmins{ids: []shared.ID{shared.NewID()}},
		lifecycleNotifier: rec,
		logger:            logger.NewNop(),
	}
	ctx := context.Background()
	svc.notifyAdminsMsg(ctx, shared.NewID(), notificationdom.Msg("member.left", "member", "a@example.com"), "t", "b", "info")
	svc.notifyUser(ctx, shared.NewID(), shared.NewID(), notificationdom.Msg("ownership.requested", "from", "Ann"), "t", "b")
	svc.notifyAdmins(ctx, shared.NewID(), "t", "b", "info")
	if len(rec.got) != 3 {
		t.Fatalf("%d notices", len(rec.got))
	}
	if m := rec.got[0].params.Message; m == nil || m.Code != "member.left" || m.Params["member"] != "a@example.com" {
		t.Errorf("admins message = %+v", m)
	}
	if m := rec.got[1].params.Message; m == nil || m.Code != "ownership.requested" || m.Params["from"] != "Ann" {
		t.Errorf("user message = %+v", m)
	}
	if rec.got[2].params.Message != nil {
		t.Errorf("an unconverted notice must keep no message")
	}
}

func TestOwnershipMessageParams(t *testing.T) {
	if got := nameOrNested("Ann", "ownership.someone.owner"); got != "Ann" {
		t.Errorf("name kept: %v", got)
	}
	if m, ok := nameOrNested("", "ownership.someone.owner").(*notificationdom.Message); !ok || m.Code != "ownership.someone.owner" {
		t.Errorf("empty name must become a nested message")
	}
	if m, ok := orgParam(orgNameFallback).(*notificationdom.Message); !ok || m.Code != "ownership.someone.org" {
		t.Errorf("fallback org must become a nested message")
	}
	if orgParam("Acme") != "Acme" {
		t.Errorf("real org name kept")
	}
}
