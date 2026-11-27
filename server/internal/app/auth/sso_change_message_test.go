package auth

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	notificationdom "github.com/openctemio/openctem/server/pkg/domain/notification"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/ssochange"
	"github.com/openctemio/openctem/server/pkg/logger"
)

type msgSSOOwners struct {
	SSOChangeOwners
	list []ssochange.OwnerContact
}

func (m msgSSOOwners) ListActiveOwners(context.Context, shared.ID) ([]ssochange.OwnerContact, error) {
	return m.list, nil
}

func TestSSOChangeNotice_MessageCode(t *testing.T) {
	inApp := &capturedInApp{}
	svc := &SSOChangeService{
		owners: msgSSOOwners{list: []ssochange.OwnerContact{{UserID: shared.NewID()}}},
		inApp:  inApp, logger: logger.NewNop(),
	}
	raw, _ := json.Marshal(DomainJITPayload{Domain: "example.com", JITEnabled: true, JITRole: "member"})
	exp := time.Date(2026, 12, 1, 9, 30, 0, 0, time.UTC)
	svc.notifyOwners(context.Background(), &ssochange.Change{
		ID: shared.NewID(), TenantID: shared.NewID(), Kind: ssochange.KindDomainJIT, Payload: raw, ExpiresAt: exp,
	})
	if len(inApp.got) != 1 || inApp.got[0].Message == nil {
		t.Fatalf("notices = %+v", inApp.got)
	}
	m := inApp.got[0].Message
	if m.Code != "sso.change_pending" || m.Params["expires_at"] != "2026-12-01T09:30:00Z" {
		t.Fatalf("message = %+v", m)
	}
	if r, ok := m.Params["requester"].(*notificationdom.Message); !ok || r.Code != "sso.platform_admin" {
		t.Errorf("requester = %v", m.Params["requester"])
	}
	sum, ok := m.Params["summary"].(*notificationdom.Message)
	if !ok || sum.Code != "sso.change.domain_jit_on" || sum.Params["domain"] != "example.com" || sum.Params["role"] != "member" {
		t.Errorf("summary = %+v", m.Params["summary"])
	}
	if err := m.Validate(); err != nil {
		t.Error(err)
	}
}

func TestDescribeSSOChangeMessage(t *testing.T) {
	mk := func(kind ssochange.Kind, payload any) *ssochange.Change {
		raw, _ := json.Marshal(payload)
		return &ssochange.Change{Kind: kind, Payload: raw}
	}
	name := "Corp"
	upd := describeSSOChangeMessage(mk(ssochange.KindIdPUpdate, IdPUpdatePayload{DisplayName: &name, TargetProvider: "entra_id", TargetName: "Corp"}))
	if upd.Code != "sso.change.idp_update" {
		t.Fatalf("update = %+v", upd)
	}
	if tg, ok := upd.Params["target"].(*notificationdom.Message); !ok || tg.Code != "sso.change.target" || tg.Params["name"] != "Corp" {
		t.Errorf("target = %+v", upd.Params["target"])
	}
	lines, ok := upd.Params["lines"].([]notificationdom.Message)
	if !ok || len(lines) != 1 || lines[0].Code != "sso.field.display_name" {
		t.Errorf("lines = %+v", upd.Params["lines"])
	}
	create := describeSSOChangeMessage(mk(ssochange.KindIdPCreate, IdPCreatePayload{Provider: "made_up", DisplayName: "X", ClientID: "c", AutoProvision: true}))
	if create.Code != "sso.change.idp_create" || create.Params["name"] != "X" || create.Params["client_id"] != "c" {
		t.Errorf("create = %+v", create)
	}
	if p, ok := create.Params["provider"].(*notificationdom.Message); !ok || p.Code != "sso.idp_noun_generic" {
		t.Errorf("provider = %+v", create.Params["provider"])
	}
	if a, ok := create.Params["auto_provision"].(*notificationdom.Message); !ok || a.Code != "sso.on" {
		t.Errorf("auto_provision = %+v", create.Params["auto_provision"])
	}
	saml := describeSSOChangeMessage(mk(ssochange.KindSAMLConfig, SAMLChangePayload{IDPEntityID: "e", IDPSSOURL: "https://idp.example.com/sso"}))
	if saml.Code != "sso.change.saml_config" || saml.Params["entity"] != "e" {
		t.Errorf("saml = %+v", saml)
	}
	if f, ok := saml.Params["fingerprint"].(*notificationdom.Message); !ok || f.Code != "sso.fingerprint_none" {
		t.Errorf("fingerprint = %+v", saml.Params["fingerprint"])
	}
	off := describeSSOChangeMessage(mk(ssochange.KindDomainJIT, DomainJITPayload{Domain: "example.com"}))
	if off.Code != "sso.change.domain_jit_off" {
		t.Errorf("off = %+v", off)
	}
}
