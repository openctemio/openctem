package mcpoauth_test

// Connected applications (RFC-062 §12) over a migrated database: who sees
// and ends which connection, and the platform view.

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/mcpoauth"
	mcpoauthdom "github.com/openctemio/openctem/api/pkg/domain/mcpoauth"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestConnectionsMineAllAndRevoke(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	tenant := shared.MustIDFromString(h.tenant)
	alice := h.member(h.tenant, "member", "findings:read")
	bob := h.member(h.tenant, "member", "findings:read")
	admin := h.member(h.tenant, "admin")

	aliceTok, oerr := h.exchange(h.approve(alice, h.tenant, authorizeQuery(nil)), verifier, nil)
	if oerr != nil {
		t.Fatal(oerr)
	}
	if _, oerr := h.exchange(h.approve(bob, h.tenant, authorizeQuery(nil)), verifier, nil); oerr != nil {
		t.Fatal(oerr)
	}

	mine, err := h.svc.ListConnections(ctx, tenant, &alice)
	if err != nil || len(mine) != 1 || mine[0].UserID != alice.String() || mine[0].ClientHost != "assistant.example" {
		t.Fatalf("alice's connections %+v %v", mine, err)
	}
	all, err := h.svc.ListConnections(ctx, tenant, nil)
	if err != nil || len(all) != 2 || all[0].UserEmail == "" {
		t.Fatalf("organization connections %+v %v", all, err)
	}
	// Another organization sees none of them.
	if other, _ := h.svc.ListConnections(ctx, shared.MustIDFromString(h.other), nil); len(other) != 0 {
		t.Fatalf("other organization lists %d connections", len(other))
	}

	aliceGrant := shared.MustIDFromString(mine[0].ID)
	// Bob cannot end Alice's connection; nor can anyone from another organization.
	if err := h.svc.RevokeConnection(ctx, tenant, aliceGrant, bob, false, mcpoauth.Actor{}); !errors.Is(err, mcpoauthdom.ErrNotFound) {
		t.Fatalf("bob revoked alice's connection: %v", err)
	}
	if err := h.svc.RevokeConnection(ctx, shared.MustIDFromString(h.other), aliceGrant, admin, true, mcpoauth.Actor{}); !errors.Is(err, mcpoauthdom.ErrNotFound) {
		t.Fatalf("cross-tenant revoke: %v", err)
	}
	if _, err := h.principal(aliceTok.AccessToken); err != nil {
		t.Fatalf("alice's token broken by refused revocations: %v", err)
	}
	// Alice ends her own.
	if err := h.svc.RevokeConnection(ctx, tenant, aliceGrant, alice, false, mcpoauth.Actor{}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.principal(aliceTok.AccessToken); err == nil {
		t.Fatal("token survived its owner's revocation")
	}
	// The administrator ends Bob's.
	all, _ = h.svc.ListConnections(ctx, tenant, nil)
	if len(all) != 1 {
		t.Fatalf("after revoke: %d connections", len(all))
	}
	if err := h.svc.RevokeConnection(ctx, tenant, shared.MustIDFromString(all[0].ID), admin, true, mcpoauth.Actor{}); err != nil {
		t.Fatal(err)
	}
	if left, _ := h.svc.ListConnections(ctx, tenant, nil); len(left) != 0 {
		t.Fatalf("%d connections left", len(left))
	}
}

func TestPlatformClientListAndBlock(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	user := h.member(h.tenant, "owner")
	tok, oerr := h.exchange(h.approve(user, h.tenant, authorizeQuery(nil)), verifier, nil)
	if oerr != nil {
		t.Fatal(oerr)
	}
	list, err := h.svc.ListAllClients(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var ref shared.ID
	for _, u := range list {
		if u.Client.ClientID == clientID {
			ref = u.Client.ID
			if u.ActiveConnections < 1 || u.Organizations < 1 {
				t.Fatalf("usage %+v", u)
			}
		}
	}
	if ref.IsZero() {
		t.Fatal("client not listed")
	}
	if err := h.svc.SetClientBlocked(ctx, ref, true); err != nil {
		t.Fatal(err)
	}
	if _, err := h.principal(tok.AccessToken); err == nil {
		t.Fatal("blocked client's token works")
	}
	if err := h.svc.SetClientBlocked(ctx, shared.NewID(), true); !errors.Is(err, mcpoauthdom.ErrNotFound) {
		t.Fatalf("unknown client: %v", err)
	}
}
