package mcpoauth_test

// Write-action confirmations (RFC-062 §10) over a migrated database.

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/mcpoauth"
	mcpoauthdom "github.com/openctemio/openctem/api/pkg/domain/mcpoauth"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func (h *harness) withConfirmations() *mcpoauth.Service {
	h.t.Helper()
	cfg := h.cfg
	cfg.Confirmations = cfg.Clients.(interface {
		mcpoauthdom.ClientRepository
		mcpoauthdom.ConfirmationRepository
	})
	svc, err := mcpoauth.NewService(cfg)
	if err != nil {
		h.t.Fatal(err)
	}
	return svc
}

func TestConfirmationFlow(t *testing.T) {
	h := newHarness(t)
	svc := h.withConfirmations()
	ctx := context.Background()
	alice := h.member(h.tenant, "owner")
	bob := h.member(h.tenant, "owner")
	tok, oerr := h.exchange(h.approve(alice, h.tenant, authorizeQuery(nil)), verifier, nil)
	if oerr != nil {
		t.Fatal(oerr)
	}
	p, err := h.principal(tok.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	args := map[string]any{"finding_id": "f1", "content": "triage note"}
	digest := mcpoauth.ArgsDigest("add_finding_comment", args)
	// The digest ignores confirmation_id, nothing else.
	if mcpoauth.ArgsDigest("add_finding_comment", map[string]any{"finding_id": "f1", "content": "triage note", "confirmation_id": "x"}) != digest ||
		mcpoauth.ArgsDigest("add_finding_comment", map[string]any{"finding_id": "f1", "content": "other"}) == digest {
		t.Fatal("digest does not bind the arguments")
	}

	pending, err := svc.RequestConfirmation(ctx, p, "add_finding_comment", digest, "Add a comment", mcpoauth.Actor{})
	if err != nil || !strings.HasPrefix(pending.URL, issuer+"/mcp/confirm/") {
		t.Fatalf("request: %+v %v", pending, err)
	}
	tenant := shared.MustIDFromString(h.tenant)
	id := shared.MustIDFromString(pending.ID)

	// Not usable before approval.
	if err := svc.UseConfirmation(ctx, p, pending.ID, "add_finding_comment", digest); !errors.Is(err, mcpoauthdom.ErrConfirmationRequired) {
		t.Fatalf("used before approval: %v", err)
	}
	// Bob can neither see nor approve Alice's action; another organization neither.
	if _, err := svc.GetConfirmation(ctx, tenant, bob, id); !errors.Is(err, mcpoauthdom.ErrNotFound) {
		t.Fatalf("other user sees the confirmation: %v", err)
	}
	if err := svc.DecideConfirmation(ctx, tenant, bob, id, true, mcpoauth.Actor{}); err == nil {
		t.Fatal("other user approved")
	}
	if err := svc.DecideConfirmation(ctx, shared.MustIDFromString(h.other), alice, id, true, mcpoauth.Actor{}); err == nil {
		t.Fatal("approved from another organization")
	}
	view, err := svc.GetConfirmation(ctx, tenant, alice, id)
	if err != nil || view.Summary != "Add a comment" || view.Status != mcpoauthdom.ConfirmationPending {
		t.Fatalf("view %+v %v", view, err)
	}
	if err := svc.DecideConfirmation(ctx, tenant, alice, id, true, mcpoauth.Actor{}); err != nil {
		t.Fatal(err)
	}
	// Other arguments, other tool, or another connection: refused.
	other := mcpoauth.ArgsDigest("add_finding_comment", map[string]any{"finding_id": "f1", "content": "changed"})
	if err := svc.UseConfirmation(ctx, p, pending.ID, "add_finding_comment", other); err == nil {
		t.Fatal("used for other arguments")
	}
	if err := svc.UseConfirmation(ctx, p, pending.ID, "other_tool", digest); err == nil {
		t.Fatal("used for another tool")
	}
	foreign := *p
	foreign.GrantID = shared.NewID().String()
	if err := svc.UseConfirmation(ctx, &foreign, pending.ID, "add_finding_comment", digest); err == nil {
		t.Fatal("used by another connection")
	}
	// Exactly once.
	if err := svc.UseConfirmation(ctx, p, pending.ID, "add_finding_comment", digest); err != nil {
		t.Fatalf("approved action refused: %v", err)
	}
	if err := svc.UseConfirmation(ctx, p, pending.ID, "add_finding_comment", digest); !errors.Is(err, mcpoauthdom.ErrConfirmationRequired) {
		t.Fatalf("used twice: %v", err)
	}
	// A refused action never runs; an expired one neither.
	p2, _ := svc.RequestConfirmation(ctx, p, "add_finding_comment", digest, "x", mcpoauth.Actor{})
	if err := svc.DecideConfirmation(ctx, tenant, alice, shared.MustIDFromString(p2.ID), false, mcpoauth.Actor{}); err != nil {
		t.Fatal(err)
	}
	if err := svc.UseConfirmation(ctx, p, p2.ID, "add_finding_comment", digest); err == nil {
		t.Fatal("refused action used")
	}
	p3, _ := svc.RequestConfirmation(ctx, p, "add_finding_comment", digest, "x", mcpoauth.Actor{})
	h.exec(`UPDATE mcp_action_confirmations SET expires_at = now() - interval '1 minute' WHERE id = $1`, p3.ID)
	if err := svc.DecideConfirmation(ctx, tenant, alice, shared.MustIDFromString(p3.ID), true, mcpoauth.Actor{}); err == nil {
		t.Fatal("expired action approved")
	}
	// No principal (an API key): nobody to confirm.
	if _, err := svc.RequestConfirmation(ctx, nil, "add_finding_comment", digest, "x", mcpoauth.Actor{}); err == nil {
		t.Fatal("confirmation without a person")
	}
}
