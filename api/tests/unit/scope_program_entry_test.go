package unit

// Program entries on the general scope routes (RFC-065 §4): they cannot be
// created there, and widening one is refused even for an approver (the
// program's attestation governs it); narrowing still works. Ownership and
// self-attestation entries keep the approval policy.

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/scope"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

func TestScopeEntry_ProgramSourceRefusedOnGeneralRoutes(t *testing.T) {
	svc, _, _ := entryService(t, 1, tenant.ScopeSettings{})
	tid := shared.NewID()
	_, err := create(svc, tid, approverA, "prog.example", func(in *scope.CreateTargetInput) { in.AuthorizationSource = "program" })
	if !errors.Is(err, scopedom.ErrProgramEntryViaPrograms) {
		t.Fatalf("a program entry must not be created on the Scope routes: %v", err)
	}
	if _, err := create(svc, tid, approverA, "letter.example", func(in *scope.CreateTargetInput) { in.AuthorizationSource = "authorization_letter" }); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("letters are not open yet: %v", err)
	}
	got, err := create(svc, tid, approverA, "internal.example", func(in *scope.CreateTargetInput) { in.AuthorizationSource = "self_attestation" })
	if err != nil || got.AuthorizationSource() != scopedom.AuthSelfAttestation || !got.IsActive() {
		t.Fatalf("self-attestation: %v", err)
	}
	// A two-admin tenant: self-attestation still needs the other admin.
	svc2, _, _ := entryService(t, 2, tenant.ScopeSettings{})
	pending, err := create(svc2, tid, approverA, "internal2.example", func(in *scope.CreateTargetInput) { in.AuthorizationSource = "self_attestation" })
	if err != nil || !pending.IsPending() {
		t.Fatalf("self-attestation follows the approval policy: %v", err)
	}
}

func TestScopeEntry_ProgramEntryWideningRefused(t *testing.T) {
	svc, tr, _ := entryService(t, 1, tenant.ScopeSettings{})
	tid := shared.NewID()
	pid := shared.NewID()
	e, err := scopedom.NewEntry(tid, scopedom.TargetTypeDomain, "*.prog.example", "", "researcher", scopedom.EntryOptions{MaxTier: scopedom.TierActive})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.SetAuthorization(scopedom.AuthProgram, &pid); err != nil {
		t.Fatal(err)
	}
	if err := tr.Create(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	t2 := "t2"
	if _, err := svc.UpdateTarget(ctx, e.ID().String(), tid.String(), scope.UpdateTargetInput{MaxTier: &t2, Actor: approverA}); !errors.Is(err, scopedom.ErrProgramManaged) {
		t.Fatalf("raising a program entry's tier must be refused: %v", err)
	}
	if _, err := svc.UpdateTarget(ctx, e.ID().String(), tid.String(), scope.UpdateTargetInput{ClearExpiry: true, Actor: approverA}); !errors.Is(err, scopedom.ErrProgramManaged) {
		t.Fatalf("changing a program entry's expiry must be refused: %v", err)
	}
	// Narrowing works.
	if _, err := svc.DeactivateTarget(ctx, e.ID().String(), tid.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ActivateTarget(ctx, e.ID().String(), tid.String(), approverA); !errors.Is(err, scopedom.ErrProgramManaged) {
		t.Fatalf("activating a program entry is resuming its program: %v", err)
	}
	// A description change is not widening.
	d := "note"
	if _, err := svc.UpdateTarget(ctx, e.ID().String(), tid.String(), scope.UpdateTargetInput{Description: &d, Actor: approverA}); err != nil {
		t.Fatalf("description: %v", err)
	}
}
