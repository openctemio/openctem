package controller

import (
	"context"
	"testing"

	auditdom "github.com/openctemio/api/pkg/domain/audit"
	"github.com/openctemio/api/pkg/domain/shared"
)

// The audit hash chain is keyed by tenant, and authentication events have no
// tenant — at login a user may belong to several tenants and has not chosen
// one. They were therefore skipped entirely. On the live database that left
// 925 of 1075 audit rows (86%) with no tamper evidence, including every
// auth.login, auth.register and auth.failed.
//
// They now extend a dedicated system chain. But writing hashes nobody checks is
// not tamper evidence, and ListActiveTenantIDs can never return the system
// chain because it is not a tenant. So the controller has to add it, and that
// is what these tests hold in place.

func TestAuditChainVerify_WalksTheSystemChain(t *testing.T) {
	ids := mkTenantIDs(2)
	verifier := &chainVerifierMock{}

	c := newTestController(t, verifier, &tenantListerMock{ids: ids})
	if _, err := c.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	var sawSystem bool
	for _, got := range verifier.calls {
		if got == auditdom.SystemChainTenantID.String() {
			sawSystem = true
			break
		}
	}
	if !sawSystem {
		t.Fatalf("the system chain was never verified. Every authentication event "+
			"lives on it, so its hashes are stored but unchecked — which is not "+
			"tamper evidence. Chains walked: %v", verifier.calls)
	}
}

// A partial run — the context deadline expires part-way — must not be able to
// skip the chain carrying the authentication records. Walking it first is the
// property; asserting "it is in the list somewhere" would not catch a change
// that appends it at the end.
func TestAuditChainVerify_SystemChainIsWalkedFirst(t *testing.T) {
	verifier := &chainVerifierMock{}

	c := newTestController(t, verifier, &tenantListerMock{ids: mkTenantIDs(3)})
	if _, err := c.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	if len(verifier.calls) == 0 {
		t.Fatal("no chains were verified at all")
	}
	if verifier.calls[0] != auditdom.SystemChainTenantID.String() {
		t.Fatalf("first chain walked = %v, want the system chain. A run cut short "+
			"by its context would skip whatever is last, and the authentication "+
			"trail is the part an intruder has the most reason to edit",
			verifier.calls[0])
	}
}

// The sentinel must never collide with a generated ID. Its version nibble is
// 'f'; uuid.NewV7 and uuid.New can only ever emit 7 or 4 there. This asserts
// the property rather than the constant, so it keeps holding if the value is
// ever changed.
func TestSystemChainTenantID_CannotCollideWithAGeneratedID(t *testing.T) {
	sentinel := auditdom.SystemChainTenantID.String()

	if sentinel == (shared.ID{}).String() {
		t.Fatal("the sentinel is the zero value of shared.ID, which call sites " +
			"already use IsZero() to mean \"unset\"")
	}

	// UUID version nibble: character 15 of 8-4-4-4-12.
	if v := sentinel[14]; v == '4' || v == '7' {
		t.Fatalf("sentinel version nibble is %q — a generated UUID could collide "+
			"with it, and then a real tenant's chain would merge with the system "+
			"chain", v)
	}

	for i := 0; i < 2000; i++ {
		if shared.NewID().String() == sentinel {
			t.Fatal("NewID produced the sentinel")
		}
	}
}
