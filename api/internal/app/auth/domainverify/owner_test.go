package domainverify

import (
	"context"
	"testing"
)

func TestOwnerOfDomain_TheVerifiedHolder(t *testing.T) {
	f := newClaimFixture(t)
	if _, err := f.verify(t, f.holder, "acme.com"); err != nil {
		t.Fatal(err)
	}
	// Another organization's pending row does not change the holder.
	mustAdd(t, f.svc, f.other, "acme.com")

	owner, ok, err := f.svc.OwnerOfDomain(context.Background(), "ACME.com")
	if err != nil || !ok || owner != f.holder {
		t.Fatalf("owner = %v ok=%v err=%v, want the holder", owner, ok, err)
	}
	if ok, _ := OwnsAnySSODomain(context.Background(), f.repo, f.holder); !ok {
		t.Error("the holder owns an SSO domain")
	}
	if ok, _ := OwnsAnySSODomain(context.Background(), f.repo, f.other); ok {
		t.Error("a pending row is not an owned domain")
	}
}

func TestOwnerOfDomain_NobodyAndInvalid(t *testing.T) {
	f := newClaimFixture(t)
	for _, d := range []string{"nobody.example", "", "not a domain"} {
		if _, ok, err := f.svc.OwnerOfDomain(context.Background(), d); ok || err != nil {
			t.Errorf("%q: ok=%v err=%v, want no owner", d, ok, err)
		}
	}
	// A pending (unproven) row owns nothing.
	mustAdd(t, f.svc, f.other, "pending.example")
	if _, ok, _ := f.svc.OwnerOfDomain(context.Background(), "pending.example"); ok {
		t.Error("a pending row must not own the domain")
	}
}

// A claim flagged as conflicting (two verified holders left over from before
// claims were exclusive) manages nobody.
func TestOwnerOfDomain_ConflictIsAmbiguous(t *testing.T) {
	f := newClaimFixture(t)
	v, err := f.verify(t, f.holder, "acme.com")
	if err != nil {
		t.Fatal(err)
	}
	v.WithClaimState(nil, true)
	if _, ok, _ := f.svc.OwnerOfDomain(context.Background(), "acme.com"); ok {
		t.Fatal("a conflicting claim must not name an owner")
	}
}
