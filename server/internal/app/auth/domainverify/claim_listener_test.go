package domainverify

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type recListener struct{ lost, restored []string }

func (r *recListener) HomeDomainLost(_ context.Context, _ shared.ID, d string) {
	r.lost = append(r.lost, d)
}
func (r *recListener) HomeDomainRestored(_ context.Context, _ shared.ID, d string) {
	r.restored = append(r.restored, d)
}

// The home cascade hears when an organization stops or starts holding an SSO
// domain: on verification, on a lapsed DNS record, and on removal.
func TestClaimListener_Transitions(t *testing.T) {
	f := newClaimFixture(t)
	l := &recListener{}
	f.svc.SetClaimListener(l)

	vd, err := f.verify(t, f.holder, "acme.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(l.restored) != 1 {
		t.Fatalf("verification must announce the claim, got %+v", l)
	}
	// The TXT record disappears; the re-verify sweep downgrades the claim.
	f.res.records = map[string][]string{}
	if _, err := f.svc.ReverifyDue(context.Background(), -time.Hour, 10); err != nil {
		t.Fatal(err)
	}
	if len(l.lost) != 1 || l.lost[0] != "acme.com" {
		t.Fatalf("a lapsed claim must be announced, got %+v", l)
	}
	// Removing a non-held row announces nothing more.
	if err := f.svc.Delete(context.Background(), f.holder, vd.ID()); err != nil {
		t.Fatal(err)
	}
	if len(l.lost) != 1 {
		t.Fatalf("a row that no longer held the claim must not be announced again, got %+v", l)
	}
}

func TestClaimListener_DeletingAHeldDomain(t *testing.T) {
	f := newClaimFixture(t)
	l := &recListener{}
	f.svc.SetClaimListener(l)
	vd, err := f.verify(t, f.holder, "acme.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Delete(context.Background(), f.holder, vd.ID()); err != nil {
		t.Fatal(err)
	}
	if len(l.lost) != 1 {
		t.Fatalf("removing a held SSO domain must be announced, got %+v", l)
	}
}
