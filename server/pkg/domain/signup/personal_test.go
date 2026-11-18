package signup

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/server/pkg/domain/verifieddomain"
)

// The personal organization at sign-up: made only for a verified person with
// no other way in, only while the switch is on under self-service.
func TestAdmitPersonalOrganization(t *testing.T) {
	on := Policy{Mode: ModeSelfService, Accounts: AccountsOpen, PersonalOrganization: true}
	off := Policy{Mode: ModeSelfService, Accounts: AccountsOpen}
	adminOnly := Policy{Mode: ModeAdminOnly, Accounts: AccountsOpen, PersonalOrganization: true}
	ok := Identity{Intent: IntentPersonalOrganization, EmailVerified: true}
	with := func(f func(*Identity)) Identity { id := ok; f(&id); return id }
	cases := []struct {
		name   string
		policy Policy
		id     Identity
		want   Outcome
	}{
		{"switch on, verified, no other way in", on, ok, OutcomePersonalOrganization},
		{"switch off", off, ok, OutcomeNotSetUp},
		{"switch on but organizations admin_only", adminOnly, ok, OutcomeNotSetUp},
		{"switch on but accounts closed", Policy{Mode: ModeSelfService, Accounts: AccountsClosed, PersonalOrganization: true}, ok, OutcomeNotSetUp},
		{"zero policy", Policy{}, ok, OutcomeNotSetUp},
		{"email not verified", on, with(func(i *Identity) { i.EmailVerified = false }), OutcomeNotSetUp},
		{"pending invitation", on, with(func(i *Identity) { i.InvitedPending = true }), OutcomeNotSetUp},
		{"organization SSO admits just in time", on, with(func(i *Identity) { i.JITEligible = true }), OutcomeNotSetUp},
		{"domain requires SSO", on, with(func(i *Identity) { i.SSORequired = true }), OutcomeNotSetUp},
		{"domain auto-joins or takes requests", on, with(func(i *Identity) { i.DomainJoinable = true }), OutcomeNotSetUp},
		{"domain claimed, closed to joining", on, with(func(i *Identity) { i.DomainClaimed = true }), OutcomeNotSetUp},
		{"domain blocks new organizations", on, with(func(i *Identity) { i.WorkspacesBlocked = true }), OutcomeNotSetUp},
		{"disposable address", on, with(func(i *Identity) { i.DisposableEmail = true }), OutcomeNotSetUp},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Admit(c.policy, c.id); got != c.want {
				t.Fatalf("Admit = %s, want %s", got, c.want)
			}
		})
	}
	// The other intents ignore the switch.
	if Admit(on, Identity{Intent: IntentAccount}) != OutcomeSelfService || Admit(on, Identity{Intent: IntentOrganization}) != OutcomeSelfService {
		t.Fatal("the switch must not change account or organization admission")
	}
}

func TestPersonalOrganizationPolicy(t *testing.T) {
	if err := (Policy{Mode: ModeAdminOnly, Accounts: AccountsOpen, PersonalOrganization: true}).Validate(); !errors.Is(err, ErrPersonalOrgNeedsSelfService) {
		t.Fatalf("admin_only with the switch: %v", err)
	}
	if err := (Policy{Mode: ModeSelfService, Accounts: AccountsOpen, PersonalOrganization: true}).Validate(); err != nil {
		t.Fatalf("self_service with the switch: %v", err)
	}
	// Stored without the field: off.
	p, err := Decode([]byte(`{"mode":"self_service","accounts":"open"}`))
	if err != nil || p.PersonalOrganization {
		t.Fatalf("old stored policy: %+v %v", p, err)
	}
	p, err = Decode([]byte(`{"mode":"self_service","accounts":"open","personal_organization":true}`))
	if err != nil || !p.CreatesPersonalOrganization() {
		t.Fatalf("stored with the switch: %+v %v", p, err)
	}
	// A ceiling below open turns it off with self-service.
	on := Policy{Mode: ModeSelfService, Accounts: AccountsOpen, PersonalOrganization: true}
	for _, c := range []Ceiling{CeilingDisabled, CeilingDomain} {
		if c.Clamp(on).PersonalOrganization {
			t.Fatalf("%s ceiling kept the switch on", c)
		}
	}
	if !CeilingOpen.Clamp(on).CreatesPersonalOrganization() {
		t.Fatal("open ceiling turned the switch off")
	}
}

type fakeDomains struct {
	ep verifieddomain.EmailPolicy
	ok bool
}

func (f fakeDomains) SignupPolicyForEmail(context.Context, string) (verifieddomain.EmailPolicy, bool, error) {
	return f.ep, f.ok, nil
}

func TestFactsForEmailMarksAClaimedDomain(t *testing.T) {
	f, err := FactsForEmail(context.Background(), fakeDomains{ok: true}, "a@example.com")
	if err != nil || !f.Claimed {
		t.Fatalf("claimed domain: %+v %v", f, err)
	}
	if !f.Apply(Identity{}).DomainClaimed {
		t.Fatal("Apply dropped the claim")
	}
	f, _ = FactsForEmail(context.Background(), fakeDomains{}, "a@example.com")
	if f.Claimed {
		t.Fatal("unclaimed domain reported as claimed")
	}
}
