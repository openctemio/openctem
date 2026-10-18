package adminconsole

import (
	"context"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/admin"
)

type fakeRosterNotifier struct {
	changes []RosterChange
}

func (n *fakeRosterNotifier) NotifyRosterChange(_ context.Context, c RosterChange) error {
	n.changes = append(n.changes, c)
	return nil
}

// Adding an administrator is announced to every other active administrator,
// never to the actor: one session alone must not create a super admin
// unnoticed.
func TestProvisionNotifiesOtherAdministrators(t *testing.T) {
	b := newBGHarness(t)
	other, _ := b.addAdmin(t, "second@acme.io", admin.AdminRoleSuperAdmin, false)
	n := &fakeRosterNotifier{}
	b.svc.SetRosterChangeNotifier(n)

	if _, _, err := b.svc.Provision(context.Background(), b.admin, ProvisionInput{
		Email: "new@acme.io", Name: "New", Role: admin.AdminRoleSuperAdmin,
	}, client); err != nil {
		t.Fatalf("provision: %v", err)
	}
	if len(n.changes) != 1 {
		t.Fatalf("want one notice, got %d", len(n.changes))
	}
	c := n.changes[0]
	if c.Kind != RosterAdminAdded || !strings.Contains(c.Summary, "new@acme.io") || !strings.Contains(c.Summary, "Super admin") {
		t.Fatalf("notice must name the new administrator and role: %+v", c)
	}
	if c.ActorEmail != b.admin.Email() || c.IP != client.IP {
		t.Fatalf("notice must name the actor and IP: %+v", c)
	}
	for _, r := range c.Recipients {
		if r == b.admin.Email() {
			t.Fatal("the actor is not a recipient")
		}
	}
	found := false
	for _, r := range c.Recipients {
		if r == other.Email() {
			found = true
		}
	}
	if !found {
		t.Fatalf("every other active administrator is a recipient: %v", c.Recipients)
	}
}

// Resetting another administrator's sign-in is announced as well.
func TestResetCredentialsNotifies(t *testing.T) {
	b := newBGHarness(t)
	other, _ := b.addAdmin(t, "second@acme.io", admin.AdminRoleOpsAdmin, false)
	n := &fakeRosterNotifier{}
	b.svc.SetRosterChangeNotifier(n)

	if err := b.svc.ResetCredentials(context.Background(), b.admin, other.ID(), client); err != nil {
		t.Fatalf("reset: %v", err)
	}
	if len(n.changes) != 1 || n.changes[0].Kind != RosterCredentialsReset || !strings.Contains(n.changes[0].Summary, other.Email()) {
		t.Fatalf("want one credentials-reset notice naming the target, got %+v", n.changes)
	}
}

// Without a notifier the change still succeeds (the WARN line is the alert).
func TestRosterNoticeWithoutNotifier(t *testing.T) {
	b := newBGHarness(t)
	if _, _, err := b.svc.Provision(context.Background(), b.admin, ProvisionInput{
		Email: "new@acme.io", Name: "New", Role: admin.AdminRoleReadonly,
	}, client); err != nil {
		t.Fatalf("provision without notifier: %v", err)
	}
}
