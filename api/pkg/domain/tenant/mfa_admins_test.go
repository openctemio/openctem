package tenant

import (
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestMFARequiredFor(t *testing.T) {
	admins := SecuritySettings{MFARequiredForAdmins: true}
	everyone := SecuritySettings{MFARequired: true}
	none := SecuritySettings{}
	for role, want := range map[string]bool{"owner": true, "admin": true, "member": false, "viewer": false, "": false} {
		if got := admins.MFARequiredFor(role); got != want {
			t.Errorf("admins rule, %q: got %v, want %v", role, got, want)
		}
		if !everyone.MFARequiredFor(role) {
			t.Errorf("everyone rule must cover %q", role)
		}
		if none.MFARequiredFor(role) {
			t.Errorf("no rule must not require 2FA for %q", role)
		}
	}
}

// A new organization starts with the admin rule on and the full defaults;
// an organization created before (empty stored settings) keeps it off.
func TestNewTenantRequiresMFAForAdmins(t *testing.T) {
	tn, err := NewTenant("Acme", "acme", "creator")
	if err != nil {
		t.Fatal(err)
	}
	sec, err := tn.SecuritySettingsStrict()
	if err != nil {
		t.Fatal(err)
	}
	if !sec.MFARequiredForAdmins || sec.MFARequired {
		t.Fatalf("new org: want admins-only 2FA, got %+v", sec)
	}
	if sec.SessionTimeoutMin != DefaultSettings().Security.SessionTimeoutMin || sec.EmailVerificationMode != EmailVerificationAuto {
		t.Fatalf("new org must keep the other security defaults, got %+v", sec)
	}

	old := Reconstitute(shared.NewID(), "Old", "old", "", "", map[string]any{}, "creator", time.Now(), time.Now())
	if old.TypedSettings().Security.MFARequiredForAdmins {
		t.Fatal("an organization created before the rule must not change")
	}
}
