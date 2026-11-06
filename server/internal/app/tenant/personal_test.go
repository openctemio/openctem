package tenant

import (
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
)

func TestCanonicalMailbox(t *testing.T) {
	cases := map[string]string{
		"J.Doe@gmail.com":        "jdoe@gmail.com",
		"jdoe+work@gmail.com":    "jdoe@gmail.com",
		"j.d.o.e@googlemail.com": "jdoe@gmail.com",
		"a.b+x@corp.example":     "a.b@corp.example",
		"not-an-email":           "",
	}
	for in, want := range cases {
		if got := canonicalMailbox(in); got != want {
			t.Errorf("%s: got %q, want %q", in, got, want)
		}
	}
}

func TestSSOExceptionValidate(t *testing.T) {
	now := time.Now().UTC()
	ok := tenantdom.SSOException{UserID: shared.NewID().String(), Reason: "vendor laptop", ExpiresAt: now.Add(24 * time.Hour)}
	if err := ok.Validate(now); err != nil {
		t.Fatal(err)
	}
	bad := []tenantdom.SSOException{
		{UserID: "nope", Reason: "r", ExpiresAt: now.Add(time.Hour)},
		{UserID: ok.UserID, Reason: "", ExpiresAt: now.Add(time.Hour)},
		{UserID: ok.UserID, Reason: "r", ExpiresAt: now.Add(-time.Hour)},
		{UserID: ok.UserID, Reason: "r", ExpiresAt: now.Add(91 * 24 * time.Hour)},
	}
	for _, e := range bad {
		if e.Validate(now) == nil {
			t.Errorf("%+v must be refused", e)
		}
	}
	sec := tenantdom.SecuritySettings{SSOExceptions: []tenantdom.SSOException{ok}}
	if !sec.HasSSOException(ok.UserID, now) || sec.HasSSOException(ok.UserID, now.Add(48*time.Hour)) {
		t.Error("an exception holds until it expires")
	}
}

func TestNewOrganizationAsksPersonalAccountsForMFA(t *testing.T) {
	tn, err := tenantdom.NewTenant("Acme", "acme-personal", "creator")
	if err != nil {
		t.Fatal(err)
	}
	if got := tn.TypedSettings().Security.PersonalAccounts.Effective(); got != tenantdom.PersonalAccountsAllowedWithMFA {
		t.Fatalf("new organization policy = %s, want allowed_with_mfa", got)
	}
	// An organization whose stored security section predates the policy
	// keeps allowing personal accounts.
	old := tenantdom.Reconstitute(shared.NewID(), "Old", "old", "", "", map[string]any{"security": map[string]any{"mfa_required": false}}, "c", time.Now(), time.Now())
	if got := old.TypedSettings().Security.PersonalAccounts.Effective(); got != tenantdom.PersonalAccountsAllowed {
		t.Fatalf("existing organization policy = %s, want allowed", got)
	}
}
