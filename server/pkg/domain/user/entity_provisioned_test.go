package user

import "testing"

func TestNewProvisionedLocalUser_IsPendingSetup(t *testing.T) {
	u, err := NewProvisionedLocalUser("new@corp.com", "New")
	if err != nil {
		t.Fatalf("NewProvisionedLocalUser: %v", err)
	}
	if !u.IsLocalUser() || u.PasswordHash() != nil {
		t.Fatal("a provisioned account is local with no password")
	}
	if !u.EmailVerified() {
		t.Fatal("a provisioned account is created verified (administrator-vouched)")
	}
	if !u.IsPendingSetup() {
		t.Fatal("a fresh provisioned account must be pending setup")
	}

	if err := u.SetPasswordHash("hash"); err != nil {
		t.Fatalf("SetPasswordHash: %v", err)
	}
	if u.IsPendingSetup() {
		t.Fatal("an account with a password is no longer pending setup")
	}
}

func TestIsPendingSetup_UsedAccountIsNotPending(t *testing.T) {
	u, _ := NewProvisionedLocalUser("sso@corp.com", "SSO")
	u.UpdateLastLogin() // e.g. signed in through SSO without ever setting a password
	if u.IsPendingSetup() {
		t.Fatal("an account that has signed in is not pending setup")
	}
}

func TestIsPendingSetup_FederatedIsNotPending(t *testing.T) {
	u, _ := NewFederatedUser("a@corp.com", "A", "", AuthProviderGoogle)
	if u.IsPendingSetup() {
		t.Fatal("federated accounts are never pending a password setup")
	}
}

func TestNewProvisionedLocalUser_RequiresEmail(t *testing.T) {
	if _, err := NewProvisionedLocalUser("", "x"); err == nil {
		t.Fatal("email is required")
	}
}
