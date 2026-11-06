package user

import "testing"

// Every way an account gets or changes its address stores one spelling:
// trimmed and lower-cased (users.email is unique on lower(email)).
func TestEmailIsStoredNormalized(t *testing.T) {
	const raw, want = "  Alice@Corp.Example ", "alice@corp.example"
	build := map[string]func() (*User, error){
		"local":       func() (*User, error) { return NewLocalUser(raw, "A", "hash") },
		"provisioned": func() (*User, error) { return NewProvisionedLocalUser(raw, "A") },
		"oauth":       func() (*User, error) { return NewOAuthUser(raw, "A", "", AuthProviderGitHub) },
		"federated":   func() (*User, error) { return NewFederatedUser(raw, "A", "", AuthProviderOIDC) },
		"plain":       func() (*User, error) { return New(raw, "A") },
	}
	for name, mk := range build {
		u, err := mk()
		if err != nil || u.Email() != want {
			t.Fatalf("%s: %q / %v", name, u.Email(), err)
		}
	}
	u, _ := New("a@corp.example", "A")
	if err := u.UpdateEmail("  NEW@Corp.Example"); err != nil || u.Email() != "new@corp.example" {
		t.Fatalf("UpdateEmail: %q / %v", u.Email(), err)
	}
	if err := u.UpdateEmail("   "); err == nil {
		t.Fatal("a blank address was accepted")
	}
}
