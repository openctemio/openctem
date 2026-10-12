package user

import "testing"

func TestAllowedAvatarURL(t *testing.T) {
	for raw, want := range map[string]bool{
		"": true,
		"https://avatars.githubusercontent.com/u/1?v=4":                      true,
		"https://lh3.googleusercontent.com/a/abc=s96-c":                      true,
		"https://secure.gravatar.com/avatar/abc":                             true,
		"https://gitlab.com/uploads/-/system/user/avatar/1":                  true,
		"https://AVATARS.githubusercontent.com/u/1":                          true,
		"https://tracker.example/pixel.gif":                                  false,
		"http://avatars.githubusercontent.com/u/1":                           false,
		"//avatars.githubusercontent.com/u/1":                                false,
		"https://user@avatars.githubusercontent.com/u/1":                     false,
		"https://avatars.githubusercontent.com:444/u/1":                      false,
		"https://googleusercontent.com/a.png":                                false,
		"https://evilgoogleusercontent.com/a.png":                            false,
		"https://lh3.googleusercontent.com.evil.example/a":                   false,
		"data:image/png;base64,AAAA":                                         false,
		"javascript:alert(1)":                                                false,
		"https://avatars.githubusercontent.com/" + string(make([]byte, 500)): false,
	} {
		if got := AllowedAvatarURL(raw); got != want {
			t.Errorf("AllowedAvatarURL(%q) = %v, want %v", raw, got, want)
		}
	}
}

// A picture from an identity provider on an unknown host is dropped, not
// refused: the sign-in still works, the person shows initials.
func TestNewFederatedAndOAuthUser_DropUnknownAvatarHost(t *testing.T) {
	u, err := NewFederatedUser("a@example.com", "A", "https://tracker.example/p.gif", AuthProviderOIDC)
	if err != nil {
		t.Fatal(err)
	}
	if u.AvatarURL() != "" {
		t.Errorf("federated user kept %q", u.AvatarURL())
	}
	u, err = NewOAuthUser("b@example.com", "B", "https://avatars.githubusercontent.com/u/2", AuthProviderGitHub)
	if err != nil {
		t.Fatal(err)
	}
	if u.AvatarURL() != "https://avatars.githubusercontent.com/u/2" {
		t.Errorf("GitHub avatar dropped: %q", u.AvatarURL())
	}
}
