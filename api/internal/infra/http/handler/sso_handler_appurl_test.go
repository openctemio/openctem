package handler

import "testing"

func TestSSOHandlerAppURLIsAnOrigin(t *testing.T) {
	cases := map[string]string{
		"https://ctem.example.com":         "https://ctem.example.com",
		"https://ctem.example.com/":        "https://ctem.example.com",
		" http://localhost:3000/app?x=1 ":  "http://localhost:3000",
		"https://user:pw@ctem.example.com": "",
		"javascript:alert(1)":              "",
		"ctem.example.com":                 "",
		"":                                 "",
	}
	for in, want := range cases {
		h := &SSOHandler{}
		h.SetAppURL(in)
		if h.appURL != want {
			t.Errorf("SetAppURL(%q) = %q, want %q", in, h.appURL, want)
		}
	}
}
