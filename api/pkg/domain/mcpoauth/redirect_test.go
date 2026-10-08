package mcpoauth

import "testing"

func TestValidateRedirectURI(t *testing.T) {
	for _, ok := range []string{
		"https://app.example/cb",
		"https://app.example/cb?x=1",
		"http://127.0.0.1/cb",
		"http://127.0.0.1:3000/cb",
		"http://[::1]:3000/cb",
		"http://localhost:8080/callback",
	} {
		if err := ValidateRedirectURI(ok); err != nil {
			t.Errorf("%s refused: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"", "/cb", "app.example/cb", "http://app.example/cb", "javascript:alert(1)",
		"myapp://cb", "https://app.example/cb#frag", "https://u:p@app.example/cb",
		"data:text/html,x", "https:///cb",
	} {
		if err := ValidateRedirectURI(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestMatchRedirectURI(t *testing.T) {
	reg := []string{"https://app.example/cb", "http://127.0.0.1:3000/cb", "http://localhost/callback?mode=x"}
	for _, ok := range []string{
		"https://app.example/cb",
		"http://127.0.0.1:3000/cb",
		"http://127.0.0.1:51234/cb", // loopback: any port
		"http://127.0.0.1/cb",
		"http://localhost:9999/callback?mode=x",
	} {
		if !MatchRedirectURI(reg, ok) {
			t.Errorf("%s refused", ok)
		}
	}
	for _, bad := range []string{
		"https://app.example/cb/",        // exact string match
		"https://APP.example/cb",         // no normalization
		"https://app.example/cb?x=1",     // query added
		"https://app.example:443/cb",     // port spelled out
		"https://app.example.evil/cb",    // suffix
		"https://app.example:8443/cb",    // https never gets the port exception
		"http://127.0.0.1:3000/cb/x",     // path differs
		"http://localhost:3000/cb",       // host spelling differs from 127.0.0.1
		"http://[::1]:3000/cb",           // ditto
		"http://127.0.0.1:0/cb",          // invalid port
		"http://127.0.0.1:99999/cb",      // invalid port
		"http://127.0.0.1:3000/cb#x",     // fragment
		"http://user@127.0.0.1:3000/cb",  // user info
		"http://localhost:9999/callback", // query missing
		"",
	} {
		if MatchRedirectURI(reg, bad) {
			t.Errorf("%s accepted", bad)
		}
	}
}

func TestIsLoopbackOnly(t *testing.T) {
	if !IsLoopbackOnly([]string{"http://127.0.0.1/cb", "http://localhost:3/cb"}) {
		t.Error("loopback-only client not detected")
	}
	if IsLoopbackOnly([]string{"http://127.0.0.1/cb", "https://app.example/cb"}) || IsLoopbackOnly(nil) {
		t.Error("client with an https redirect flagged loopback-only")
	}
}
