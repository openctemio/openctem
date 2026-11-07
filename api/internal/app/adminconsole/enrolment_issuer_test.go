package adminconsole

import (
	"context"
	"strings"
	"testing"
)

func TestEnrolmentIssuer(t *testing.T) {
	cases := map[string]string{
		"https://admin.example.com":      "OpenCTEM Admin (admin.example.com)",
		"https://Admin.Example.com:8443": "OpenCTEM Admin (admin.example.com)",
		"https://staging.example.com./":  "OpenCTEM Admin (staging.example.com)",
		"":                               "OpenCTEM Admin",
		"::not a url":                    "OpenCTEM Admin",
		"https://[2001:db8::1]:443/":     "OpenCTEM Admin",
	}
	for in, want := range cases {
		if got := EnrolmentIssuer("OpenCTEM Admin", in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
	if got := EnrolmentIssuer(" ", "https://a.example"); got != Issuer+" (a.example)" {
		t.Errorf("blank label: %q", got)
	}
}

// A new enrolment is labeled with the console host; without the setting the
// plain label stays (existing behavior, secrets untouched).
func TestNewEnrolmentCarriesConsoleHost(t *testing.T) {
	h := newHarness(t)
	res, err := h.svc.Start(context.Background(), refresh, password, client)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.OTPAuthURI, "OpenCTEM%20Admin:") || strings.Contains(res.OTPAuthURI, "example.com") {
		t.Fatalf("default label changed: %s", res.OTPAuthURI)
	}

	h2 := newHarness(t)
	h2.svc.SetEnrolmentIssuer(EnrolmentIssuer(Issuer, "https://admin.example.com"))
	res, err = h2.svc.Start(context.Background(), refresh, password, client)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.OTPAuthURI, "OpenCTEM%20Admin%20%28admin.example.com%29:") {
		t.Fatalf("host missing from issuer: %s", res.OTPAuthURI)
	}
}
