package emaildomain

import "testing"

func TestClaimRefusal(t *testing.T) {
	cases := map[string]Reason{
		// Organization domains.
		"acme.com":          ReasonNone,
		"corp.acme.com":     ReasonNone,
		"acme.co.uk":        ReasonNone,
		"ACME.COM.":         ReasonNone,
		"example.internal":  ReasonNone, // unlisted TLD: not a shared suffix
		"sub.example.local": ReasonNone,
		// Public suffixes, ICANN section.
		"com":    ReasonPublicSuffix,
		"co.uk":  ReasonPublicSuffix,
		"com.vn": ReasonPublicSuffix,
		// Private section: the suffix and every name under it.
		"github.io":       ReasonPublicSuffix,
		"alice.github.io": ReasonPublicSuffix,
		"app.vercel.app":  ReasonPublicSuffix,
		"x.blogspot.com":  ReasonPublicSuffix,
		// Consumer providers, including subdomains and the old blocklist.
		"gmail.com":               ReasonConsumer,
		"Outlook.com":             ReasonConsumer,
		"yahoo.co.jp":             ReasonConsumer,
		"mail.yahoo.com":          ReasonConsumer,
		"onmicrosoft.com":         ReasonConsumer,
		"contoso.onmicrosoft.com": ReasonConsumer,
		"proton.me":               ReasonConsumer,
		"@icloud.com":             ReasonConsumer,
		// Disposable services.
		"mailinator.com":       ReasonDisposable,
		"inbox.mailinator.com": ReasonDisposable,
		"10minutemail.com":     ReasonDisposable,
		"":                     ReasonPublicSuffix,
	}
	for in, want := range cases {
		if got := ClaimRefusal(in); got != want {
			t.Errorf("ClaimRefusal(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestEmbeddedListsLoaded(t *testing.T) {
	load()
	if len(consumer) < 100 {
		t.Fatalf("consumer list too short: %d", len(consumer))
	}
	if len(disposable) < 1000 {
		t.Fatalf("disposable list too short: %d", len(disposable))
	}
	for d := range consumer {
		if _, ok := disposable[d]; ok && d != "" {
			// Not an error, but a provider on both lists would make the
			// reason ambiguous; consumer wins in ClaimRefusal.
			t.Logf("listed as both consumer and disposable: %s", d)
		}
	}
}
