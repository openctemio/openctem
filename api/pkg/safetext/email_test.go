package safetext

import "testing"

func TestMaskEmails(t *testing.T) {
	cases := map[string]string{
		"contact jane.doe@example.com today":              "contact j***@example.com today",
		"a@b.co, x_y+tag@mail.example.org.":               "a***@b.co, x***@mail.example.org.",
		"mailto:Info@Example.COM":                         "mailto:I***@Example.COM",
		"GET /reset?email=jane%40example.com HTTP/1.1":    "GET /reset?email=j***%40example.com HTTP/1.1",
		"GET /reset?email=jane%40Example.com&x=a@b.io":    "GET /reset?email=j***%40Example.com&x=a***@b.io",
		"\"jane@example.com\"":                            "\"j***@example.com\"",
		"line1\njane@example.com\n":                       "line1\nj***@example.com\n",
		"git@github.com:org/repo.git":                     "g***@github.com:org/repo.git",
		"https://user@host.example.com/x":                 "https://u***@host.example.com/x",
		"pkg:npm/%40angular/core@12.0.0":                  "pkg:npm/%40angular/core@12.0.0",
		"lib@1.2.3 image@sha256:abcd @someone a@b @x.com": "lib@1.2.3 image@sha256:abcd @someone a@b @x.com",
		"user@localhost":                                  "user@localhost",
		"":                                                "",
		"no address here":                                 "no address here",
	}
	for in, want := range cases {
		if got := MaskEmails(in); got != want {
			t.Errorf("MaskEmails(%q) = %q, want %q", in, got, want)
		}
		// Idempotent.
		if got := MaskEmails(MaskEmails(in)); got != want {
			t.Errorf("MaskEmails twice (%q) = %q, want %q", in, got, want)
		}
		if ContainsEmail(want) {
			t.Errorf("ContainsEmail(%q) after masking", want)
		}
	}
	if !ContainsEmail("x jane@example.com") || ContainsEmail("lib@1.2.3") {
		t.Error("ContainsEmail")
	}
}

func TestMaskEmailsMovingOffsets(t *testing.T) {
	s := "id=1 jane.doe@example.com tail SECRET end"
	//    0123456789...
	before, inside, atSecret, end := 2, 8, 31, len(s)
	got := MaskEmailsMoving(s, &before, &inside, &atSecret, &end, nil)
	if got != "id=1 j***@example.com tail SECRET end" {
		t.Fatalf("masked %q", got)
	}
	if before != 2 || inside != 6 || got[atSecret:atSecret+6] != "SECRET" || end != len(got) {
		t.Fatalf("offsets before=%d inside=%d secret=%d end=%d", before, inside, atSecret, end)
	}
	two := "a@x.io b@y.io K"
	k := len(two) - 1
	if out := MaskEmailsMoving(two, &k); out[k:] != "K" {
		t.Fatalf("two: %q k=%d", out, k)
	}
}
