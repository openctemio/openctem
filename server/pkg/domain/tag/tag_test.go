package tag

import (
	"errors"
	"strings"
	"testing"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

func TestCheck(t *testing.T) {
	cases := []struct {
		in   string
		want Reason
	}{
		{"production", ""},
		{"team:payments", ""},
		{"  Env:Prod  ", ""},
		{"PHP:8.1.12", ""},
		{"", ReasonEmpty},
		{"   ", ReasonEmpty},
		{strings.Repeat("a", MaxLength), ""},
		{strings.Repeat("a", MaxLength+1), ReasonTooLong},
		{strings.Repeat("é", MaxLength), ""},
		{"a\u202eb", ReasonHidden}, // bidi override
		{"a\u200bb", ReasonHidden}, // zero width space
		{"a\x00b", ReasonHidden},   // NUL
		{"a\nb", ReasonHidden},     // newline
		{"a\tb", ReasonHidden},     // tab
		{"<script>", ReasonMarkup}, // markup
		{"a>b", ReasonMarkup},
		{"=cmd|' /C calc'!A0", ReasonFormula},
		{"+1", ReasonFormula},
		{"-x", ReasonFormula},
		{"@sum", ReasonFormula},
		{"bug-bounty", ReasonReserved},
		{"Bug-Bounty", ReasonReserved},
		{"sys:owner", ReasonReserved},
		{"program:acme", ReasonReserved},
		{"source:hackerone", ReasonReserved},
		{"platform:x", ReasonReserved},
		{"dangling_cname", ReasonReserved},
		{"programmatic", ""},
	}
	for _, c := range cases {
		got, why := Check(c.in)
		if why != c.want {
			t.Errorf("Check(%q) = %q, want %q", c.in, why, c.want)
		}
		if why == "" && got != Normalize(c.in) {
			t.Errorf("Check(%q) changed the tag to %q", c.in, got)
		}
	}
}

func TestValidateNewKeepsLegacyTags(t *testing.T) {
	long := strings.Repeat("x", 80) // a legacy tag over the limit
	cur := []string{long, "bug-bounty"}
	out, err := ValidateNew(cur, []string{long, "bug-bounty", "env:prod"})
	if err != nil {
		t.Fatalf("legacy tags must not block a save: %v", err)
	}
	if len(out) != 3 {
		t.Fatalf("got %v", out)
	}
	// Adding a new long or reserved tag is refused.
	for _, bad := range []string{strings.Repeat("y", 80), "sys:x", "a\u202eb"} {
		_, err = ValidateNew(cur, []string{long, bad})
		var te *Error
		if !errors.As(err, &te) {
			t.Fatalf("%q: want *Error, got %v", bad, err)
		}
	}
}

func TestValidateNewCapAndDedupe(t *testing.T) {
	var many []string
	for i := 0; i <= MaxPerObject; i++ {
		many = append(many, "t"+strings.Repeat("a", i%5)+string(rune('a'+i%26))+string(rune('a'+i/26)))
	}
	if _, err := ValidateNew(nil, many); err == nil {
		t.Fatal("more than MaxPerObject tags must be refused")
	}
	out, err := ValidateNew(nil, []string{"a", " a ", "b"})
	if err != nil || len(out) != 2 {
		t.Fatalf("dedupe after normalize: %v %v", out, err)
	}
}

func TestFilterImport(t *testing.T) {
	protected := func(tag string) (Reason, bool) {
		if strings.EqualFold(tag, "env:prod") {
			return ReasonProtected, false
		}
		return "", true
	}
	in := []string{"ok", "OK", "ok", strings.Repeat("z", 200), "bug-bounty", "env:prod", "a\u200bb", "<b>", "fine:1"}
	got, dropped := FilterImport(in, protected)
	want := []string{"ok", "OK", "fine:1"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("got %v want %v", got, want)
	}
	for r, n := range map[Reason]int{ReasonTooLong: 1, ReasonReserved: 1, ReasonProtected: 1, ReasonHidden: 1, ReasonMarkup: 1} {
		if dropped[r] != n {
			t.Errorf("dropped[%s]=%d want %d (%v)", r, dropped[r], n, dropped)
		}
	}
}

func TestFilterImportCap(t *testing.T) {
	var in []string
	for i := 0; i < MaxPerImport+5; i++ {
		in = append(in, "t"+string(rune('a'+i)))
	}
	got, dropped := FilterImport(in, nil)
	if len(got) != MaxPerImport || dropped[ReasonOverCap] != 5 {
		t.Fatalf("got %d dropped %v", len(got), dropped)
	}
}

func TestRefusal_IsAValidationErrorWithAFixedSentence(t *testing.T) {
	_, err := ValidateNew(nil, []string{"sys:x"})
	got := Refusal(err)
	if !errors.Is(got, shared.ErrValidation) {
		t.Fatalf("not a validation error: %v", got)
	}
	var de *shared.DomainError
	if !errors.As(got, &de) || de.Code != CodeInvalidTag || !strings.Contains(de.Message, "reserved") {
		t.Fatalf("got %+v", got)
	}
	if Refusal(errors.New("pq: connection refused")).(*shared.DomainError).Message != "a tag is not allowed" {
		t.Fatal("a lower error's text reached the message")
	}
}
