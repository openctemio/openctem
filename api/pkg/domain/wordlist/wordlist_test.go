package wordlist

import (
	"errors"
	"strconv"
	"strings"
	"testing"
)

func TestNormalize_KeepsDNSLabelsOnly(t *testing.T) {
	text := strings.Join([]string{
		"# branch codes",
		"HN01",
		"  hcm02  ",
		"chinhanh # a comment after the label",
		"api.eu",
		"",
		"hn01",                         // repeat (case-folded)
		"*.wild",                       // wildcard
		"http://evil.example/x",        // URL
		"under_score",                  // not a DNS label
		"-lead",                        // leading dash
		"a.b.c.d",                      // more than three labels
		"12345",                        // all digits
		"bad\x00nul",                   // control character
		"x" + strings.Repeat("y", 63),  // label too long
		"ghp1a2B3c4D5e6F7g8H9i0J1k2L3", // looks like a token
		"trailing.",
		"vn\r",
	}, "\n")
	n, err := Normalize(text)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"hn01", "hcm02", "chinhanh", "api.eu", "trailing", "vn"}
	if strings.Join(n.Labels, ",") != strings.Join(want, ",") {
		t.Fatalf("labels %v, want %v", n.Labels, want)
	}
	if n.Duplicates != 1 || n.Secrets != 1 || n.Invalid != 8 {
		t.Fatalf("dropped: invalid %d secrets %d duplicates %d", n.Invalid, n.Secrets, n.Duplicates)
	}
	if len(n.Examples) != maxExamples {
		t.Fatalf("examples %v", n.Examples)
	}
	for _, e := range n.Examples {
		if strings.ContainsRune(e, 0) || len(e) > maxExampleLen {
			t.Fatalf("example %q not cleaned", e)
		}
	}
	if n.Content != strings.Join(want, "\n")+"\n" || len(n.SHA256) != 64 {
		t.Fatalf("content %q sha %q", n.Content, n.SHA256)
	}
	again, _ := Normalize(text)
	if again.SHA256 != n.SHA256 {
		t.Fatal("not deterministic")
	}
}

func TestNormalize_Bounds(t *testing.T) {
	if _, err := Normalize("# only comments\n\n*.x\n"); !errors.Is(err, ErrEmpty) {
		t.Fatalf("no label: %v", err)
	}
	if _, err := Normalize(strings.Repeat("a", MaxInputBytes+1)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("text over the cap: %v", err)
	}
	var b strings.Builder
	for i := 0; i <= MaxLabels; i++ {
		b.WriteString("w" + strconv.Itoa(i) + "\n")
	}
	if _, err := Normalize(b.String()); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("labels over the cap: %v", err)
	}
}

func TestValidateNameAndDescription(t *testing.T) {
	for _, ok := range []string{"branch codes", "vn-words", "list_1.v2"} {
		if ValidateName(ok) != nil {
			t.Errorf("%q refused", ok)
		}
	}
	for _, bad := range []string{"", " lead", "a/b", "<script>", strings.Repeat("a", 65)} {
		if ValidateName(bad) == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if ValidateDescription(strings.Repeat("é", MaxDescription)) != nil || ValidateDescription(strings.Repeat("a", MaxDescription+1)) == nil {
		t.Fatal("description bound")
	}
}
