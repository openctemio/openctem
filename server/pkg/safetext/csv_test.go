package safetext

import "testing"

func TestCSVCell(t *testing.T) {
	cases := map[string]string{
		"":                   "",
		"plain":              "plain",
		"=1+1":               "'=1+1",
		"+1":                 "'+1",
		"-1":                 "'-1",
		"@SUM(A1)":           "'@SUM(A1)",
		"\t=x":               "'\t=x",
		"\rx":                "'\rx",
		" =HYPERLINK(\"x\")": "' =HYPERLINK(\"x\")",
		"  \t@cmd":           "'  \t@cmd",
		"\n+1":               "'\n+1",
		"a=b":                "a=b",
		"'already quoted":    "'already quoted",
		"   ":                "   ",
	}
	for in, want := range cases {
		if got := CSVCell(in); got != want {
			t.Errorf("CSVCell(%q) = %q, want %q", in, got, want)
		}
	}
}

// Every escaped cell imports back to its original value, and an apostrophe
// the cell had itself is kept.
func TestUnescapeCSVCellRoundTrip(t *testing.T) {
	for _, in := range []string{"", "plain", "=1+1", " =x", "\t-1", "@a", "'quoted", "'", "''=x", "a=b"} {
		if got := UnescapeCSVCell(CSVCell(in)); got != in {
			t.Errorf("round trip %q -> %q", in, got)
		}
	}
	if got := UnescapeCSVCell("'kept"); got != "'kept" {
		t.Errorf("own apostrophe removed: %q", got)
	}
}
