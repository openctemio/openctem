package handler

import "testing"

func TestSanitizeCSVCell(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"plain", "plain"},
		{"a=b", "a=b"},
		{"=HYPERLINK(\"https://evil.test\",\"x\")", "'=HYPERLINK(\"https://evil.test\",\"x\")"},
		{"+1+1", "'+1+1"},
		{"-1+1", "'-1+1"},
		{"@SUM(A1)", "'@SUM(A1)"},
		{"\tx", "'\tx"},
		{"\rx", "'\rx"},
		// Importers trim leading whitespace, so these are formulas too.
		{" =cmd|' /C calc'!A0", "' =cmd|' /C calc'!A0"},
		{"   +1", "'   +1"},
		{"\n@x", "'\n@x"},
		{" \t-1", "' \t-1"},
		{"  plain", "  plain"},
		{"\t", "'\t"},
	}
	for _, c := range cases {
		if got := sanitizeCSVCell(c.in); got != c.want {
			t.Errorf("sanitizeCSVCell(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
