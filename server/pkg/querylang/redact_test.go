package querylang

import "testing"

func TestRedact(t *testing.T) {
	cases := []struct{ in, want string }{
		// names, addresses and ids are masked; enum values, numbers,
		// relative times and the pipeline stay.
		{`findings where asset.name in ("db-a.example.com", "db-b.example.com") and severity = high`,
			`findings where asset.name in ("***", "***") and severity = high`},
		{`findings where asset.ip = "192.0.2.10" or cvss_score >= 9 and created_at > -14d`,
			`findings where asset.ip = "***" or cvss_score >= 9 and created_at > -14d`},
		{`findings where assigned_to = "6f1d2a1e-0000-4000-8000-000000000001" and not status = resolved | count by severity`,
			`findings where assigned_to = "***" and not status = resolved | count by severity`},
		{`findings where assigned_to = me`, `findings where assigned_to = me`},
		{`findings where text ~ "payroll"`, `findings where text ~ "***"`},
		{`findings where cvss_score between 7 and 9`, `findings where cvss_score between 7 and 9`},
		// a bare word that is not a member of the field's enum is a name
		{`findings where asset.name = dbpayroll`, `findings where asset.name = "***"`},
	}
	for _, c := range cases {
		got, ok := Redact(c.in)
		if !ok {
			t.Fatalf("Redact(%q) did not parse", c.in)
		}
		if got != c.want {
			t.Errorf("Redact(%q)\n got %q\nwant %q", c.in, got, c.want)
		}
		if _, err := Parse(got); err != nil {
			t.Errorf("redacted text %q does not parse: %v", got, err)
		}
	}
	if out, ok := Redact(`findings where (`); ok || out != "" {
		t.Errorf("unparsable text must give nothing, got %q", out)
	}
}
