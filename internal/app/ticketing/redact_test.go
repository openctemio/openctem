package ticketing

import (
	"strings"
	"testing"
)

func TestRedactSecrets(t *testing.T) {
	cases := []struct {
		name      string
		in        string
		mustNotIn []string // substrings that must be gone
		mustIn    []string // substrings that must survive
	}{
		{
			name:      "aws access key id",
			in:        "leaked key AKIAIOSFODNN7EXAMPLE in config",
			mustNotIn: []string{"AKIAIOSFODNN7EXAMPLE"},
			mustIn:    []string{"[REDACTED]", "leaked key", "in config"},
		},
		{
			name:      "password assignment",
			in:        `db.password = "hunter2supersecret"`,
			mustNotIn: []string{"hunter2supersecret"},
			mustIn:    []string{"password", "[REDACTED]"},
		},
		{
			name:      "api_key colon assignment",
			in:        "api_key: sk_live_abcdef1234567890",
			mustNotIn: []string{"sk_live_abcdef1234567890"},
			mustIn:    []string{"api_key", "[REDACTED]"},
		},
		{
			name:   "benign text untouched",
			in:     "This is a SQL injection in the login form.",
			mustIn: []string{"This is a SQL injection in the login form."},
		},
		{
			name:      "empty string",
			in:        "",
			mustNotIn: nil,
			mustIn:    nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := RedactSecrets(tc.in)
			for _, m := range tc.mustNotIn {
				if strings.Contains(got, m) {
					t.Errorf("output %q still contains secret %q", got, m)
				}
			}
			for _, m := range tc.mustIn {
				if !strings.Contains(got, m) {
					t.Errorf("output %q missing expected substring %q", got, m)
				}
			}
		})
	}
}
