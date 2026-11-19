package provideraddrcmd

import (
	"database/sql"
	"errors"
	"strings"
	"testing"
)

// A malformed DATABASE_URL makes the driver echo it; the password must not
// reach the operator's terminal.
func TestDBErrorText_NeverEchoesThePassword(t *testing.T) {
	const pw = "s3cr3t-p4ss"
	for _, tc := range []struct{ name, url string }{
		{"well formed", "postgres://app:" + pw + "@db.internal:5432/openctem?sslmode=disable"},
		{"malformed port", "postgres://app:" + pw + "@db.internal:notaport/openctem"},
		{"unparsable", "postgres://app:" + pw + "@db.internal:5432/open ctem%zz"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, err := sql.Open("postgres", tc.url)
			if err == nil {
				err = db.Ping()
				_ = db.Close()
			}
			if err == nil {
				t.Skip("driver accepted the URL")
			}
			// What the driver says may or may not contain the password; a
			// worst case that does must be cleaned too.
			for _, e := range []error{err, errors.New("bad config " + tc.url + " rejected")} {
				got := dbErrorText("connect", e, tc.url)
				if strings.Contains(got, pw) {
					t.Fatalf("password in %q", got)
				}
				if !strings.HasPrefix(got, "connect: ") {
					t.Fatalf("lost the stage: %q", got)
				}
			}
		})
	}
	if got := dbErrorText("open database", errors.New("boom"), ""); !strings.Contains(got, "boom") {
		t.Fatalf("empty URL: %q", got)
	}
}
