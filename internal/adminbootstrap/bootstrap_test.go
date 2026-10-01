package adminbootstrap

import (
	"strings"
	"testing"
)

func TestOptionsRequireABackup(t *testing.T) {
	cases := map[string]struct {
		o       Options
		wantErr string
	}{
		"backup required":   {Options{Email: "a@x.io"}, "break-glass backup administrator is required"},
		"same email":        {Options{Email: "a@x.io", BackupEmail: "A@x.io"}, "different email"},
		"both flags":        {Options{Email: "a@x.io", BackupEmail: "b@x.io", NoBackup: true}, "mutually exclusive"},
		"bad role":          {Options{Email: "a@x.io", NoBackup: true, Role: "root"}, "invalid role"},
		"explicit opt-out":  {Options{Email: "a@x.io", NoBackup: true}, ""},
		"with backup":       {Options{Email: "a@x.io", BackupEmail: "b@x.io"}, ""},
		"link needs no bkp": {Options{Email: "a@x.io", LinkOnly: true}, ""},
	}
	for name, c := range cases {
		o := c.o
		err := o.Normalize()
		switch {
		case c.wantErr == "" && err != nil:
			t.Fatalf("%s: unexpected error %v", name, err)
		case c.wantErr != "" && (err == nil || !strings.Contains(err.Error(), c.wantErr)):
			t.Fatalf("%s: want error containing %q, got %v", name, c.wantErr, err)
		}
	}
}
