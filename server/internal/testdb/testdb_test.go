package testdb

import (
	"strings"
	"testing"
)

func TestGuard(t *testing.T) {
	cases := []struct {
		name, raw, allow, want string
		wantErr                bool
	}{
		{"unset", "", "", "", false},
		{"test db", "postgres://u:p@localhost:5432/app_test?sslmode=disable", "", "postgres://u:p@localhost:5432/app_test?sslmode=disable", false},
		{"compat db", "postgres://u:p@localhost:5432/app_compat", "", "postgres://u:p@localhost:5432/app_compat", false},
		{"live db refused", "postgres://u:p@localhost:5432/openctem?sslmode=disable", "", "", true},
		{"test as prefix refused", "postgres://u:p@localhost:5432/test_openctem", "", "", true},
		{"no db name refused", "postgres://u:p@localhost:5432/", "", "", true},
		{"dbname query", "postgres://u:p@localhost:5432?dbname=x_test", "", "postgres://u:p@localhost:5432?dbname=x_test", false},
		{"kv dsn test", "host=localhost dbname=app_test sslmode=disable", "", "host=localhost dbname=app_test sslmode=disable", false},
		{"kv dsn live refused", "host=localhost dbname='openctem' sslmode=disable", "", "", true},
		{"override exact", "postgres://u:p@localhost:5432/scratch", "scratch", "postgres://u:p@localhost:5432/scratch", false},
		{"override other name refused", "postgres://u:p@localhost:5432/openctem", "scratch", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(allowOverrideEnv, tc.allow)
			got, err := guard(tc.raw)
			if got != tc.want {
				t.Fatalf("guard(%q) = %q, want %q", tc.raw, got, tc.want)
			}
			if (err != nil) != tc.wantErr {
				t.Fatalf("guard(%q) err = %v, wantErr %v", tc.raw, err, tc.wantErr)
			}
		})
	}
}

// recovered runs f and returns what it panicked with ("" if it returned).
func recovered(f func()) (msg string) {
	defer func() {
		if r := recover(); r != nil {
			msg, _ = r.(string)
			if msg == "" {
				msg = "non-string panic"
			}
		}
	}()
	f()
	return ""
}

// A non-test database must never reach a DB-backed test, and the run must
// fail rather than report a green that skipped every DB test.
func TestURL_NonTestDatabasePanicsAndNeverReturnsIt(t *testing.T) {
	const live = "postgres://u:p@localhost:5432/openctem?sslmode=disable"
	t.Setenv("DATABASE_URL", live)
	t.Setenv(allowOverrideEnv, "")
	for _, required := range []string{"", "1"} {
		t.Setenv(requiredEnv, required)
		var got string
		msg := recovered(func() { got = URL() })
		if got != "" {
			t.Fatalf("URL() returned the non-test database %q", got)
		}
		if !strings.Contains(msg, `refusing database "openctem"`) || !strings.Contains(msg, "_test") {
			t.Fatalf("required=%q: want a panic naming the refused database and the rule, got %q", required, msg)
		}
	}
}

func TestRLSURL_NonTestDatabasePanics(t *testing.T) {
	t.Setenv("DATABASE_URL_RLS_TEST", "postgres://u:p@localhost:5432/openctem")
	t.Setenv(allowOverrideEnv, "")
	if msg := recovered(func() { _ = RLSURL() }); !strings.Contains(msg, "DATABASE_URL_RLS_TEST") {
		t.Fatalf("want a panic naming DATABASE_URL_RLS_TEST, got %q", msg)
	}
}

func TestURL_UnsetSkipsUnlessRequired(t *testing.T) {
	t.Setenv("DATABASE_URL", "")
	t.Setenv(requiredEnv, "")
	if msg := recovered(func() {
		if got := URL(); got != "" {
			t.Errorf("URL() = %q, want empty", got)
		}
	}); msg != "" {
		t.Fatalf("unset DATABASE_URL without %s must not panic, got %q", requiredEnv, msg)
	}

	t.Setenv(requiredEnv, "1")
	if msg := recovered(func() { _ = URL() }); !strings.Contains(msg, requiredEnv) {
		t.Fatalf("unset DATABASE_URL with %s=1 must panic, got %q", requiredEnv, msg)
	}

	// The RLS database stays optional even when the DB tests are required.
	t.Setenv("DATABASE_URL_RLS_TEST", "")
	if msg := recovered(func() { _ = RLSURL() }); msg != "" {
		t.Fatalf("unset DATABASE_URL_RLS_TEST must not panic, got %q", msg)
	}
}

func TestURL_TestDatabaseReturned(t *testing.T) {
	const dsn = "postgres://u@localhost:5432/app_test?sslmode=disable"
	t.Setenv("DATABASE_URL", dsn)
	t.Setenv(requiredEnv, "1")
	if got := URL(); got != dsn {
		t.Fatalf("URL() = %q, want %q", got, dsn)
	}
}

func TestRequired(t *testing.T) {
	for v, want := range map[string]bool{"": false, "0": false, "false": false, "1": true, "true": true, "TRUE": true, "yes": true} {
		t.Setenv(requiredEnv, v)
		if got := Required(); got != want {
			t.Errorf("Required() with %q = %v, want %v", v, got, want)
		}
	}
}

// fakeTB records whether Skipf skipped or failed. Embedding testing.TB
// satisfies the interface's unexported method; only the methods Skipf calls
// are implemented.
type fakeTB struct {
	testing.TB
	skipped, failed bool
	msg             string
}

func (f *fakeTB) Helper() {}
func (f *fakeTB) Skipf(format string, args ...any) {
	f.skipped = true
}
func (f *fakeTB) Fatalf(format string, args ...any) {
	f.failed = true
	f.msg = format
}

func TestSkipf_FailsWhenRequired(t *testing.T) {
	t.Setenv(requiredEnv, "")
	f := &fakeTB{}
	Skipf(f, "cannot reach DATABASE_URL: %v", "refused")
	if !f.skipped || f.failed {
		t.Fatalf("not required: want skip, got skipped=%v failed=%v", f.skipped, f.failed)
	}

	t.Setenv(requiredEnv, "1")
	f = &fakeTB{}
	Skipf(f, "cannot reach DATABASE_URL: %v", "refused")
	if f.skipped || !f.failed {
		t.Fatalf("required: want failure, got skipped=%v failed=%v", f.skipped, f.failed)
	}
	if !strings.Contains(f.msg, "cannot reach DATABASE_URL") {
		t.Fatalf("failure must carry the skip reason, got %q", f.msg)
	}
}
