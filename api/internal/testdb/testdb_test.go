package testdb

import "testing"

func TestGuard(t *testing.T) {
	cases := []struct {
		name, raw, allow, want string
	}{
		{"unset", "", "", ""},
		{"test db", "postgres://u:p@localhost:5432/app_test?sslmode=disable", "", "postgres://u:p@localhost:5432/app_test?sslmode=disable"},
		{"compat db", "postgres://u:p@localhost:5432/app_compat", "", "postgres://u:p@localhost:5432/app_compat"},
		{"live db refused", "postgres://u:p@localhost:5432/openctem?sslmode=disable", "", ""},
		{"test as prefix refused", "postgres://u:p@localhost:5432/test_openctem", "", ""},
		{"no db name refused", "postgres://u:p@localhost:5432/", "", ""},
		{"dbname query", "postgres://u:p@localhost:5432?dbname=x_test", "", "postgres://u:p@localhost:5432?dbname=x_test"},
		{"kv dsn test", "host=localhost dbname=app_test sslmode=disable", "", "host=localhost dbname=app_test sslmode=disable"},
		{"kv dsn live refused", "host=localhost dbname='openctem' sslmode=disable", "", ""},
		{"override exact", "postgres://u:p@localhost:5432/scratch", "scratch", "postgres://u:p@localhost:5432/scratch"},
		{"override other name refused", "postgres://u:p@localhost:5432/openctem", "scratch", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(allowOverrideEnv, tc.allow)
			if got := guard(tc.raw); got != tc.want {
				t.Fatalf("guard(%q) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}
