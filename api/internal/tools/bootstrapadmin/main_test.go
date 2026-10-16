package bootstrapadmin

import (
	"net/url"
	"testing"
)

// A DB_PASSWORD with URL delimiters in it reaches the driver unchanged.
func TestDatabaseURLFromEscapesParts(t *testing.T) {
	const pass = `p@ss:w/rd?#%25 x&y=z`
	env := map[string]string{
		"DB_HOST": "db.example.com", "DB_PORT": "6543", "DB_USER": "ops@team",
		"DB_PASSWORD": pass, "DB_NAME": "openctem", "DB_SSLMODE": "verify-full",
	}
	raw := databaseURLFrom(func(k string) string { return env[k] })

	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	if got, _ := u.User.Password(); got != pass || u.User.Username() != "ops@team" {
		t.Fatalf("credentials = %q / %q", u.User.Username(), got)
	}
	if u.Hostname() != "db.example.com" || u.Port() != "6543" || u.Path != "/openctem" ||
		u.Query().Get("sslmode") != "verify-full" {
		t.Fatalf("url parts: %+v", u)
	}
}

func TestDatabaseURLFromNeedsEveryPart(t *testing.T) {
	env := map[string]string{"DB_HOST": "h", "DB_USER": "u", "DB_NAME": "n"} // no password
	if got := databaseURLFrom(func(k string) string { return env[k] }); got != "" {
		t.Fatalf("want empty without DB_PASSWORD, got %q", got)
	}
}

func TestDatabaseURLFromIPv6Host(t *testing.T) {
	env := map[string]string{"DB_HOST": "2001:db8::1", "DB_USER": "u", "DB_PASSWORD": "p", "DB_NAME": "n"}
	u, err := url.Parse(databaseURLFrom(func(k string) string { return env[k] }))
	if err != nil || u.Hostname() != "2001:db8::1" || u.Port() != "5432" {
		t.Fatalf("ipv6 host: %v %+v", err, u)
	}
}

// With a console role configured the CLI connects as it: the app role cannot
// write admin_users then.
func TestDatabaseURLFromPrefersConsoleRole(t *testing.T) {
	env := map[string]string{
		"DB_HOST": "h", "DB_USER": "app", "DB_PASSWORD": "p", "DB_NAME": "n",
		"DB_ADMIN_USER": "console", "DB_ADMIN_PASSWORD": "c",
	}
	u, err := url.Parse(databaseURLFrom(func(k string) string { return env[k] }))
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := u.User.Password(); u.User.Username() != "console" || got != "c" {
		t.Fatalf("credentials = %q / %q", u.User.Username(), got)
	}
	delete(env, "DB_ADMIN_PASSWORD")
	if got := databaseURLFrom(func(k string) string { return env[k] }); got != "" {
		t.Fatalf("want empty without DB_ADMIN_PASSWORD, got %q", got)
	}
}
