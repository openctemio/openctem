package asset

// Name forms that used to give one asset several names, or kept part of a
// database password in the asset name (CTEM deep dive 2026-10).

import (
	"strings"
	"testing"
)

func TestNormalizeName_EdgeForms(t *testing.T) {
	cases := []struct {
		name string
		typ  AssetType
		want string
	}{
		// Database: credentials end at the last "@"; query and fragment never count.
		{"postgres://admin:S3cr@t!@db.example.com:5432/app", AssetTypeDatabase, "db.example.com:5432/app"},
		{"mysql://db1.example.com/app?user=svc@corp.example", AssetTypeDatabase, "db1.example.com/app"},
		{"mysql://db2.example.com/x?user=svc@corp.example", AssetTypeDatabase, "db2.example.com/x"},
		{"mongodb://u:p@DB.example.com/x#frag@y", AssetTypeDatabase, "db.example.com/x"},
		// Repository: one pass to the canonical form.
		{"github.com/org/repo.git/", AssetTypeRepository, "github.com/org/repo"},
		{"https://github.com/Org/Repo/", AssetTypeRepository, "github.com/org/repo"},
		{"ssh://git@github.com/org/repo.git", AssetTypeRepository, "github.com/org/repo"},
		{"ssh://git@gitlab.example.com:2222/group/proj.git", AssetTypeRepository, "gitlab.example.com/group/proj"},
		// Host: a bracketed IPv6 address, with or without a port.
		{"[2001:DB8::1]", AssetTypeHost, "2001:db8::1"},
		{"[2001:db8:0::1]:443", AssetTypeHost, "2001:db8::1"},
		// URL: the DNS root dot and IPv6 spelling do not make a new origin.
		{"https://Example.com./login", AssetTypeApplication, "https://example.com/login"},
		{"https://example.com.:443/", AssetTypeApplication, "https://example.com"},
		{"https://[2001:DB8:0::1]:8443/x", AssetTypeApplication, "https://[2001:db8::1]:8443/x"},
	}
	for _, c := range cases {
		got := NormalizeName(c.name, c.typ, "")
		if got != c.want {
			t.Errorf("NormalizeName(%q, %s) = %q, want %q", c.name, c.typ, got, c.want)
		}
		if again := NormalizeName(got, c.typ, ""); again != got {
			t.Errorf("not idempotent: %q -> %q -> %q", c.name, got, again)
		}
	}
}

func TestNormalizeDatabase_NoPasswordInName(t *testing.T) {
	for _, in := range []string{
		"postgres://admin:S3cr@t!@db.example.com:5432/app",
		"postgres://admin:p@ss@word@db.example.com/app",
		"redis://:hunter2@cache.example.com:6379",
	} {
		got := NormalizeName(in, AssetTypeDatabase, "")
		for _, secret := range []string{"s3cr", "t!", "p@ss", "word@", "hunter2", "admin"} {
			if strings.Contains(got, secret) {
				t.Errorf("NormalizeName(%q) = %q keeps %q of the credentials", in, got, secret)
			}
		}
	}
}
