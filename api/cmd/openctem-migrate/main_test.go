package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCleanURL(t *testing.T) {
	got, err := cleanURL("postgresql://u@h:5432/db?sslmode=require&x-multi-statement=true&x-migrations-table=foo")
	if err != nil {
		t.Fatal(err)
	}
	if got != "postgres://u@h:5432/db?sslmode=require" {
		t.Fatalf("cleanURL = %q", got)
	}
	for _, bad := range []string{"mysql://u:secret@h/db", "://u:secret@h", "file:///etc/passwd"} {
		_, err := cleanURL(bad)
		if err == nil {
			t.Fatalf("cleanURL(%q) accepted it", bad)
		}
		if strings.Contains(err.Error(), "secret") {
			t.Fatalf("the error repeats the URL's password: %v", err)
		}
	}
}

func TestRunArguments(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "000001_a.up.sql"), []byte("SELECT 1;"), 0o600); err != nil {
		t.Fatal(err)
	}
	dup := t.TempDir()
	for _, f := range []string{"000001_a.up.sql", "000001_b.up.sql"} {
		if err := os.WriteFile(filepath.Join(dup, f), []byte("SELECT 1;"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	db := "postgres://u:hunter2@127.0.0.1:1/db?sslmode=disable"
	cases := []struct {
		name string
		args []string
		code int
		want string
	}{
		{"help", []string{"-help"}, 0, "usage: openctem-migrate"},
		{"no command", []string{"-path", dir, "-database", db}, 2, "usage"},
		{"no database", []string{"-path", dir, "up"}, 2, "usage"},
		{"unknown command", []string{"-path", dir, "-database", db, "drop"}, 1, `unknown command "drop"`},
		{"down without a count", []string{"-path", dir, "-database", db, "down"}, 1, "down needs the number"},
		{"down with a bad count", []string{"-path", dir, "-database", db, "down", "-all"}, 1, "not a positive number"},
		{"force with a bad version", []string{"-path", dir, "-database", db, "force", "0"}, 1, "not a migration version"},
		{"duplicate versions refused before connecting", []string{"-path", dup, "-database", db, "up"}, 1, "used twice"},
		{"source flag", []string{"-source", "file://" + dup, "-database", db, "up"}, 1, "used twice"},
		{"bad scheme", []string{"-path", dir, "-database", "mysql://u:hunter2@h/db", "up"}, 1, "postgres://"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			code := run(context.Background(), tc.args, &out, &errOut)
			if code != tc.code {
				t.Fatalf("exit %d, want %d (stderr %q)", code, tc.code, errOut.String())
			}
			all := out.String() + errOut.String()
			if !strings.Contains(all, tc.want) {
				t.Fatalf("output %q does not contain %q", all, tc.want)
			}
			if strings.Contains(all, "hunter2") {
				t.Fatalf("the output repeats the password: %q", all)
			}
		})
	}
}
