package main

import "testing"

func TestReadOnlyURL(t *testing.T) {
	cases := map[string]string{
		"postgres://u:p@h:5432/db?sslmode=disable": "postgres://u:p@h:5432/db?default_transaction_read_only=on&sslmode=disable",
		"host=h dbname=db":                         "host=h dbname=db default_transaction_read_only=on",
	}
	for in, want := range cases {
		if got := readOnlyURL(in); got != want {
			t.Errorf("readOnlyURL(%q) = %q, want %q", in, got, want)
		}
	}
}
