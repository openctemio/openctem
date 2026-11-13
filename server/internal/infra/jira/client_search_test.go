package jira

import "testing"

func TestSearchJQL(t *testing.T) {
	cases := map[string]string{
		"SEC-42":          `key = "SEC-42"`,
		"sec-42":          `key = "SEC-42"`,
		"login bypass":    `text ~ "login bypass" ORDER BY updated DESC`,
		`a" OR key != "x`: `text ~ "a\" OR key != \"x" ORDER BY updated DESC`,
		`back\slash`:      `text ~ "back\\slash" ORDER BY updated DESC`,
		"line\nbreak":     `text ~ "line break" ORDER BY updated DESC`,
		"":                `ORDER BY updated DESC`,
	}
	for in, want := range cases {
		if got := SearchJQL(in); got != want {
			t.Errorf("SearchJQL(%q) = %q, want %q", in, got, want)
		}
	}
}
