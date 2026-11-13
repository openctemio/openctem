package scm

import "testing"

func TestLastPageFromLinkHeader(t *testing.T) {
	cases := []struct {
		name string
		hdr  string
		want int
	}{
		{"empty", "", 0},
		{"no last rel", `<https://api.github.com/user/repos?page=2>; rel="next"`, 0},
		{
			"next and last",
			`<https://api.github.com/user/repos?page=2&per_page=30>; rel="next", <https://api.github.com/user/repos?page=5&per_page=30>; rel="last"`,
			5,
		},
		{
			"prev and last",
			`<https://api.github.com/user/repos?page=1>; rel="prev", <https://api.github.com/user/repos?page=12>; rel="last"`,
			12,
		},
		{"malformed", `garbage; rel="last"`, 0},
		{"missing page param", `<https://api.github.com/user/repos>; rel="last"`, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := lastPageFromLinkHeader(tc.hdr); got != tc.want {
				t.Errorf("lastPageFromLinkHeader(%q) = %d, want %d", tc.hdr, got, tc.want)
			}
		})
	}
}
