package pagination

import (
	"errors"
	"net/url"
	"testing"
)

func TestFromRequest(t *testing.T) {
	cases := []struct {
		query        string
		page, perPag int
		invalid      bool
	}{
		{"", 1, 25, false},
		{"page=3&per_page=50", 3, 50, false},
		{"per_page=1000", 1, MaxPerPage, false},
		{"page=999999999", 100000, 25, false},
		{"page=0", 0, 0, true},
		{"page=-2", 0, 0, true},
		{"page=2.5", 0, 0, true},
		{"page=0x10", 0, 0, true},
		{"per_page=abc", 0, 0, true},
		{"per_page=0", 0, 0, true},
	}
	for _, c := range cases {
		q, _ := url.ParseQuery(c.query)
		p, err := FromRequest(q, 25)
		if c.invalid {
			if !errors.Is(err, ErrInvalid) {
				t.Errorf("%q: err = %v, want ErrInvalid", c.query, err)
			}
			continue
		}
		if err != nil || p.Page != c.page || p.PerPage != c.perPag {
			t.Errorf("%q: got %+v, %v; want page %d per_page %d", c.query, p, err, c.page, c.perPag)
		}
	}
}

func TestMapKeepsPaging(t *testing.T) {
	r := NewResult([]int{1, 2}, 12, New(2, 2))
	got := Map(r, func(i int) string { return string(rune('a' + i)) })
	if len(got.Data) != 2 || got.Data[0] != "b" || got.Total != 12 || got.Page != 2 || got.PerPage != 2 || got.TotalPages != 6 {
		t.Fatalf("Map = %+v", got)
	}
}
