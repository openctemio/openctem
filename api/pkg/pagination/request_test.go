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

// A list with its own cap (members, 500) keeps it above MaxPerPage and
// validates exactly like every other list.
func TestFromRequestMax(t *testing.T) {
	q, _ := url.ParseQuery("page=2&per_page=400")
	if p, err := FromRequestMax(q, 100, 500); err != nil || p.Page != 2 || p.PerPage != 400 || p.Offset() != 400 {
		t.Fatalf("got %+v, %v", p, err)
	}
	q, _ = url.ParseQuery("per_page=9000")
	if p, _ := FromRequestMax(q, 100, 500); p.PerPage != 500 {
		t.Fatalf("per_page = %d, want the cap 500", p.PerPage)
	}
	q, _ = url.ParseQuery("page=0")
	if _, err := FromRequestMax(q, 100, 500); !errors.Is(err, ErrInvalid) {
		t.Fatalf("page=0: err = %v, want ErrInvalid", err)
	}
	if p, _ := FromRequestMax(url.Values{}, 100, 500); p.Page != 1 || p.PerPage != 100 {
		t.Fatalf("defaults = %+v", p)
	}
}

func TestMapKeepsPaging(t *testing.T) {
	r := NewResult([]int{1, 2}, 12, New(2, 2))
	got := Map(r, func(i int) string { return string(rune('a' + i)) })
	if len(got.Data) != 2 || got.Data[0] != "b" || got.Total != 12 || got.Page != 2 || got.PerPage != 2 || got.TotalPages != 6 {
		t.Fatalf("Map = %+v", got)
	}
}

// A top-N list reads limit with the same validation: default when missing,
// capped above the maximum, refused when not a positive whole number.
func TestLimitFromRequest(t *testing.T) {
	for _, c := range []struct {
		query   string
		want    int
		invalid bool
	}{
		{"", 50, false},
		{"limit=10", 10, false},
		{"limit=5000", 100, false},
		{"limit=0", 0, true},
		{"limit=-1", 0, true},
		{"limit=ten", 0, true},
	} {
		q, _ := url.ParseQuery(c.query)
		n, err := LimitFromRequest(q, 50, 100)
		if c.invalid {
			if !errors.Is(err, ErrInvalid) {
				t.Errorf("%q: err = %v, want ErrInvalid", c.query, err)
			}
			continue
		}
		if err != nil || n != c.want {
			t.Errorf("%q: %d %v, want %d", c.query, n, err, c.want)
		}
	}
}
