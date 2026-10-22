package pagination

import "testing"

func TestSortSQL_AppendsIDTieBreaker(t *testing.T) {
	allowed := map[string]string{"name": "name", "created_at": "created_at", "id": "id"}
	cases := []struct {
		name, sort, idExpr, want string
	}{
		{"single asc", "name", "id", "name ASC, id ASC"},
		{"single desc follows last direction", "-created_at", "id", "created_at DESC, id DESC"},
		{"multi uses last direction", "name,-created_at", "id", "name ASC, created_at DESC, id DESC"},
		{"qualified", "name", "a.id", "name ASC, a.id ASC"},
		{"already sorted by id", "-id", "id", "id DESC"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := NewSortOption(allowed).Parse(c.sort)
			if got := s.SQLWithTieBreaker(c.idExpr); got != c.want {
				t.Fatalf("got %q want %q", got, c.want)
			}
		})
	}
	if got := NewSortOption(allowed).Parse("name").SQL(); got != "name ASC, id ASC" {
		t.Fatalf("SQL() = %q", got)
	}
	if got := NewSortOption(allowed).SQL(); got != "" {
		t.Fatalf("empty sort must stay empty, got %q", got)
	}
	if got := NewSortOption(allowed).SQLWithDefault("x DESC"); got != "x DESC" {
		t.Fatalf("default = %q", got)
	}
	if got := NewSortOption(allowed).Parse("name").SQLWithDefaultAndTieBreaker("x", "a.id"); got != "name ASC, a.id ASC" {
		t.Fatalf("got %q", got)
	}
}
