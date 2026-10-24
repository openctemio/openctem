package handler

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestParseMemberUserIDs(t *testing.T) {
	a, b := shared.NewID().String(), shared.NewID().String()
	cases := []struct {
		name string
		raw  string
		want int
		ok   bool
	}{
		{"empty is no filter", "", 0, true},
		{"two ids", a + "," + b, 2, true},
		{"spaces trimmed", a + " , " + b, 2, true},
		{"not a uuid", a + ",x'; DROP TABLE users;--", 0, false},
		{"empty element", a + ",", 0, false},
		{"too many", strings.TrimSuffix(strings.Repeat(a+",", maxMemberUserIDs+1), ","), 0, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			ids, ok := parseMemberUserIDs(w, c.raw)
			if ok != c.ok || len(ids) != c.want {
				t.Fatalf("got %d ids ok=%v (status %d), want %d ok=%v", len(ids), ok, w.Code, c.want, c.ok)
			}
			if !c.ok && w.Code != 400 {
				t.Fatalf("status = %d, want 400", w.Code)
			}
		})
	}
}
