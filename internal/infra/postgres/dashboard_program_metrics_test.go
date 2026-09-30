package postgres

import (
	"math"
	"testing"
)

func TestAcceptanceRate(t *testing.T) {
	if got := acceptanceRate(0, 0); got != nil {
		t.Fatalf("nothing decided: want nil (not measured), got %v", *got)
	}
	cases := []struct {
		accepted, missed int
		want             float64
	}{
		{0, 3, 0},
		{3, 0, 100},
		{3, 1, 75},
		{1, 2, 100.0 / 3},
	}
	for _, c := range cases {
		got := acceptanceRate(c.accepted, c.missed)
		if got == nil || math.Abs(*got-c.want) > 1e-9 {
			t.Fatalf("acceptanceRate(%d, %d): want %v, got %v", c.accepted, c.missed, c.want, got)
		}
	}
}
