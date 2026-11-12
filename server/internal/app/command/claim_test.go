package command

import "testing"

func TestFreeScanSlots(t *testing.T) {
	three := 3
	zero := 0
	cases := []struct {
		name          string
		maxJobs, held int
		reported      *int
		want          int
	}{
		{"limit minus held", 5, 2, nil, 3},
		{"never below zero", 2, 4, nil, 0},
		{"no limit set counts as one", 0, 0, nil, 1},
		{"the smaller of computed and reported", 10, 1, &three, 3},
		{"reported full wins", 10, 1, &zero, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := freeScanSlots(tc.maxJobs, tc.held, tc.reported); got != tc.want {
				t.Fatalf("freeScanSlots(%d, %d, %v) = %d, want %d", tc.maxJobs, tc.held, tc.reported, got, tc.want)
			}
		})
	}
}
