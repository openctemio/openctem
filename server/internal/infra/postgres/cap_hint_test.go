package postgres

import "testing"

func TestCapHintBoundsRequestSizedAllocations(t *testing.T) {
	cases := []struct{ in, want int }{
		{-5, 0}, {0, 0}, {20, 20}, {maxSliceCapHint, maxSliceCapHint},
		{maxSliceCapHint + 1, maxSliceCapHint}, {1 << 40, maxSliceCapHint},
	}
	for _, c := range cases {
		if got := capHint(c.in); got != c.want {
			t.Errorf("capHint(%d) = %d, want %d", c.in, got, c.want)
		}
	}
}
