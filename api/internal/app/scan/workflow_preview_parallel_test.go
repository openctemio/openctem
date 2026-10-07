package scan

import "testing"

func TestMaxParallelSensors(t *testing.T) {
	for _, c := range []struct{ chunk, online, want int }{
		{200, 3, 3}, // chunked: every online sensor takes a share
		{0, 3, 1},   // one command: one sensor
		{200, 0, 0}, // nobody can run it
		{0, 0, 0},
	} {
		if got := maxParallelSensors(c.chunk, c.online); got != c.want {
			t.Errorf("maxParallelSensors(%d, %d) = %d, want %d", c.chunk, c.online, got, c.want)
		}
	}
}
