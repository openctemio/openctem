package config

import (
	"testing"
	"time"
)

func TestDefaultWriteTimeoutAboveRequest(t *testing.T) {
	if got := defaultWriteTimeout(30 * time.Second); got != 35*time.Second {
		t.Fatalf("got %v, want 35s", got)
	}
}

func TestWriteTimeoutBelowRequest(t *testing.T) {
	cases := []struct {
		w, r time.Duration
		want bool
	}{
		{15 * time.Second, 30 * time.Second, true},
		{30 * time.Second, 30 * time.Second, true},
		{35 * time.Second, 30 * time.Second, false},
		{0, 30 * time.Second, false},
	}
	for _, c := range cases {
		s := ServerConfig{WriteTimeout: c.w, RequestTimeout: c.r}
		if s.WriteTimeoutBelowRequest() != c.want {
			t.Errorf("write=%v request=%v want %v", c.w, c.r, c.want)
		}
	}
}
