package handler

import (
	"testing"
	"time"
)

func TestTenantRateLimiter_RefillsAndRetryAfter(t *testing.T) {
	l := newTenantRateLimiter(6, 6)
	now := time.Now()
	for i := range 6 {
		if ok, _ := l.allow("t1", now); !ok {
			t.Fatalf("call %d refused", i+1)
		}
	}
	ok, retry := l.allow("t1", now)
	if ok || retry < 1 || retry > 10 {
		t.Fatalf("7th call = %v, retry %d; want refused with 1..10 s", ok, retry)
	}
	// A refused call takes no token: one is back after 10 seconds.
	if ok, _ := l.allow("t1", now.Add(10*time.Second)); !ok {
		t.Fatal("no token after 10 seconds")
	}
	if ok, _ := l.allow("t2", now); !ok {
		t.Fatal("another tenant was limited")
	}
}
