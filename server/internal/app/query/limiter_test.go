package query

import (
	"errors"
	"sync"
	"testing"
)

func TestLimiter(t *testing.T) {
	l := newLimiter(2, 4, 100)
	r1, err := l.acquire("t1", "u1")
	if err != nil {
		t.Fatal(err)
	}
	r2, _ := l.acquire("t1", "u1")
	if _, err := l.acquire("t1", "u1"); !errors.Is(err, ErrBusy) {
		t.Fatalf("third run of one user: %v", err)
	}
	// Another tenant's user is independent.
	if r, err := l.acquire("t2", "u1"); err != nil {
		t.Fatalf("other tenant: %v", err)
	} else {
		r()
	}
	r3, _ := l.acquire("t1", "u2")
	r4, _ := l.acquire("t1", "u2")
	if _, err := l.acquire("t1", "u3"); !errors.Is(err, ErrBusy) {
		t.Fatalf("fifth run of one tenant: %v", err)
	}
	r1()
	r1() // releasing twice is harmless
	if r, err := l.acquire("t1", "u3"); err != nil {
		t.Fatalf("after release: %v", err)
	} else {
		r()
	}
	r2()
	r3()
	r4()
	if len(l.users) != 0 || len(l.tenants) != 0 {
		t.Fatalf("leaked counters: %v %v", l.users, l.tenants)
	}
}

// Many tenants, each under its own cap, still share the process cap.
func TestLimiterProcessCap(t *testing.T) {
	l := newLimiter(MaxPerUser, MaxPerTenant, 3)
	var rel []func()
	for i, tenant := range []string{"t1", "t2", "t3"} {
		r, err := l.acquire(tenant, "u")
		if err != nil {
			t.Fatalf("tenant %d: %v", i, err)
		}
		rel = append(rel, r)
	}
	if _, err := l.acquire("t4", "u"); !errors.Is(err, ErrBusy) {
		t.Fatalf("over the process cap: %v", err)
	}
	rel[0]()
	if r, err := l.acquire("t4", "u"); err != nil {
		t.Fatalf("after release: %v", err)
	} else {
		r()
	}
	rel[1]()
	rel[2]()
	if l.running != 0 {
		t.Fatalf("running = %d", l.running)
	}
}

func TestLimiterConcurrent(t *testing.T) {
	l := newLimiter(MaxPerUser, MaxPerTenant, MaxPerProcess)
	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if r, err := l.acquire("t", "u"); err == nil {
				r()
			}
		}()
	}
	wg.Wait()
	if len(l.users) != 0 || len(l.tenants) != 0 || l.running != 0 {
		t.Fatalf("leaked counters: %v %v", l.users, l.tenants)
	}
}
