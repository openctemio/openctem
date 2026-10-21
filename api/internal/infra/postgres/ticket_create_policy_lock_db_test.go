package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// One create per finding at a time: the second caller for the same
// (tenant, integration, finding) waits for the first, other findings and
// other tenants are not held up, and a canceled wait gives up cleanly.
func TestTicketCreatePolicy_LockFinding_DB(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	repo := NewTicketCreatePolicyRepository(&DB{DB: db})
	tenant, other := shared.NewID(), shared.NewID()
	intg, finding, otherFinding := shared.NewID(), shared.NewID(), shared.NewID()

	unlock, err := repo.LockFinding(ctx, tenant, intg, finding)
	if err != nil {
		t.Fatal(err)
	}

	// The same finding waits; a canceled wait returns an error.
	wctx, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
	if _, err := repo.LockFinding(wctx, tenant, intg, finding); err == nil {
		t.Fatal("a second lock on the same finding was granted")
	}
	cancel()

	// Other findings and other tenants are free.
	for name, k := range map[string][3]shared.ID{
		"other finding": {tenant, intg, otherFinding},
		"other tenant":  {other, intg, finding},
	} {
		fctx, fcancel := context.WithTimeout(ctx, 2*time.Second)
		u, err := repo.LockFinding(fctx, k[0], k[1], k[2])
		fcancel()
		if err != nil {
			t.Fatalf("%s was blocked: %v", name, err)
		}
		u()
	}

	// A waiter proceeds as soon as the holder unlocks.
	got := make(chan error, 1)
	go func() {
		u, err := repo.LockFinding(ctx, tenant, intg, finding)
		if err == nil {
			u()
		}
		got <- err
	}()
	select {
	case err := <-got:
		t.Fatalf("the waiter did not wait: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	unlock()
	select {
	case err := <-got:
		if err != nil {
			t.Fatalf("waiter after unlock: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the waiter never got the lock after unlock")
	}
}
