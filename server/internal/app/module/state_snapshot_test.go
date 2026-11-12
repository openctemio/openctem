package module

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	moduledom "github.com/openctemio/openctem/server/pkg/domain/module"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// dlEntitlements is an entitlement reader that also reports its next change.
type dlEntitlements struct {
	fakeEntitlements
	next *time.Time
}

func (d dlEntitlements) NotEntitledWithDeadline(ctx context.Context, t string) (map[string]*time.Time, *time.Time, error) {
	out, err := d.fakeEntitlements.NotEntitled(ctx, t)
	return out, d.next, err
}

const moduleForTests = moduledom.ModulePentest

func newSnapshotService(e EntitlementReader) *ModuleService {
	s := NewModuleService(&fakeModuleRepo{}, logger.NewNop())
	s.SetTenantModuleRepo(&fakeTenantModuleRepo{})
	s.SetEntitlements(e)
	return s
}

func TestSnapshot_CarriesTheNextChangeOfAGrace(t *testing.T) {
	until := time.Now().Add(time.Hour)
	s := newSnapshotService(dlEntitlements{
		fakeEntitlements: fakeEntitlements{grace: map[string]time.Time{moduleForTests: until}},
		next:             &until,
	})
	states, validUntil, cacheable := s.TenantModuleStateSnapshot(context.Background(), tid)
	if states[moduleForTests] != ReasonReadOnlyGrace || !cacheable || !validUntil.Equal(until) {
		t.Fatalf("states=%v validUntil=%v cacheable=%v", states, validUntil, cacheable)
	}
}

// A failed entitlement read is reported unavailable and uncacheable.
func TestSnapshot_FailedReadIsNotCacheable(t *testing.T) {
	s := newSnapshotService(fakeEntitlements{err: errors.New("db down")})
	states, _, cacheable := s.TenantModuleStateSnapshot(context.Background(), tid)
	if cacheable {
		t.Fatal("a failed read must not be cacheable")
	}
	if states[moduleForTests] != ReasonUnavailable {
		t.Fatalf("a failed read must fail closed, got %q", states[moduleForTests])
	}
}

// With no switches off and no entitlement problem the state is cacheable and
// open-ended.
func TestSnapshot_HealthyStateIsCacheable(t *testing.T) {
	s := newSnapshotService(fakeEntitlements{})
	states, validUntil, cacheable := s.TenantModuleStateSnapshot(context.Background(), tid)
	if len(states) != 0 || !validUntil.IsZero() || !cacheable {
		t.Fatalf("states=%v validUntil=%v cacheable=%v", states, validUntil, cacheable)
	}
}

// The ETag changes when the state changes with no write (a grace ends), when
// a failed read recovers, and it never repeats after the counter is lost.
func TestETagToken_FollowsTheStateNotOnlyTheCounter(t *testing.T) {
	ctx := context.Background()
	healthy := newSnapshotService(fakeEntitlements{}).ETagToken(ctx, tid)

	grace := newSnapshotService(fakeEntitlements{grace: map[string]time.Time{moduleForTests: time.Now().Add(time.Hour)}}).ETagToken(ctx, tid)
	ended := newSnapshotService(fakeEntitlements{off: map[string]bool{moduleForTests: true}}).ETagToken(ctx, tid)
	failed := newSnapshotService(fakeEntitlements{err: errors.New("down")}).ETagToken(ctx, tid)
	recovered := newSnapshotService(fakeEntitlements{}).ETagToken(ctx, tid)

	seen := map[string]string{"healthy": healthy, "grace": grace, "ended": ended, "failed": failed}
	for a, ta := range seen {
		for b, tb := range seen {
			if a < b && ta == tb {
				t.Fatalf("the ETag of %q and %q is the same (%s): a client would keep a stale payload", a, b, ta)
			}
		}
	}
	if recovered != healthy {
		t.Fatalf("an unchanged state must keep its ETag: %s vs %s", recovered, healthy)
	}
	// No counter (Redis flushed or down): reads 0, never a counter value.
	if !strings.HasPrefix(healthy, "v0.") {
		t.Fatalf("a missing counter must read as version 0, got %s", healthy)
	}
	// The token carries no module id.
	if strings.Contains(ended, moduleForTests) {
		t.Fatal("the ETag leaks a module id")
	}
}
