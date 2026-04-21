package auth

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/api/pkg/logger"
)

// F-8: unit tests for the single-use WebSocket ticket service.
//
// The core security guarantee is "exactly-once redemption" — a captured
// ticket cannot be replayed. These tests lock that down + cover the
// malformed/expired/wrong-shape rejection paths.

// memStore is an in-memory stand-in for the Redis-backed store. Its
// GetDel is atomic (holds the mutex for read+delete) so we replicate
// the production semantics faithfully.
type memStore struct {
	mu     sync.Mutex
	values map[string]memEntry
}

type memEntry struct {
	value     string
	expiresAt time.Time
}

func newMemStore() *memStore {
	return &memStore{values: make(map[string]memEntry)}
}

func (m *memStore) Set(_ context.Context, key, value string, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.values[key] = memEntry{value: value, expiresAt: time.Now().Add(ttl)}
	return nil
}

func (m *memStore) GetDel(_ context.Context, key string) (string, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, ok := m.values[key]
	if !ok {
		return "", false, nil
	}
	if time.Now().After(entry.expiresAt) {
		delete(m.values, key)
		return "", false, nil
	}
	delete(m.values, key)
	return entry.value, true, nil
}

func newTestTicketService() (*WSTicketService, *memStore) {
	s := newMemStore()
	return NewWSTicketService(s, 5*time.Second, logger.NewNop()), s
}

func TestWSTicketService_IssueAndRedeem(t *testing.T) {
	svc, _ := newTestTicketService()
	ctx := context.Background()

	ticket, err := svc.IssueTicket(ctx, "user-1", "tenant-A")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if len(ticket) != 64 {
		t.Fatalf("ticket length = %d, want 64 hex chars", len(ticket))
	}

	claims, err := svc.RedeemTicket(ctx, ticket)
	if err != nil {
		t.Fatalf("redeem: %v", err)
	}
	if claims.UserID != "user-1" || claims.TenantID != "tenant-A" {
		t.Fatalf("claims = %+v, want user-1/tenant-A", claims)
	}
}

// SECURITY INVARIANT: a ticket MUST be consumable exactly once.
func TestWSTicketService_DoubleRedeem_Rejects(t *testing.T) {
	svc, _ := newTestTicketService()
	ctx := context.Background()

	ticket, err := svc.IssueTicket(ctx, "user-1", "tenant-A")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	// First redemption succeeds.
	if _, err := svc.RedeemTicket(ctx, ticket); err != nil {
		t.Fatalf("first redeem: %v", err)
	}

	// Second redemption MUST fail — this is the replay-defence.
	_, err = svc.RedeemTicket(ctx, ticket)
	if !errors.Is(err, ErrTicketNotFound) {
		t.Fatalf("second redeem err = %v, want ErrTicketNotFound", err)
	}
}

func TestWSTicketService_WrongLength_Rejects(t *testing.T) {
	svc, _ := newTestTicketService()
	ctx := context.Background()

	cases := []string{
		"",                        // empty
		"too-short",               // below 64 chars
		"12345",                   // way below
		"0123456789abcdef" + "0123456789abcdef" + "0123456789abcdef" + "0123456789abcde", // 63 chars
	}
	for _, c := range cases {
		if _, err := svc.RedeemTicket(ctx, c); !errors.Is(err, ErrTicketNotFound) {
			t.Fatalf("input %q: err = %v, want ErrTicketNotFound", c, err)
		}
	}
}

func TestWSTicketService_NonHex_Rejects(t *testing.T) {
	svc, _ := newTestTicketService()
	ctx := context.Background()

	// 64 chars but not valid hex — must be rejected before any Redis call.
	nonHex := "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
	_, err := svc.RedeemTicket(ctx, nonHex)
	if !errors.Is(err, ErrTicketNotFound) {
		t.Fatalf("err = %v, want ErrTicketNotFound", err)
	}
}

func TestWSTicketService_Expired_Rejects(t *testing.T) {
	// Build a service with a 1ms TTL so we can reliably trigger
	// expiry without sleeping longer than necessary.
	store := newMemStore()
	svc := NewWSTicketService(store, 1*time.Millisecond, logger.NewNop())
	ctx := context.Background()

	ticket, err := svc.IssueTicket(ctx, "user-1", "tenant-A")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	time.Sleep(10 * time.Millisecond)

	_, err = svc.RedeemTicket(ctx, ticket)
	if !errors.Is(err, ErrTicketNotFound) {
		t.Fatalf("err = %v, want ErrTicketNotFound (expired)", err)
	}
}

func TestWSTicketService_EmptyUserOrTenant_Rejects(t *testing.T) {
	svc, _ := newTestTicketService()
	ctx := context.Background()

	if _, err := svc.IssueTicket(ctx, "", "t"); err == nil {
		t.Fatal("empty user should error")
	}
	if _, err := svc.IssueTicket(ctx, "u", ""); err == nil {
		t.Fatal("empty tenant should error")
	}
}

func TestWSTicketService_TTLSeconds(t *testing.T) {
	svc := NewWSTicketService(newMemStore(), 30*time.Second, logger.NewNop())
	if svc.TTLSeconds() != 30 {
		t.Fatalf("TTLSeconds = %d, want 30", svc.TTLSeconds())
	}
}

func TestWSTicketService_TamperedPayload_Rejects(t *testing.T) {
	// Directly inject garbage under a valid-looking key so the shape
	// check passes but JSON unmarshal fails. Redeem must refuse.
	store := newMemStore()
	svc := NewWSTicketService(store, 5*time.Second, logger.NewNop())
	ctx := context.Background()

	// 32 raw bytes -> 64 hex chars, matches the service's expected shape.
	tok := "abcd" + "abcd" + "abcd" + "abcd" + "abcd" + "abcd" + "abcd" + "abcd" +
		"abcd" + "abcd" + "abcd" + "abcd" + "abcd" + "abcd" + "abcd" + "abcd"
	_ = store.Set(ctx, "wsticket:"+tok, "not-json-at-all", 5*time.Second)

	_, err := svc.RedeemTicket(ctx, tok)
	if !errors.Is(err, ErrTicketNotFound) {
		t.Fatalf("err = %v, want ErrTicketNotFound (tampered payload)", err)
	}
}
