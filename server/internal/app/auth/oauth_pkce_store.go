package auth

import (
	"context"
	"sync"
	"time"
)

// PKCEVerifierStore keeps an OAuth PKCE code_verifier on the server between
// the authorize redirect and the callback, keyed by the state it was issued
// with. GetDel is single use: it returns and deletes the entry, so a state
// (and its verifier) can complete at most one login.
//
// The verifier must never travel in the state: the state goes through the
// browser, the identity provider and any log or Referer on the way, so
// whoever intercepts the authorization code would hold the verifier as well
// and PKCE would protect nothing.
//
// The method set matches internal/infra/redis.Client, which production wires
// directly (keys carry a TTL and GETDEL is atomic across replicas).
type PKCEVerifierStore interface {
	Set(ctx context.Context, key, verifier string, ttl time.Duration) error
	GetDel(ctx context.Context, key string) (verifier string, ok bool, err error)
}

// MemoryPKCEStore is an in-process PKCEVerifierStore. It is correct only
// for a single API replica; production wires the Redis store.
type MemoryPKCEStore struct {
	mu      sync.Mutex
	entries map[string]memoryPKCEEntry
}

type memoryPKCEEntry struct {
	verifier string
	expires  time.Time
}

// NewMemoryPKCEStore creates an empty in-process store.
func NewMemoryPKCEStore() *MemoryPKCEStore {
	return &MemoryPKCEStore{entries: make(map[string]memoryPKCEEntry)}
}

// Set stores verifier under key until ttl elapses.
func (m *MemoryPKCEStore) Set(_ context.Context, key, verifier string, ttl time.Duration) error {
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, e := range m.entries {
		if now.After(e.expires) {
			delete(m.entries, k)
		}
	}
	m.entries[key] = memoryPKCEEntry{verifier: verifier, expires: now.Add(ttl)}
	return nil
}

// GetDel returns and removes the verifier stored under key.
func (m *MemoryPKCEStore) GetDel(_ context.Context, key string) (string, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.entries[key]
	if !ok {
		return "", false, nil
	}
	delete(m.entries, key)
	if time.Now().After(e.expires) {
		return "", false, nil
	}
	return e.verifier, true, nil
}
