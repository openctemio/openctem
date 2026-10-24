package ingest

// Versioned per-tenant policy snapshots (docs/rfcs/RFC-122-ingest-receipts.md,
// "Dispositions").
//
// Every write to a policy table ingest applies (suppression rules, scope
// exclusions) bumps the tenant's ingest_policy_versions row in the same
// statement (trigger). Ingest reads the version (one indexed row) and reuses
// its in-memory snapshot of the policies while the version is unchanged.
// The snapshot is loaded before anything is written: a snapshot that cannot
// load fails the ingest, which the worker retries. Ingest never proceeds
// without its policies (the suppression lookup used to fail open). Rules
// whose time runs out while cached stop matching on their own
// (suppression.Rule.Matches re-checks expiry).

import (
	"context"
	"fmt"
	"sync"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/suppression"
)

// PolicyVersionReader reads a tenant's ingest policy version
// (postgres.IngestPolicyVersions); 0 when no policy was ever written.
type PolicyVersionReader interface {
	PolicyVersion(ctx context.Context, tenantID shared.ID) (int64, error)
}

// PolicySnapshot is the policies one ingest applies, at one version.
type PolicySnapshot struct {
	Version     int64
	Suppression []*suppression.Rule
	// loaded: the suppression rules were read (a checker is wired).
	loaded bool
}

// maxPolicySnapshots bounds the cached snapshots (one per tenant).
const maxPolicySnapshots = 10_000

type policyCache struct {
	mu sync.Mutex
	m  map[shared.ID]*PolicySnapshot
}

// SetPolicyVersions enables the snapshot cache: without it the policies are
// read on every ingest (still before anything is written).
func (s *Service) SetPolicyVersions(r PolicyVersionReader) { s.policyVersions = r }

// loadPolicySnapshot returns the tenant's policy snapshot, from the cache
// while its version is current. An error means ingest must not proceed.
func (s *Service) loadPolicySnapshot(ctx context.Context, tenantID shared.ID) (*PolicySnapshot, error) {
	var version int64
	if s.policyVersions != nil {
		v, err := s.policyVersions.PolicyVersion(ctx, tenantID)
		if err != nil {
			return nil, fmt.Errorf("read the ingest policy version: %w", err)
		}
		version = v
		s.policies.mu.Lock()
		cached := s.policies.m[tenantID]
		s.policies.mu.Unlock()
		if cached != nil && cached.Version == version {
			return cached, nil
		}
	}
	snap := &PolicySnapshot{Version: version}
	if checker := s.findingProcessor.suppressionChecker; checker != nil {
		rules, err := checker.ListActiveRules(ctx, tenantID)
		if err != nil {
			return nil, fmt.Errorf("load the suppression rules: %w", err)
		}
		snap.Suppression, snap.loaded = rules, true
	}
	if s.policyVersions != nil {
		s.policies.mu.Lock()
		if s.policies.m == nil || len(s.policies.m) >= maxPolicySnapshots {
			s.policies.m = map[shared.ID]*PolicySnapshot{}
		}
		s.policies.m[tenantID] = snap
		s.policies.mu.Unlock()
	}
	return snap, nil
}
