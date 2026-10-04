package easm

// EASM seeds (RFC-036 §5.1, §6.3; GET/POST/PATCH/DELETE /api/v1/easm/seeds).
//
// Security:
//   - every read and write is tenant-scoped in the store, and the tenant
//     comes from the caller's token, never the request;
//   - two tenants may seed the same domain; nothing about another tenant's
//     seed or verification is ever revealed (no "already claimed");
//   - verification is computed from the tenant's own verified_domains rows,
//     never accepted from the client;
//   - a seed's value is normalized and validated per kind
//     (pkg/domain/easmseed): public suffixes and providers' shared domains
//     are refused, so a seed cannot claim other organizations' names.

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/easmseed"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// SeedStore persists seeds. Tenant-scoped.
type SeedStore interface {
	ListSeeds(ctx context.Context, tenantID shared.ID) ([]easmseed.Seed, error)
	CountSeeds(ctx context.Context, tenantID shared.ID) (int, error)
	// CreateSeed inserts the seed; shared.ErrConflict when the tenant
	// already has the same (kind, value).
	CreateSeed(ctx context.Context, s easmseed.Seed) error
	// UpdateSeed changes label and discovery_enabled; shared.ErrNotFound
	// when the seed is not the tenant's.
	UpdateSeed(ctx context.Context, tenantID, id shared.ID, label string, discovery bool) (*easmseed.Seed, error)
	// DeleteSeed removes it; shared.ErrNotFound when it is not the tenant's.
	DeleteSeed(ctx context.Context, tenantID, id shared.ID) (*easmseed.Seed, error)
}

// VerifiedDomains lists the tenant's verified domain names (status verified).
type VerifiedDomains interface {
	VerifiedDomainNames(ctx context.Context, tenantID shared.ID) ([]string, error)
}

// SeedService manages seeds.
type SeedService struct {
	store    SeedStore
	verified VerifiedDomains
	now      func() time.Time
}

// NewSeedService creates the service. A nil verifier reports every seed
// unverified.
func NewSeedService(store SeedStore, verified VerifiedDomains) *SeedService {
	return &SeedService{store: store, verified: verified, now: func() time.Time { return time.Now().UTC() }}
}

// SeedView is a seed with its computed verification.
type SeedView struct {
	ID               string `json:"id"`
	Kind             string `json:"kind"`
	Value            string `json:"value"`
	Label            string `json:"label,omitempty"`
	DiscoveryEnabled bool   `json:"discovery_enabled"`
	// Verification: dns_txt when the organization proved control of the
	// domain (or a parent) with a DNS TXT record; none otherwise.
	Verification string     `json:"verification"`
	VerifiedBy   string     `json:"verified_domain,omitempty"`
	AttestedBy   string     `json:"attested_by,omitempty"`
	AttestedAt   time.Time  `json:"attested_at"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    *time.Time `json:"updated_at,omitempty"`
}

// Verification values.
const (
	VerificationNone   = "none"
	VerificationDNSTXT = "dns_txt"
)

// CreateSeedInput is a new seed.
type CreateSeedInput struct {
	Kind             string
	Value            string
	Label            string
	DiscoveryEnabled *bool
	// Attested must be true: the caller states the organization is
	// authorized to have this seed discovered and checked.
	Attested bool
	ActorID  string
}

// List returns the tenant's seeds, sorted by kind then value.
func (s *SeedService) List(ctx context.Context, tenantID shared.ID) ([]SeedView, error) {
	seeds, err := s.store.ListSeeds(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	verified, err := s.verifiedNames(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := make([]SeedView, 0, len(seeds))
	for _, sd := range seeds {
		out = append(out, view(sd, verified))
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Value < out[j].Value
	})
	return out, nil
}

// Create validates and stores a seed.
func (s *SeedService) Create(ctx context.Context, tenantID shared.ID, in CreateSeedInput) (*SeedView, error) {
	if !in.Attested {
		return nil, fmt.Errorf("%w: confirm that the organization is authorized to have this seed discovered (attested)", shared.ErrValidation)
	}
	kind := easmseed.Kind(strings.TrimSpace(in.Kind))
	value, err := easmseed.Normalize(kind, in.Value)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", shared.ErrValidation, strings.TrimPrefix(err.Error(), easmseed.ErrInvalid.Error()+": "))
	}
	label, err := easmseed.CleanLabel(in.Label)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", shared.ErrValidation, strings.TrimPrefix(err.Error(), easmseed.ErrInvalid.Error()+": "))
	}
	n, err := s.store.CountSeeds(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if n >= easmseed.MaxPerTenant {
		return nil, fmt.Errorf("%w: at most %d seeds per organization", shared.ErrValidation, easmseed.MaxPerTenant)
	}
	discovery := true
	if in.DiscoveryEnabled != nil {
		discovery = *in.DiscoveryEnabled
	}
	now := s.now()
	sd := easmseed.Seed{
		ID: shared.NewID(), TenantID: tenantID, Kind: kind, Value: value, Label: label,
		DiscoveryEnabled: discovery, AttestedAt: now, CreatedAt: now, UpdatedAt: now,
	}
	if actor, err := shared.IDFromString(in.ActorID); err == nil {
		sd.AttestedBy, sd.CreatedBy = &actor, &actor
	}
	if err := s.store.CreateSeed(ctx, sd); err != nil {
		return nil, err
	}
	verified, err := s.verifiedNames(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	v := view(sd, verified)
	return &v, nil
}

// Update changes a seed's label and discovery switch.
func (s *SeedService) Update(ctx context.Context, tenantID, id shared.ID, label *string, discovery *bool) (*SeedView, error) {
	cur, err := s.find(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	newLabel, newDiscovery := cur.Label, cur.DiscoveryEnabled
	if label != nil {
		if newLabel, err = easmseed.CleanLabel(*label); err != nil {
			return nil, fmt.Errorf("%w: %s", shared.ErrValidation, strings.TrimPrefix(err.Error(), easmseed.ErrInvalid.Error()+": "))
		}
	}
	if discovery != nil {
		newDiscovery = *discovery
	}
	sd, err := s.store.UpdateSeed(ctx, tenantID, id, newLabel, newDiscovery)
	if err != nil {
		return nil, err
	}
	verified, err := s.verifiedNames(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	v := view(*sd, verified)
	return &v, nil
}

// Delete removes a seed and returns it (for the audit record).
func (s *SeedService) Delete(ctx context.Context, tenantID, id shared.ID) (*easmseed.Seed, error) {
	return s.store.DeleteSeed(ctx, tenantID, id)
}

func (s *SeedService) find(ctx context.Context, tenantID, id shared.ID) (*easmseed.Seed, error) {
	seeds, err := s.store.ListSeeds(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	for i := range seeds {
		if seeds[i].ID == id {
			return &seeds[i], nil
		}
	}
	return nil, shared.ErrNotFound
}

func (s *SeedService) verifiedNames(ctx context.Context, tenantID shared.ID) ([]string, error) {
	if s.verified == nil {
		return nil, nil
	}
	names, err := s.verified.VerifiedDomainNames(ctx, tenantID)
	if err != nil && !errors.Is(err, shared.ErrNotFound) {
		return nil, fmt.Errorf("list verified domains: %w", err)
	}
	return names, nil
}

func view(sd easmseed.Seed, verified []string) SeedView {
	v := SeedView{
		ID: sd.ID.String(), Kind: string(sd.Kind), Value: sd.Value, Label: sd.Label,
		DiscoveryEnabled: sd.DiscoveryEnabled, Verification: VerificationNone,
		AttestedAt: sd.AttestedAt, CreatedAt: sd.CreatedAt,
	}
	if sd.AttestedBy != nil {
		v.AttestedBy = sd.AttestedBy.String()
	}
	if !sd.UpdatedAt.IsZero() {
		u := sd.UpdatedAt
		v.UpdatedAt = &u
	}
	if sd.Kind == easmseed.KindRootDomain {
		for _, d := range verified {
			if easmseed.CoversName(strings.ToLower(strings.TrimSuffix(d, ".")), sd.Value) {
				v.Verification, v.VerifiedBy = VerificationDNSTXT, d
				break
			}
		}
	}
	return v
}
