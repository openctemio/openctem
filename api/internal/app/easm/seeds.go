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
//     are refused, so a seed cannot claim other organizations' names;
//   - a seed authorizes active (T1) probes of every name at or under it and
//     confirms them into the inventory, so adding one widens scope. A NEW
//     seed is therefore created as the scope entry "*.<domain>" through the
//     scope entry path (scope.Service.CreateTarget, RFC-054 §6.1): it needs
//     attack_surface:scope:approve, step-up, the organization's approval
//     count and the platform guardrails, notifies every administrator and is
//     audited as a scope entry. A member cannot add one; members request
//     one-off entries instead. Existing seed rows keep working until they
//     are folded into scope entries.

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/pkg/domain/easmseed"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
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

// SeedEntries creates scope entries through the guarded widening path
// (*scope.Service).
type SeedEntries interface {
	CreateTarget(ctx context.Context, input scope.CreateTargetInput) (*scopedom.Target, error)
}

// SeedService manages seeds.
type SeedService struct {
	store    SeedStore
	verified VerifiedDomains
	entries  SeedEntries
}

// SetEntries wires the scope entry path new seeds are created through.
// Without it adding a seed is refused (fail closed).
func (s *SeedService) SetEntries(e SeedEntries) { s.entries = e }

// NewSeedService creates the service. A nil verifier reports every seed
// unverified.
func NewSeedService(store SeedStore, verified VerifiedDomains) *SeedService {
	return &SeedService{store: store, verified: verified}
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
	// Actor is the caller and whether they hold
	// attack_surface:scope:approve. Adding a seed is never a system change.
	Actor scope.Actor
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

// Create validates a new root-domain seed and adds it as the permanent scope
// entry "*.<domain>" through the scope entry path: approvers only, with
// step-up, the organization's approval count (the entry may be pending),
// the platform guardrails and an administrator notification. Discovery runs
// from the entry once it is in effect.
func (s *SeedService) Create(ctx context.Context, tenantID shared.ID, in CreateSeedInput) (*scopedom.Target, error) {
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
	if in.DiscoveryEnabled != nil && !*in.DiscoveryEnabled {
		return nil, fmt.Errorf("%w: a new seed always discovers; to authorize the domain without discovery, add it as a scope entry", shared.ErrValidation)
	}
	// A seed widens scope: approvers only, and never a system change.
	if in.Actor.UserID == "" || !in.Actor.CanApprove {
		return nil, ErrSeedNeedsApprover
	}
	if s.entries == nil {
		return nil, fmt.Errorf("seeds are scope entries and the scope entry path is not configured; nothing added")
	}
	// A root domain at or under one of the tenant's existing seeds adds
	// nothing: it is already covered (research/22 P0-13, 22c B9).
	existing, err := s.store.ListSeeds(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	for _, e := range existing {
		if e.Kind != easmseed.KindRootDomain {
			continue
		}
		if e.Value == value {
			return nil, fmt.Errorf("%w: the seed %s already exists", shared.ErrConflict, value)
		}
		if strings.HasSuffix(value, "."+e.Value) {
			return nil, fmt.Errorf("%w: %s is already covered by the seed %s", shared.ErrValidation, value, e.Value)
		}
	}
	return s.entries.CreateTarget(ctx, scope.CreateTargetInput{
		TenantID:    tenantID.String(),
		TargetType:  string(scopedom.TargetTypeDomain),
		Pattern:     "*." + value,
		Description: label,
		Reason:      "Root-domain seed " + value + ": the requester attested that the organization is authorized to have it discovered and checked",
		CreatedBy:   in.Actor.UserID,
		Actor:       in.Actor,
	})
}

// ErrSeedNeedsApprover refuses a seed from a caller without
// attack_surface:scope:approve (403, the scope entry code).
var ErrSeedNeedsApprover = shared.NewDomainError(scope.ErrWideningNeedsApprove.Code,
	"a seed authorizes active checks of every name under it, so only a scope approver can add it; ask an administrator, or request a one-off scope entry for a single name",
	shared.ErrForbidden)

// Update changes a seed's label and discovery switch. turnedOn reports a
// discovery switch that went from off to on, a widening the caller announces
// to the administrators.
func (s *SeedService) Update(ctx context.Context, tenantID, id shared.ID, label *string, discovery *bool) (v *SeedView, turnedOn bool, err error) {
	cur, err := s.find(ctx, tenantID, id)
	if err != nil {
		return nil, false, err
	}
	newLabel, newDiscovery, wasOn := cur.Label, cur.DiscoveryEnabled, cur.DiscoveryEnabled
	if label != nil {
		if newLabel, err = easmseed.CleanLabel(*label); err != nil {
			return nil, false, fmt.Errorf("%w: %s", shared.ErrValidation, strings.TrimPrefix(err.Error(), easmseed.ErrInvalid.Error()+": "))
		}
	}
	if discovery != nil {
		newDiscovery = *discovery
	}
	sd, err := s.store.UpdateSeed(ctx, tenantID, id, newLabel, newDiscovery)
	if err != nil {
		return nil, false, err
	}
	verified, err := s.verifiedNames(ctx, tenantID)
	if err != nil {
		return nil, false, err
	}
	out := view(*sd, verified)
	return &out, newDiscovery && !wasOn, nil
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
