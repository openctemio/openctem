// Package ssochange models an organization SSO change that a platform
// administrator submitted and that waits for an owner of the organization to
// approve it (RFC-022, owner decision 2026-10-02).
//
// The organization's SAML configuration and OIDC identity providers decide who
// can sign in to it. A platform administrator who could change them directly
// could install their own IdP signing certificate or OIDC client and sign in as
// any member, so the admin console only proposes such a change; an owner
// applies it.
package ssochange

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/identityprovider"
	"github.com/openctemio/openctem/api/pkg/domain/samlprovider"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/verifieddomain"
)

// Kind is what a pending change does.
type Kind string

const (
	// KindSAMLConfig sets (creates or replaces) the organization's SAML config.
	KindSAMLConfig Kind = "saml_config"
	// KindIdPCreate adds an OIDC identity provider.
	KindIdPCreate Kind = "idp_create"
	// KindIdPUpdate changes an existing OIDC identity provider.
	KindIdPUpdate Kind = "idp_update"
	// KindDomainJIT raises a verified domain's just-in-time provisioning
	// (admits newcomers, or gives them a higher role) (RFC-058).
	KindDomainJIT Kind = "domain_jit"
)

// Status is where a change is in its lifecycle.
type Status string

const (
	StatusPending    Status = "pending"
	StatusApproved   Status = "approved"
	StatusRejected   Status = "rejected"
	StatusExpired    Status = "expired"
	StatusSuperseded Status = "superseded"
)

// DefaultTTL is how long a change waits for an owner before it expires.
const DefaultTTL = 7 * 24 * time.Hour

var (
	// ErrNotFound: no such change in this organization.
	ErrNotFound = errors.New("sso change not found")
	// ErrNotPending: the change was already approved, rejected or superseded.
	ErrNotPending = errors.New("sso change is no longer pending")
	// ErrExpired: the change waited longer than its TTL.
	ErrExpired = errors.New("sso change has expired")
	// ErrNotOwner: the caller is not an active owner of the organization.
	ErrNotOwner = errors.New("only an owner of the organization can decide an sso change")
)

// Change is one submitted SSO change.
type Change struct {
	ID       shared.ID
	TenantID shared.ID
	Kind     Kind
	// TargetID is the identity provider an idp_update changes.
	TargetID string
	// Payload is the submitted configuration, never containing a secret.
	Payload json.RawMessage
	// SecretEncrypted is the encrypted OIDC client secret, when one was
	// submitted. It is never returned to a client.
	SecretEncrypted  string
	Status           Status
	RequestedByAdmin *shared.ID
	RequestedByEmail string
	CreatedAt        time.Time
	ExpiresAt        time.Time
	DecidedAt        *time.Time
	DecidedBy        *shared.ID
}

// IsExpired reports whether a pending change is past its expiry at now.
func (c *Change) IsExpired(now time.Time) bool {
	return !now.Before(c.ExpiresAt)
}

// EffectiveStatus is the status a client should see: a pending change past its
// expiry reads as expired even before the row is swept.
func (c *Change) EffectiveStatus(now time.Time) Status {
	if c.Status == StatusPending && c.IsExpired(now) {
		return StatusExpired
	}
	return c.Status
}

// OwnerContact is an active owner of an organization, who is told about a
// pending change and may decide it.
type OwnerContact struct {
	UserID shared.ID
	Email  string
	Name   string
}

// LiveWrite is the live-config write an approval performs. Exactly one field
// is set.
type LiveWrite struct {
	SAML      *samlprovider.SAMLProvider
	IdPCreate *identityprovider.IdentityProvider
	IdPUpdate *identityprovider.IdentityProvider
	DomainJIT *verifieddomain.VerifiedDomain
}

// Repository persists pending changes.
type Repository interface {
	// Create stores c and marks any earlier pending change for the same
	// organization, kind and target as superseded, in one transaction.
	Create(ctx context.Context, c *Change) error
	// Get returns one change of the organization.
	Get(ctx context.Context, tenantID, id shared.ID) (*Change, error)
	// List returns the organization's changes, newest first. When
	// pendingOnly is set it returns only changes that are pending and not
	// expired.
	List(ctx context.Context, tenantID shared.ID, pendingOnly bool, limit int) ([]*Change, error)
	// Approve marks the change approved by decidedBy and performs write, in
	// one transaction. It returns ErrNotFound, ErrExpired or ErrNotPending
	// (and writes nothing) when the change cannot be approved.
	Approve(ctx context.Context, tenantID, id, decidedBy shared.ID, write LiveWrite) error
	// Reject marks the change rejected by decidedBy. Same errors as Approve.
	Reject(ctx context.Context, tenantID, id, decidedBy shared.ID) error
}
