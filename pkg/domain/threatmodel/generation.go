package threatmodel

import (
	"context"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// The types and ports in this file are the read-side contracts the generation
// service (internal/app/threatmodel) consumes. They live in the domain package
// so the infrastructure adapters (postgres) implement them without importing the
// application layer, and the pure generation logic can be unit-tested against
// small neutral value types rather than the full finding/attacker aggregates.

// Network-access and credential capability levels, ordered weakest→strongest.
// An attacker satisfies a technique's minimum requirement when its own level
// rank is >= the required rank. Empty ("") means "no requirement".
const (
	NetworkExternal = "external"
	NetworkInternal = "internal"
	NetworkPhysical = "physical"

	CredentialNone  = "none"
	CredentialUser  = "user"
	CredentialAdmin = "admin"
)

// AttackerCapabilities is the capability gate an attacker profile brings to the
// generation pipeline. It mirrors attackerprofile.Capabilities but is a neutral
// value type so the pure applicability logic has no dependency on that aggregate.
type AttackerCapabilities struct {
	NetworkAccess   string // external|internal|physical ("" treated as external)
	CredentialLevel string // none|user|admin ("" treated as none)
	Persistence     bool
}

// NetworkRank ranks a network-access level. Unknown/empty ranks as external (1).
func NetworkRank(level string) int {
	switch level {
	case NetworkInternal:
		return 2
	case NetworkPhysical:
		return 3
	default:
		// external or unknown — the weakest position (internet-only).
		return 1
	}
}

// CredentialRank ranks a credential level. Unknown/empty ranks as none (0).
func CredentialRank(level string) int {
	switch level {
	case CredentialUser:
		return 1
	case CredentialAdmin:
		return 2
	default:
		return 0
	}
}

// AttackerProfileFact is a neutral projection of an attacker profile used as a
// generation input (id + capability gate).
type AttackerProfileFact struct {
	ID           shared.ID
	Name         string
	ProfileType  string
	Capabilities AttackerCapabilities
	IsDefault    bool
}

// FindingFact is a neutral projection of a finding used to derive threat status.
// Only the columns the status rules need are carried.
type FindingFact struct {
	ID                  shared.ID
	AssetID             shared.ID
	TechniqueID         string   // findings.mitre_technique_id ("" when unmapped)
	CWEIDs              []string // findings.cwe_ids
	Category            string   // findings.finding_type (vulnerability/secret/…)
	Status              string   // findings.status
	AcceptanceExpiresAt *time.Time
}

// AttackerProfileReader loads the tenant's attacker profiles (capability gates).
type AttackerProfileReader interface {
	// ListAttackerProfiles returns every attacker profile for the tenant, default
	// profiles first. An empty result is valid (the caller falls back to a single
	// synthetic external-unauth profile).
	ListAttackerProfiles(ctx context.Context, tenantID shared.ID) ([]AttackerProfileFact, error)
}

// FindingReader loads the findings on a bounded set of assets for status
// derivation. Implementations MUST tenant-scope the query.
type FindingReader interface {
	// ListThreatFindings returns the status-relevant findings for the given assets.
	// assetIDs is bounded by the generation caps (chain targets + hops). An empty
	// assetIDs slice returns no findings without touching the database.
	ListThreatFindings(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID) ([]FindingFact, error)
}
