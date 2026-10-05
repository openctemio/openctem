package cirun

import (
	"context"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Errors.
var (
	ErrTrustConfigNotFound = fmt.Errorf("%w: CI trust configuration not found", shared.ErrNotFound)
	ErrRunNotFound         = fmt.Errorf("%w: CI run not found", shared.ErrNotFound)
	ErrPolicyNotFound      = fmt.Errorf("%w: CI gate policy not found", shared.ErrNotFound)
	ErrOverrideNotFound    = fmt.Errorf("%w: CI gate override not found", shared.ErrNotFound)
	ErrPolicyExists        = fmt.Errorf("%w: a gate policy for this scope already exists", shared.ErrConflict)
	ErrTrustConfigExists   = fmt.Errorf("%w: a CI trust configuration with this name already exists", shared.ErrConflict)
)

// Repository persists CI trust, runs, gate policies and overrides. Every
// method but the token and replay lookups is tenant-scoped.
type Repository interface {
	CreateTrustConfig(ctx context.Context, c *TrustConfig) error
	UpdateTrustConfig(ctx context.Context, c *TrustConfig) error
	DeleteTrustConfig(ctx context.Context, tenantID, id shared.ID) error
	GetTrustConfig(ctx context.Context, tenantID, id shared.ID) (*TrustConfig, error)
	ListTrustConfigs(ctx context.Context, tenantID shared.ID) ([]TrustConfig, error)
	// EnabledTrustConfigs returns the tenant's enabled configurations for
	// an issuer.
	EnabledTrustConfigs(ctx context.Context, tenantID shared.ID, issuer string) ([]TrustConfig, error)
	TouchTrustConfig(ctx context.Context, tenantID, id shared.ID, at time.Time) error

	// ClaimJTI records an OIDC token id; false means it was exchanged
	// before (replay). Global, not tenant-scoped: one token, one exchange.
	ClaimJTI(ctx context.Context, issuer, jti string, expiresAt time.Time) (bool, error)
	PurgeExpiredJTIs(ctx context.Context, before time.Time) (int64, error)

	CreateRun(ctx context.Context, r *Run) error
	GetRun(ctx context.Context, tenantID, id shared.ID) (*Run, error)
	// GetRunByTokenHash returns the run whose unexpired upload token hashes
	// to hash. Not tenant-scoped: the token is the credential.
	GetRunByTokenHash(ctx context.Context, hash []byte, now time.Time) (*Run, error)
	// RotateRunToken replaces a running run's upload token (the old one
	// stops working).
	RotateRunToken(ctx context.Context, tenantID, runID shared.ID, hash []byte, expiresAt time.Time) error
	ListRuns(ctx context.Context, tenantID shared.ID, f RunFilter) ([]Run, int, error)
	// RecordRunReport adds the fingerprints a report sighted (capped at
	// MaxRunFindings per run) and counts the report.
	RecordRunReport(ctx context.Context, tenantID, runID shared.ID, fingerprints []string) error
	// RunFindings returns the findings on the run's repository asset whose
	// fingerprints the run recorded.
	RunFindings(ctx context.Context, tenantID, runID, assetID shared.ID) ([]RunFinding, error)
	SaveVerdict(ctx context.Context, tenantID, runID shared.ID, verdict string, detail []byte, at time.Time) error

	ListGatePolicies(ctx context.Context, tenantID shared.ID) ([]GatePolicy, error)
	GetGatePolicy(ctx context.Context, tenantID, id shared.ID) (*GatePolicy, error)
	CreateGatePolicy(ctx context.Context, p *GatePolicy) error
	UpdateGatePolicy(ctx context.Context, p *GatePolicy) error
	DeleteGatePolicy(ctx context.Context, tenantID, id shared.ID) error
	// GatePoliciesFor returns the enabled policies that may apply to a
	// repository asset: its own, those of its business units, the tenant's.
	GatePoliciesFor(ctx context.Context, tenantID, assetID shared.ID) ([]GatePolicy, error)

	CreateOverride(ctx context.Context, o *GateOverride) error
	ListOverrides(ctx context.Context, tenantID shared.ID, assetID *shared.ID, scope *shared.DataScope) ([]GateOverride, error)
	GetOverride(ctx context.Context, tenantID, id shared.ID) (*GateOverride, error)
	RevokeOverride(ctx context.Context, tenantID, id, by shared.ID, at time.Time) error
	// ActiveOverride returns the newest unrevoked, unexpired override that
	// covers the commit, or nil.
	ActiveOverride(ctx context.Context, tenantID, assetID shared.ID, sha string, now time.Time) (*GateOverride, error)
}
