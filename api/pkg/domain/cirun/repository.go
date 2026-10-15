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
	ErrBaselineNotFound    = fmt.Errorf("%w: CI gate baseline not found", shared.ErrNotFound)
	ErrBaselineExists      = fmt.Errorf("%w: the repository has or had a CI gate baseline", shared.ErrConflict)
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
	// PipelineAudienceState: whether the pipeline exists and has exchanged a
	// token with its configuration's current audience.
	PipelineAudienceState(ctx context.Context, tenantID shared.ID, key PipelineKey) (exists, upgraded bool, err error)
	// MarkPipelineAudienceUpgraded ends the legacy audience for the pipeline.
	MarkPipelineAudienceUpgraded(ctx context.Context, tenantID shared.ID, key PipelineKey, at time.Time) error

	// CIRequireOIDC reads whether the tenant refuses CI results sent with a
	// sensor key; SetCIRequireOIDC writes it.
	CIRequireOIDC(ctx context.Context, tenantID shared.ID) (bool, error)
	SetCIRequireOIDC(ctx context.Context, tenantID shared.ID, require bool) error

	// ClaimReplay records the first exchange of an OIDC token (issuer,
	// jti). When the token was exchanged before it returns fresh false and
	// the earlier record. Global, not tenant-scoped: a token id is claimed
	// once across all organizations.
	ClaimReplay(ctx context.Context, r Replay) (fresh bool, prior *Replay, err error)
	// ReuseReplay counts one more exchange of the same token (same issuer,
	// jti, organization and digest) while it has had fewer than max; nil
	// when the record does not match or the bound is reached.
	ReuseReplay(ctx context.Context, issuer, jti string, tenantID shared.ID, digest []byte, max int) (*Replay, error)
	// BindReplayRun records the run a token's exchange produced (only while
	// none is recorded, or the same one).
	BindReplayRun(ctx context.Context, issuer, jti string, tenantID, runID shared.ID) error
	PurgeExpiredJTIs(ctx context.Context, before time.Time) (int64, error)

	CreateRun(ctx context.Context, r *Run) error
	// CountPipelineRunsSince counts the runs a pipeline started since the
	// time (the per-pipeline rate).
	CountPipelineRunsSince(ctx context.Context, tenantID, pipelineID shared.ID, since time.Time) (int, error)
	GetRun(ctx context.Context, tenantID, id shared.ID) (*Run, error)
	// GetRunByTokenHash returns the run whose unexpired upload token hashes
	// to hash. Not tenant-scoped: the token is the credential.
	GetRunByTokenHash(ctx context.Context, hash []byte, now time.Time) (*Run, error)
	// RotateRunToken replaces a running run's upload token (the old one
	// stops working).
	RotateRunToken(ctx context.Context, tenantID, runID shared.ID, hash []byte, expiresAt time.Time) error
	// OpenAggregateRun returns the open aggregate run of the run's pipeline
	// run (pipeline, external run id, attempt, commit), creating it from
	// the given run when there is none; created says which.
	OpenAggregateRun(ctx context.Context, r *Run) (open *Run, created bool, err error)
	// AddRunToken adds an upload token to a running run (a job of an aggregate
	// run, or a re-exchange of the token that opened a run).
	AddRunToken(ctx context.Context, tenantID, runID shared.ID, hash []byte, jobID string, expiresAt time.Time) error
	ListRuns(ctx context.Context, tenantID shared.ID, f RunFilter) ([]Run, int, error)
	// ReserveRunReport takes one of the run's MaxRunReports report slots,
	// atomically and only while the run is running: ErrRunEvaluated after
	// the verdict, ErrRunReportCap when the slots are used up. A report is
	// ingested only after its slot is reserved.
	ReserveRunReport(ctx context.Context, tenantID, runID shared.ID) error
	// RecordRunReport adds the fingerprints a report sighted (capped at
	// MaxRunFindings per run); ErrRunEvaluated once the run has its verdict.
	// A report past the cap marks the run (RunFindingsOverCap).
	RecordRunReport(ctx context.Context, tenantID, runID shared.ID, fingerprints []string) error
	// RunFindingsOverCap reports whether the run sighted more findings than
	// it could record; such a run fails its gate.
	RunFindingsOverCap(ctx context.Context, tenantID, runID shared.ID) (bool, error)
	// RunFindings returns the findings on the run's repository asset whose
	// fingerprints the run recorded.
	RunFindings(ctx context.Context, tenantID, runID, assetID shared.ID) ([]RunFinding, error)
	// FindingsByFingerprints returns the findings on assetID that hold the
	// given fingerprints (at most MaxRunFindings), with the fields
	// RunFindings returns.
	FindingsByFingerprints(ctx context.Context, tenantID, assetID shared.ID, fingerprints []string) ([]RunFinding, error)
	// SaveVerdict stores the first verdict of a running run whose recorded
	// findings count is still expectFindings (the count the verdict was
	// computed from): ErrRunEvaluated when another verdict was stored first,
	// ErrRunChanged when a report was recorded meanwhile.
	SaveVerdict(ctx context.Context, tenantID, runID shared.ID, verdict string, detail []byte, at time.Time, expectFindings int) error

	ListGatePolicies(ctx context.Context, tenantID shared.ID) ([]GatePolicy, error)
	GetGatePolicy(ctx context.Context, tenantID, id shared.ID) (*GatePolicy, error)
	CreateGatePolicy(ctx context.Context, p *GatePolicy) error
	UpdateGatePolicy(ctx context.Context, p *GatePolicy) error
	DeleteGatePolicy(ctx context.Context, tenantID, id shared.ID) error
	// GatePoliciesFor returns the enabled policies that may apply to a
	// repository asset: its own, those of its business units, the tenant's.
	GatePoliciesFor(ctx context.Context, tenantID, assetID shared.ID) ([]GatePolicy, error)

	// GateBaseline returns a repository's gate baseline, or nil when it has
	// none.
	GateBaseline(ctx context.Context, tenantID, assetID shared.ID) (*GateBaseline, error)
	// GateBaselineFingerprints returns those of fingerprints that are in the
	// repository's gate baseline.
	GateBaselineFingerprints(ctx context.Context, tenantID, assetID shared.ID, fingerprints []string) ([]string, error)
	// SetGateBaseline records the findings open now on the repository's
	// default branch as its gate baseline, replacing any earlier one, and
	// fills b.FindingsCount and b.Branch. A first-run baseline is recorded
	// only when the repository never had one (ErrBaselineExists otherwise).
	SetGateBaseline(ctx context.Context, b *GateBaseline) error
	// DeleteGateBaseline removes a repository's gate baseline and its
	// findings (ErrBaselineNotFound when it has none); the repository keeps
	// a record that it had one, so no first run records another.
	DeleteGateBaseline(ctx context.Context, tenantID, assetID shared.ID) error

	CreateOverride(ctx context.Context, o *GateOverride) error
	ListOverrides(ctx context.Context, tenantID shared.ID, assetID *shared.ID, scope *shared.DataScope) ([]GateOverride, error)
	GetOverride(ctx context.Context, tenantID, id shared.ID) (*GateOverride, error)
	RevokeOverride(ctx context.Context, tenantID, id, by shared.ID, at time.Time) error
	// ActiveOverride returns the newest unrevoked, unexpired override that
	// covers the commit, or nil.
	ActiveOverride(ctx context.Context, tenantID, assetID shared.ID, sha string, now time.Time) (*GateOverride, error)
	// MissingExpectedCapabilities returns the capabilities the run's
	// repository is expected to report (its coverage expectation; an empty
	// list means every capability) that no tool the run reported has, per
	// the tool catalog. None when the repository has no expectation.
	MissingExpectedCapabilities(ctx context.Context, tenantID, runID shared.ID) ([]string, error)

	PipelineRepository
	CoverageRepository
}

// Coverage errors.
var (
	ErrExpectationNotFound = fmt.Errorf("%w: coverage expectation not found", shared.ErrNotFound)
	ErrPipelineRetired     = fmt.Errorf("%w: the CI pipeline is already retired", shared.ErrConflict)
	ErrRepositoryNotFound  = fmt.Errorf("%w: repository not found", shared.ErrNotFound)
)

// CoverageRepository persists coverage expectations, alert state and the
// stale-source finding updates. Every method but PipelineTenantsForPlatform
// is tenant-scoped.
type CoverageRepository interface {
	ListRepositories(ctx context.Context, tenantID shared.ID, scope *shared.DataScope, limit int) ([]RepositoryRef, error)
	CoverageObservations(ctx context.Context, tenantID shared.ID, since time.Time) ([]CoverageObservation, error)
	ListExpectations(ctx context.Context, tenantID shared.ID) (map[shared.ID]Expectation, error)
	UpsertExpectation(ctx context.Context, e *Expectation) error
	DeleteExpectation(ctx context.Context, tenantID, assetID shared.ID) error
	RepositoryExists(ctx context.Context, tenantID, assetID shared.ID) (bool, error)
	ListAlertState(ctx context.Context, tenantID shared.ID) ([]AlertState, error)
	FireAlert(ctx context.Context, tenantID shared.ID, a Alert, at time.Time) (bool, error)
	ClearAlert(ctx context.Context, tenantID, subjectID shared.ID, kind AlertKind) error
	PipelineTenantsForPlatform(ctx context.Context) ([]shared.ID, error)
	// TokenRefusalsSince counts the tenant's refused CI token exchanges
	// (audited, so verified tokens only) since the time.
	TokenRefusalsSince(ctx context.Context, tenantID shared.ID, since time.Time) (int, error)
	// RecentTokenRefusals lists the tenant's latest refused CI token
	// exchanges, newest first, at most limit.
	RecentTokenRefusals(ctx context.Context, tenantID shared.ID, limit int) ([]TokenRefusal, error)
	MarkStaleSourceFindings(ctx context.Context, tenantID shared.ID, p *Pipeline) ([]shared.ID, error)
	RetirePipeline(ctx context.Context, tenantID, pipelineID shared.ID, by *shared.ID, reason string, at time.Time) (*Pipeline, []shared.ID, error)
}

// PipelineCaps bound the pipelines a tenant and a trust configuration may
// have.
type PipelineCaps struct {
	PerTenant      int
	PerTrustConfig int
}

// PipelineRepository persists CI pipelines. Every method is tenant-scoped.
type PipelineRepository interface {
	// RepositoryBoundElsewhere reports whether an active pipeline of the
	// provider and issuer, keyed by another repository id, already reports
	// on the repository asset of that name: a name the token does not sign
	// stays with the first repository id that used it.
	RepositoryBoundElsewhere(ctx context.Context, tenantID shared.ID, provider Provider, issuer, repositoryName, externalRepoID string) (bool, error)
	// RequestRepoExceptions stores exceptions a repository asks for (its
	// .openctem.yml, inline ignore comments, an ignore file) as pending
	// suppression rules on the repository asset, requested by actor (the CI
	// identity), skipping any already open, with a "created" audit row each,
	// and returns how many it created.
	RequestRepoExceptions(ctx context.Context, tenantID, assetID shared.ID, repository, actor string, exceptions []RepoException) (int, error)
	// PinOwner records ownerID for the configuration's owner name unless one
	// is pinned already, and returns the pinned id and whether this call
	// pinned it.
	PinOwner(ctx context.Context, tenantID, trustConfigID shared.ID, ownerName, ownerID string) (string, bool, error)
	// ResetOwnerPins drops the configuration's pins (they are taken again at
	// the next admitted exchange).
	ResetOwnerPins(ctx context.Context, tenantID, trustConfigID shared.ID) (int64, error)
	// OwnerPins lists the configuration's pins.
	OwnerPins(ctx context.Context, tenantID, trustConfigID shared.ID) ([]OwnerPin, error)
	// UpsertPipeline finds the pipeline with p's key (adopting a backfilled
	// legacy row of the same repository asset and workflow path) or creates
	// it within the caps (ErrPipelineCap). An existing pipeline takes p's
	// trust configuration, is no longer revoked and, unless fork is set,
	// takes p's display names, template and default branch. The stored
	// pipeline is returned with created = true for a new row.
	UpsertPipeline(ctx context.Context, p *Pipeline, fork bool, caps PipelineCaps) (*Pipeline, bool, error)
	// RefreshPipeline recomputes the pipeline's run summary (last run,
	// counts, gates, health inputs, cadence) from its runs.
	RefreshPipeline(ctx context.Context, tenantID, pipelineID shared.ID) error
	GetPipeline(ctx context.Context, tenantID, id shared.ID) (*Pipeline, error)
	// ListPipelines returns the tenant's pipelines (at most MaxListedPipelines).
	ListPipelines(ctx context.Context, tenantID shared.ID, f PipelineFilter) ([]Pipeline, error)
	// PipelineBranches summarizes the pipeline's runs per branch, newest
	// first, at most MaxPipelineBranches.
	PipelineBranches(ctx context.Context, tenantID, pipelineID shared.ID) ([]PipelineBranch, error)
	// PipelineGateTrend returns the newest evaluated non-fork
	// default-branch runs, newest first.
	PipelineGateTrend(ctx context.Context, tenantID, pipelineID shared.ID, limit int) ([]GatePoint, error)
	// RevokeTrustConfigPipelines marks the pipelines the configuration
	// admitted last as revoked and invalidates the upload tokens of its runs
	// still running. Returns the pipelines revoked.
	RevokeTrustConfigPipelines(ctx context.Context, tenantID, trustConfigID shared.ID, at time.Time) (int64, error)
	// RecordRunOutcome stores what the runner reported at evaluation.
	RecordRunOutcome(ctx context.Context, tenantID, runID shared.ID, scanFailures int) error
	// RecordRunTools merges tool labels into the run's (capped).
	RecordRunTools(ctx context.Context, tenantID, runID shared.ID, tools []ToolLabel) error
}

// TokenRefusal is a refused CI token exchange, as audited: verified tokens
// only (an unverified token is never recorded), with the rule codes that
// refused it.
type TokenRefusal struct {
	At         time.Time
	Repository string
	Provider   string
	Ref        string
	Event      string
	Reasons    []string
	Message    string
}

// MaxTokenRefusals bounds a refusal listing.
const MaxTokenRefusals = 50

// Replay is the record of an exchanged OIDC token (ci_oidc_replay).
type Replay struct {
	Issuer string
	JTI    string
	// TenantID is the organization the token was admitted into (nil for a
	// record written before re-exchange existed).
	TenantID *shared.ID
	// TokenSHA256 is the digest of the exact token.
	TokenSHA256 []byte
	// RunID is the run the token opened or joined (nil until known).
	RunID     *shared.ID
	Exchanges int
	FirstAt   time.Time
	ExpiresAt time.Time
}

// MaxTokenExchanges bounds how many times one OIDC token may be exchanged
// (the first exchange included). Each re-exchange returns a token for the
// same run; the bound keeps a token from minting upload tokens without end.
const MaxTokenExchanges = 5
