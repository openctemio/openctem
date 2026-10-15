// Package cirun runs the CI side of the platform: the OIDC token exchange
// that gives a pipeline run a short-lived upload token, the upload of its
// results, and the central gate verdict.
//
// Design: docs/rfcs/RFC-051-ci-runner-identity-and-gate.md.
package cirun

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/branch"
	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/oidc"

	"github.com/openctemio/ctis"
)

// ErrExchangeRefused is the only error a caller of Exchange sees for a token
// that is not accepted, whatever the reason: the reason goes to the log and,
// for a verified token, to the tenant's audit log.
var ErrExchangeRefused = errors.New("ci token exchange refused")

// ErrIssuerUnavailable: the token's issuer keys cannot be obtained right now
// (unreachable beyond the stale bound, or a key rotation not yet fetched).
// The token was not claimed; the job may retry it (503 with Retry-After).
var ErrIssuerUnavailable = errors.New("ci token issuer keys unavailable")

// ErrRunnerOutdated refuses an exchange from a runner that reports a version
// below the minimum CI runner release (CI_RUNNER_MIN_VERSION). It is told to
// the caller (only after its token verified and was admitted): the fix is on
// its side. The error returned is a *RunnerOutdatedError.
var ErrRunnerOutdated = errors.New("ci runner older than the minimum supported version")

// RunnerOutdatedError names the runner's version, the minimum and the
// release to pin, so the job can be told exactly what to change.
type RunnerOutdatedError struct {
	Version string
	Min     string
	// Pin is the release the console's snippets pin (the newest), else Min.
	Pin string
}

func (e *RunnerOutdatedError) Error() string { return ErrRunnerOutdated.Error() }
func (e *RunnerOutdatedError) Unwrap() error { return ErrRunnerOutdated }

// errPipelineRate is a pipeline over MaxPipelineRunsPerHour (refused as
// ErrExchangeRefused, audited).
var errPipelineRate = errors.New("pipeline run rate exceeded")

// errAggregateNoRunID: an aggregate exchange whose token names no pipeline
// run (the key every job of the run shares).
var errAggregateNoRunID = errors.New("aggregate exchange without a pipeline run id")

// ErrReportOutOfScope refuses a report that names an asset other than the
// run's repository.
var ErrReportOutOfScope = fmt.Errorf("%w: a CI run reports only on its own repository", shared.ErrValidation)

// TokenVerifier verifies CI workload tokens (pkg/oidc).
type TokenVerifier interface {
	VerifyWorkloadToken(ctx context.Context, raw string, exp oidc.WorkloadExpectations) (*oidc.WorkloadToken, error)
}

// AssetStore finds and creates the repository asset a run belongs to.
type AssetStore interface {
	GetByID(ctx context.Context, tenantID, id shared.ID) (*asset.Asset, error)
	GetByName(ctx context.Context, tenantID shared.ID, name string) (*asset.Asset, error)
	Create(ctx context.Context, a *asset.Asset) error
}

// BranchStore reads a repository's branches (by repository asset id).
type BranchStore interface {
	GetByName(ctx context.Context, repositoryID shared.ID, name string) (*branch.Branch, error)
	GetDefaultBranch(ctx context.Context, repositoryID shared.ID) (*branch.Branch, error)
}

// BaselineReader reads which findings are open on a branch.
type BaselineReader interface {
	FingerprintsOpenOnBranch(ctx context.Context, tenantID, branchID shared.ID, fingerprints []string) ([]string, error)
	// BranchCountsAsExposure: the branch is default, protected, or of type
	// main or release (a release line, never a feature branch).
	BranchCountsAsExposure(ctx context.Context, tenantID, branchID shared.ID) (bool, error)
}

// ReportIngester applies a run's report (internal/app/ingest).
type ReportIngester interface {
	IngestForCIRun(ctx context.Context, tenantID, runID shared.ID, repository string, report *ctis.Report) (*ingest.Output, error)
}

// BusinessUnits checks that a business unit belongs to the tenant.
type BusinessUnits interface {
	BusinessUnitExists(ctx context.Context, tenantID, id shared.ID) (bool, error)
}

// Auditor writes audit records.
type Auditor interface {
	LogEvent(ctx context.Context, actx auditapp.AuditContext, event auditapp.AuditEvent) error
}

// Config tunes the service.
type Config struct {
	// WebBaseURL is the web console's address, for the links in a verdict
	// ("" gives relative links).
	WebBaseURL string
	// PipelineCaps bound the pipelines per tenant and per trust
	// configuration (zero values take the defaults).
	PipelineCaps cirun.PipelineCaps
	// Versions is the CI runner release line a runner's version is judged
	// against (CI_RUNNER_LATEST_VERSION, CI_RUNNER_MIN_VERSION). CI runners
	// (openctemio/ci) are versioned apart from sensors, so the sensor's
	// release settings never apply to them.
	Versions cirun.StatusPolicy
	// KnownLimit bounds the decided results one upload response lists
	// (zero takes cirun.MaxKnownInResponse).
	KnownLimit int
}

func (c Config) knownLimit() int {
	if c.KnownLimit <= 0 {
		return cirun.MaxKnownInResponse
	}
	return c.KnownLimit
}

func (c Config) caps() cirun.PipelineCaps {
	out := c.PipelineCaps
	if out.PerTenant <= 0 {
		out.PerTenant = cirun.DefaultMaxPipelinesPerTenant
	}
	if out.PerTrustConfig <= 0 {
		out.PerTrustConfig = cirun.DefaultMaxPipelinesPerTrustConfig
	}
	return out
}

// Service is the CI run service.
type Service struct {
	repo      cirun.Repository
	verifier  TokenVerifier
	assets    AssetStore
	branches  BranchStore
	baseline  BaselineReader
	ingester  ReportIngester
	units     BusinessUnits
	audit     Auditor
	alerts    AdminAlerter
	cfg       Config
	log       *logger.Logger
	now       func() time.Time
	purgeMu   sync.Mutex
	lastPurge time.Time
	images    ImageLinker
	stepUp    shared.RecentAuthGate
	rules     SuppressionRules
	modules   ModuleGuard
}

// Deps are the service's collaborators.
type Deps struct {
	Repo     cirun.Repository
	Verifier TokenVerifier
	Assets   AssetStore
	Branches BranchStore
	Baseline BaselineReader
	Ingester ReportIngester
	Units    BusinessUnits
	Audit    Auditor
	// Alerts tells every administrator about break-glass (nil: audit only).
	Alerts AdminAlerter
}

// NewService creates the service.
func NewService(d Deps, cfg Config, log *logger.Logger) *Service {
	if log == nil {
		log = logger.NewNop()
	}
	return &Service{repo: d.Repo, verifier: d.Verifier, assets: d.Assets, branches: d.Branches, baseline: d.Baseline,
		ingester: d.Ingester, units: d.Units, audit: d.Audit, alerts: d.Alerts, cfg: cfg, log: log.With("service", "cirun"), now: time.Now}
}

// SetClock replaces the clock (tests).
func (s *Service) SetClock(now func() time.Time) { s.now = now }

// Actor is who performed an administrative action.
type Actor struct {
	UserID    string
	Email     string
	IP        string
	UserAgent string
	RequestID string
}

func (s *Service) logAudit(ctx context.Context, tenantID shared.ID, a Actor, ev auditapp.AuditEvent) {
	if s.audit == nil {
		return
	}
	if err := s.audit.LogEvent(ctx, auditapp.AuditContext{TenantID: tenantID.String(), ActorID: a.UserID,
		ActorEmail: a.Email, ActorIP: a.IP, UserAgent: a.UserAgent, RequestID: a.RequestID}, ev); err != nil {
		s.log.Warn("ci audit record not written", "action", ev.Action.String(), "error", logger.SanitizeError(err))
	}
}

func (s *Service) alertAdmins(ctx context.Context, tenantID shared.ID, a AdminAlert) {
	if s.alerts != nil {
		s.alerts.AlertAdmins(ctx, tenantID, a)
	}
}

// ---------------------------------------------------------------- exchange --

// ExchangeInput is a CI job's exchange request.
type ExchangeInput struct {
	TenantID string
	IDToken  string
	// RunID, when set, asks for a fresh token for a run this pipeline
	// already holds (a long job whose token expired). It is honored only for
	// the same repository, commit and pipeline run, before the run was
	// evaluated and within MaxRunContinuation of its start.
	RunID string
	// Aggregate asks to join the run shared by every job of the same
	// pipeline run (same pipeline, external run id, attempt and commit,
	// all from the verified token), opening it for the first job. Each
	// job gets its own upload token for it.
	Aggregate bool
	// Hints are what the job reports about itself, used only for what its
	// provider's token does not sign (cirun.Hints): the commit on CircleCI
	// (and Bitbucket or Jenkins tokens without one), the repository name on
	// Bitbucket.
	Hints     cirun.Hints
	ClientIP  string
	UserAgent string
}

// MaxRunContinuation bounds how long after its start a run can get a fresh
// token.
const MaxRunContinuation = 6 * time.Hour

// ExchangeOutput is a run and its upload token. The token is returned once
// and never stored.
type ExchangeOutput struct {
	Run       *cirun.Run
	Token     string
	ExpiresAt time.Time
	// JobID is the CI job the token was issued to (verified claim).
	JobID string
	// Joined: the job joined an aggregate run another job had opened.
	Joined bool
	// Exchanges is how many times the job's OIDC token has been exchanged,
	// this one included (more than 1: a re-exchange for the same run).
	Exchanges int
}

// Exchange verifies a CI job's OIDC token against the tenant's trust
// configurations and, when one admits it, creates a run on the repository
// asset and returns its upload token. Every refusal is ErrExchangeRefused.
func (s *Service) Exchange(ctx context.Context, in ExchangeInput) (*ExchangeOutput, error) {
	s.purgeReplay(ctx)
	tenantID, err := shared.IDFromString(strings.TrimSpace(in.TenantID))
	if err != nil || tenantID.IsZero() {
		return nil, s.refuseUnverified("tenant id is not a valid id")
	}
	issuer, err := oidc.UnverifiedIssuer(in.IDToken)
	if err != nil {
		return nil, s.refuseUnverified("token is malformed")
	}
	configs, err := s.repo.EnabledTrustConfigs(ctx, tenantID, strings.TrimRight(issuer, "/"))
	if err != nil {
		return nil, fmt.Errorf("load trust configurations: %w", err)
	}
	if len(configs) == 0 {
		// Before any verification: nothing is written to the tenant's audit
		// log, so an anonymous caller cannot fill it.
		return nil, s.refuseUnverified("no enabled trust configuration for the issuer")
	}

	tok, claims, err := s.verify(ctx, in.IDToken, configs, in.Hints)
	if err != nil {
		s.log.Info("ci exchange refused: token did not verify", "tenant_id", tenantID.String(),
			"issuer", logger.SanitizeValue(issuer), "error", logger.SanitizeError(err))
		if errors.Is(err, oidc.ErrJWKSUnavailable) || errors.Is(err, oidc.ErrKeyNotFound) {
			// The issuer's keys cannot be had right now (the issuer is
			// unreachable past the stale bound, or it rotated to a key the
			// platform may fetch only once per interval). Nothing was
			// claimed: the job may retry the same token shortly.
			return nil, ErrIssuerUnavailable
		}
		return nil, ErrExchangeRefused
	}

	cfg, refusals := admit(configs, tok, claims, s.now())
	if cfg == nil {
		s.auditRefusal(ctx, tenantID, in, claims, refusals)
		return nil, ErrExchangeRefused
	}
	// A repository name stays with the repository id that first reported
	// under it (checkRepositoryBinding).
	if refusal, err := s.checkRepositoryBinding(ctx, tenantID, cfg, claims); err != nil {
		return nil, err
	} else if refusal != nil {
		s.auditRefusal(ctx, tenantID, in, claims, []*cirun.Refusal{refusal})
		return nil, publicRefusal(refusal)
	}
	// The organization or namespace stays the one first admitted under its
	// name (checkOwnerPin).
	if refusal, err := s.checkOwnerPin(ctx, tenantID, cfg, claims); err != nil {
		return nil, err
	} else if refusal != nil {
		s.auditRefusal(ctx, tenantID, in, claims, []*cirun.Refusal{refusal})
		return nil, publicRefusal(refusal)
	}
	// The pipeline's identity comes from the verified claims only: a token
	// without an immutable repository id or a usable workflow path is not
	// admitted, whatever the trust configuration says.
	key, refusal := cirun.PipelineKeyFromClaims(cfg.Provider, cfg.Issuer, claims)
	if refusal != nil {
		s.auditRefusal(ctx, tenantID, in, claims, []*cirun.Refusal{refusal})
		return nil, publicRefusal(refusal)
	}
	legacy := claims.Audience != cfg.Audience
	if legacy {
		if refusal, err := s.checkLegacyAudience(ctx, tenantID, cfg, key); err != nil {
			return nil, err
		} else if refusal != nil {
			s.auditRefusal(ctx, tenantID, in, claims, []*cirun.Refusal{refusal})
			return nil, publicRefusal(refusal)
		}
	}
	if v := s.runnerVersion(in.UserAgent); runnerRefusal(v, s.cfg.Versions) != nil {
		s.auditRefusal(ctx, tenantID, in, claims, []*cirun.Refusal{runnerRefusal(v, s.cfg.Versions)})
		pin := s.cfg.Versions.LatestVersion
		if pin == "" {
			pin = s.cfg.Versions.MinVersion
		}
		return nil, &RunnerOutdatedError{Version: v, Min: s.cfg.Versions.MinVersion, Pin: pin}
	}
	// The token's replay record: the first exchange claims it; the same
	// token presented again (an answer lost, a second step of the job) gets
	// a fresh upload token for the same run only (reexchange.go).
	digest := sha256.Sum256([]byte(in.IDToken))
	var runID *shared.ID
	if strings.TrimSpace(in.RunID) == "" && !in.Aggregate {
		// A plain run's id is chosen before it exists, so a re-exchange
		// after a failed creation makes this run and never a second one.
		id := shared.NewID()
		runID = &id
	}
	fresh, prior, err := s.repo.ClaimReplay(ctx, cirun.Replay{Issuer: tok.Issuer, JTI: tok.JTI, TenantID: &tenantID,
		TokenSHA256: digest[:], RunID: runID, ExpiresAt: tok.ExpiresAt.Add(time.Hour)})
	if err != nil {
		return nil, fmt.Errorf("record token id: %w", err)
	}
	exchanges := 1
	if !fresh {
		rp, err := s.reuseToken(ctx, tenantID, in, claims, tok, digest[:], prior)
		if err != nil {
			return nil, err
		}
		exchanges, runID = rp.Exchanges, rp.RunID
	}

	var out *ExchangeOutput
	switch {
	case !fresh && runID != nil:
		out, err = s.resumeRun(ctx, tenantID, cfg, claims, key, in, *runID, prior)
	case strings.TrimSpace(in.RunID) != "":
		out, err = s.continueRun(ctx, tenantID, cfg, claims, in.RunID, false)
		if errors.Is(err, ErrExchangeRefused) {
			s.auditRefusal(ctx, tenantID, in, claims, []*cirun.Refusal{{Code: "run_mismatch",
				Detail: "the token does not belong to the run it asked to continue"}})
			err = &RefusedError{Code: "run_mismatch", Message: "This CI token does not belong to the run it asked to continue."}
		}
	default:
		out, err = s.createRun(ctx, tenantID, cfg, claims, key, in.UserAgent, in.Aggregate, runID)
		err = s.refuseCreate(ctx, tenantID, in, claims, err)
	}
	if err == nil && (fresh || runID == nil || *runID != out.Run.ID) {
		if berr := s.repo.BindReplayRun(ctx, tok.Issuer, tok.JTI, tenantID, out.Run.ID); berr != nil {
			s.log.Warn("ci token run not recorded", "error", logger.SanitizeError(berr))
		}
	}
	if err == nil {
		out.Exchanges = exchanges
	}
	if err != nil {
		return nil, err
	}
	_ = s.repo.TouchTrustConfig(ctx, tenantID, cfg.ID, s.now())
	if !legacy && cfg.LegacyAudience != "" {
		// The pipeline uses the new audience: its legacy one is refused from
		// now on.
		if err := s.repo.MarkPipelineAudienceUpgraded(ctx, tenantID, key, s.now()); err != nil {
			s.log.Warn("ci pipeline audience upgrade not recorded", "error", logger.SanitizeError(err))
		}
	}
	s.auditIssued(ctx, tenantID, in, cfg, out, legacy)
	return out, nil
}

// RefuseRepositoryBinding refuses a job whose repository name is already
// bound to another repository id of the same CI issuer in the tenant.
const RefuseRepositoryBinding = "repository_binding"

// bindsRepositoryID reports whether a provider's pipeline key is the
// repository's own immutable id (GitHub repository_id, GitLab project_id,
// Bitbucket repositoryUuid), so a repository name can be bound to it. The
// other providers key pipelines on a CI project or job, which may build
// several repositories.
func bindsRepositoryID(p cirun.Provider) bool {
	return p == cirun.ProviderGitHub || p == cirun.ProviderGitLab || p == cirun.ProviderBitbucket
}

// checkRepositoryBinding keeps a repository asset with the repository that
// first reported into it. Trust rules match owners and repositories by
// name; a name can change hands (an organization renamed or deleted and its
// name registered again, a repository deleted and created anew, and on
// Bitbucket a name the token does not sign at all). The first repository id
// that reports under a name keeps it while that pipeline is not retired:
// a different repository under the same name is refused (audited) until an
// administrator retires the old pipeline.
func (s *Service) checkRepositoryBinding(ctx context.Context, tenantID shared.ID, cfg *cirun.TrustConfig, c cirun.Claims) (*cirun.Refusal, error) {
	if !bindsRepositoryID(cfg.Provider) || strings.TrimSpace(c.RepositoryID) == "" {
		return nil, nil
	}
	name := asset.NormalizeName(c.CanonicalRepository(), asset.AssetTypeRepository, "")
	bound, err := s.repo.RepositoryBoundElsewhere(ctx, tenantID, cfg.Provider, cfg.Issuer, name, c.RepositoryID)
	if err != nil {
		return nil, fmt.Errorf("check repository binding: %w", err)
	}
	if bound {
		return &cirun.Refusal{Code: RefuseRepositoryBinding,
			Detail: fmt.Sprintf("repository %q reports under another repository id", name)}, nil
	}
	return nil, nil
}

// RefuseOwnerPin refuses a job whose organization or namespace name is
// pinned to another immutable id.
const RefuseOwnerPin = "owner_id_mismatch"

// checkOwnerPin keeps a trust configuration with the organization (GitHub
// repository_owner_id) or namespace (GitLab namespace_id) that first used a
// name. Rules match names, and an organization renamed or deleted gives its
// name to whoever registers it next; the first admitted exchange pins the id
// (audited) and a later token with the same name and another id is refused.
// An administrator re-pins by changing the configuration's owners or
// repositories, which drops its pins.
func (s *Service) checkOwnerPin(ctx context.Context, tenantID shared.ID, cfg *cirun.TrustConfig, c cirun.Claims) (*cirun.Refusal, error) {
	if cfg.Provider != cirun.ProviderGitHub && cfg.Provider != cirun.ProviderGitLab {
		return nil, nil
	}
	name, id := strings.TrimSpace(c.OwnerName), strings.TrimSpace(c.OwnerID)
	if name == "" || id == "" || len(name) > 500 || len(id) > 64 {
		return nil, nil
	}
	pinned, created, err := s.repo.PinOwner(ctx, tenantID, cfg.ID, name, id)
	if err != nil {
		return nil, fmt.Errorf("pin CI owner: %w", err)
	}
	if created {
		s.logAudit(ctx, tenantID, Actor{Email: ciActor(c)},
			auditapp.NewSuccessEvent(auditdom.ActionCITrustConfigUpdated, auditdom.ResourceTypeCITrustConfig, cfg.ID.String()).
				WithResourceName(cfg.Name).
				WithMessage(fmt.Sprintf("CI trust configuration %q pinned %s to id %s", cfg.Name, name, id)).
				WithMetadata("owner_pinned", name).
				WithMetadata("owner_id", id))
		return nil, nil
	}
	if pinned != id {
		return &cirun.Refusal{Code: RefuseOwnerPin,
			Detail: fmt.Sprintf("%s is pinned to id %s; the token names id %s", name, pinned, id)}, nil
	}
	return nil, nil
}

// verify tries the token against each distinct provider and audience of
// the configurations; the first that verifies wins. The claims are read with
// that provider's mapping and completed with the job's hints where the
// provider signs nothing (cirun.Claims.ApplyHints).
func (s *Service) verify(ctx context.Context, raw string, configs []cirun.TrustConfig, hints cirun.Hints) (*oidc.WorkloadToken, cirun.Claims, error) {
	if s.verifier == nil {
		return nil, cirun.Claims{}, errors.New("no token verifier")
	}
	tried := map[string]bool{}
	var lastErr error
	now := s.now()
	for _, c := range configs {
		auds := []string{c.Audience}
		if c.LegacyAccepted(c.LegacyAudience, now) {
			// The audience the configuration had before audiences named the
			// tenant: admitted only for a pipeline not yet moved to the new
			// one (checked in Exchange once the pipeline is known).
			auds = append(auds, c.LegacyAudience)
		}
		for _, aud := range auds {
			key := string(c.Provider) + "\x00" + aud
			if tried[key] {
				continue
			}
			tried[key] = true
			tok, err := s.verifier.VerifyWorkloadToken(ctx, raw, oidc.WorkloadExpectations{Issuer: c.Issuer, Audience: aud,
				JTIOptional: cirun.JTIOptional(c.Provider)})
			if err != nil {
				lastErr = err
				continue
			}
			claims := cirun.ParseClaims(c.Provider, tok.Claims)
			// The replay key the verifier chose (the token's jti, or a hash of
			// the token for a provider that sends none).
			claims.JTI = tok.JTI
			claims.ApplyHints(hints)
			claims.Audience = aud
			return tok, claims, nil
		}
	}
	if lastErr == nil {
		lastErr = errors.New("no audience to verify against")
	}
	return nil, cirun.Claims{}, lastErr
}

// admit returns the first configuration (with the token's audience) whose
// rules admit the claims, or the refusals of each.
func admit(configs []cirun.TrustConfig, tok *oidc.WorkloadToken, claims cirun.Claims, now time.Time) (*cirun.TrustConfig, []*cirun.Refusal) {
	var refusals []*cirun.Refusal
	for i := range configs {
		c := &configs[i]
		if (c.Audience != claims.Audience && !c.LegacyAccepted(claims.Audience, now)) ||
			c.Issuer != tok.Issuer || c.Provider != claims.Provider {
			continue
		}
		if r := c.Rules.Admit(claims); r != nil {
			refusals = append(refusals, r)
			continue
		}
		return c, nil
	}
	return nil, refusals
}

func (s *Service) createRun(ctx context.Context, tenantID shared.ID, cfg *cirun.TrustConfig, c cirun.Claims,
	key cirun.PipelineKey, userAgent string, aggregate bool, runID *shared.ID) (*ExchangeOutput, error) {
	if aggregate && strings.TrimSpace(c.RunID) == "" {
		return nil, errAggregateNoRunID
	}
	repoName := c.CanonicalRepository()
	repoAsset, err := s.repositoryAsset(ctx, tenantID, repoName)
	if err != nil {
		return nil, err
	}
	defaultBranch := cfg.DefaultBranch
	if s.branches != nil {
		if b, err := s.branches.GetDefaultBranch(ctx, repoAsset.ID()); err == nil && b != nil && b.Name() != "" {
			defaultBranch = b.Name()
		}
	}
	now := s.now().UTC()
	cfgID := cfg.ID
	templateRef, templateSHA := cirun.Template(cfg.Provider, cfg.Issuer, c)
	pipeline, err := s.upsertPipeline(ctx, &cirun.Pipeline{
		ID: shared.NewID(), TenantID: tenantID, Provider: key.Provider, Issuer: key.Issuer,
		ExternalRepoID: key.ExternalRepoID, WorkflowPath: key.WorkflowPath, RepositoryAssetID: repoAsset.ID(),
		TrustConfigID: &cfgID, RepositoryName: repoAsset.Name(),
		WorkflowName: cirun.SanitizeLabel(c.WorkflowName, 255),
		TemplateRef:  templateRef, TemplateSHA: templateSHA, DefaultBranch: defaultBranch, CreatedAt: now,
	}, c.IsForkEvent(), cfg)
	if err != nil {
		return nil, err
	}
	recent, err := s.repo.CountPipelineRunsSince(ctx, tenantID, pipeline.ID, now.Add(-time.Hour))
	if err != nil {
		return nil, fmt.Errorf("count pipeline runs: %w", err)
	}
	if recent >= cirun.MaxPipelineRunsPerHour {
		return nil, errPipelineRate
	}
	sensorVersion := s.runnerVersion(userAgent)
	token, hash, err := cirun.NewToken()
	if err != nil {
		return nil, err
	}
	expires := now.Add(cirun.TokenTTL)
	id := shared.NewID()
	if runID != nil && !aggregate {
		id = *runID
	}
	run := &cirun.Run{
		ID:                id,
		TenantID:          tenantID,
		TrustConfigID:     &cfgID,
		RepositoryAssetID: repoAsset.ID(),
		Provider:          cfg.Provider,
		Issuer:            cfg.Issuer,
		Repository:        repoAsset.Name(),
		Ref:               truncate(c.Ref, 500),
		Branch:            truncate(c.Branch, 255),
		CommitSHA:         truncate(c.SHA, 64),
		CommitVerified:    c.CommitVerified,
		BaseRef:           truncate(CleanBaseRef(c), 255),
		PullRequest:       truncate(c.PullRequest, 32),
		DefaultBranch:     defaultBranch,
		IsDefaultBranch:   cirun.IsDefaultBranchRun(c, defaultBranch),
		Event:             truncate(c.Event, 64),
		Environment:       truncate(c.Environment, 255),
		Actor:             truncate(c.Actor, 255),
		ExternalRunID:     truncate(c.RunID, 64),
		RunAttempt:        truncate(c.RunAttempt, 16),
		ExternalJobID:     truncate(c.JobID, 64),
		Workflow:          truncate(c.Workflow, 500),
		PipelineURL:       truncate(cirun.PipelineURL(cfg.Provider, cfg.Issuer, c), 1000),
		Fork:              c.IsForkEvent(),
		TokenHash:         hash,
		TokenExpiresAt:    &expires,
		Status:            cirun.StatusRunning,
		PipelineID:        &pipeline.ID,
		SensorVersion:     sensorVersion,
		TemplateRef:       templateRef,
		CreatedAt:         now,
		UpdatedAt:         now,
	}
	if aggregate {
		return s.joinAggregate(ctx, run, token, hash, expires)
	}
	if err := s.repo.CreateRun(ctx, run); err != nil {
		return nil, fmt.Errorf("create run: %w", err)
	}
	s.refreshPipeline(ctx, tenantID, run.PipelineID)
	return &ExchangeOutput{Run: run, Token: token, ExpiresAt: expires, JobID: run.ExternalJobID}, nil
}

// joinAggregate opens or joins the aggregate run of the pipeline run that
// run describes and issues this job its own upload token for it. The run is
// found by its pipeline, external run id, attempt and commit, all taken
// from the verified token, so a job can only join a run of its own
// pipeline run; another job's token keeps working.
func (s *Service) joinAggregate(ctx context.Context, run *cirun.Run, token string, hash []byte, expires time.Time) (*ExchangeOutput, error) {
	jobID := run.ExternalJobID
	run.Aggregate, run.ExternalJobID, run.TokenHash, run.TokenExpiresAt = true, "", nil, nil
	open, created, err := s.repo.OpenAggregateRun(ctx, run)
	if errors.Is(err, cirun.ErrRunNotFound) {
		// The open run was evaluated between the insert and the read: one
		// more attempt opens the next one.
		open, created, err = s.repo.OpenAggregateRun(ctx, run)
	}
	if err != nil {
		return nil, fmt.Errorf("open aggregate run: %w", err)
	}
	if open.Repository != run.Repository || open.Issuer != run.Issuer || open.RepositoryAssetID != run.RepositoryAssetID {
		return nil, ErrExchangeRefused
	}
	if err := s.repo.AddRunToken(ctx, open.TenantID, open.ID, hash, jobID, expires); err != nil {
		return nil, fmt.Errorf("add run token: %w", err)
	}
	if created {
		s.refreshPipeline(ctx, open.TenantID, open.PipelineID)
	}
	return &ExchangeOutput{Run: open, Token: token, ExpiresAt: expires, JobID: jobID, Joined: !created}, nil
}

// runnerVersion is the sensor version the runner's User-Agent reports
// (normalized; "" when it reports none).
// runnerRefusal refuses a runner below the minimum CI runner release. The
// version is the one the runner reports (User-Agent): this keeps known-bad
// releases out, it does not authenticate the binary. A client that reports
// no version is admitted and shown as unknown.
func runnerRefusal(version string, pol cirun.StatusPolicy) *cirun.Refusal {
	if pol.MinVersion == "" || sensor.ClassifyVersion(version, "", pol.MinVersion) != sensor.VersionUnsupported {
		return nil
	}
	return &cirun.Refusal{Code: "runner_outdated",
		Detail: fmt.Sprintf("CI runner %s is older than the minimum supported CI runner release %s", version, pol.MinVersion)}
}

func (s *Service) runnerVersion(userAgent string) string {
	_, v := sensor.ResolveBuild(sensor.BuildReport{}, "", userAgent, s.now())
	return sensor.NormalizeVersion(v)
}

// upsertPipeline finds or creates the run's pipeline within the caps and
// audits a new one. Only an admitted, verified exchange gets here.
func (s *Service) upsertPipeline(ctx context.Context, p *cirun.Pipeline, fork bool, cfg *cirun.TrustConfig) (*cirun.Pipeline, error) {
	out, created, err := s.repo.UpsertPipeline(ctx, p, fork, s.cfg.caps())
	if err != nil {
		if errors.Is(err, cirun.ErrPipelineCap) {
			return nil, err
		}
		return nil, fmt.Errorf("upsert pipeline: %w", err)
	}
	if created {
		s.logAudit(ctx, p.TenantID, Actor{Email: "ci:" + string(p.Provider)},
			auditapp.NewSuccessEvent(auditdom.ActionCIPipelineCreated, auditdom.ResourceTypeCIPipeline, out.ID.String()).
				WithResourceName(out.RepositoryName+" "+out.WorkflowPath).
				WithMessage(fmt.Sprintf("CI pipeline %s on %s registered by %q", out.WorkflowPath, out.RepositoryName, cfg.Name)).
				WithMetadata("trust_config_id", cfg.ID.String()).
				WithMetadata("provider", string(out.Provider)).
				WithMetadata("external_repo_id", out.ExternalRepoID).
				WithMetadata("workflow_path", out.WorkflowPath).
				WithMetadata("repository_asset_id", out.RepositoryAssetID.String()).
				WithMetadata("fork", fork))
	}
	return out, nil
}

// refreshPipeline recomputes a pipeline's run summary. A failure is logged:
// the next run refreshes it again, and the run itself is recorded.
func (s *Service) refreshPipeline(ctx context.Context, tenantID shared.ID, pipelineID *shared.ID) {
	if pipelineID == nil {
		return
	}
	if err := s.repo.RefreshPipeline(ctx, tenantID, *pipelineID); err != nil {
		s.log.Warn("ci pipeline summary not refreshed", "pipeline_id", pipelineID.String(), "error", logger.SanitizeError(err))
	}
}

// continueRun issues a fresh token for an existing run of the same job: same
// tenant, repository, commit, CI run id and attempt, and the same job when
// the run recorded one; not yet evaluated and recent. Anything else is
// ErrExchangeRefused: another job of the pipeline, or a re-run, gets its own
// run.
func (s *Service) continueRun(ctx context.Context, tenantID shared.ID, cfg *cirun.TrustConfig, c cirun.Claims, rawRunID string, keepTokens bool) (*ExchangeOutput, error) {
	runID, err := shared.IDFromString(strings.TrimSpace(rawRunID))
	if err != nil {
		return nil, ErrExchangeRefused
	}
	run, err := s.repo.GetRun(ctx, tenantID, runID)
	if err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			return nil, ErrExchangeRefused
		}
		return nil, fmt.Errorf("load run: %w", err)
	}
	now := s.now().UTC()
	if run.Repository != asset.NormalizeName(c.CanonicalRepository(), asset.AssetTypeRepository, "") ||
		run.CommitSHA != c.SHA || run.ExternalRunID == "" || run.ExternalRunID != c.RunID || run.Issuer != cfg.Issuer ||
		run.RunAttempt != truncate(c.RunAttempt, 16) || (run.ExternalJobID != "" && run.ExternalJobID != truncate(c.JobID, 64)) ||
		run.Status != cirun.StatusRunning || now.Sub(run.CreatedAt) > MaxRunContinuation {
		return nil, ErrExchangeRefused
	}
	token, hash, err := cirun.NewToken()
	if err != nil {
		return nil, err
	}
	expires := now.Add(cirun.TokenTTL)
	if run.Aggregate || keepTokens {
		// Another job's token of the run (or, on a re-exchange, the token
		// the same job already holds) must keep working: add a token
		// instead of rotating one.
		if err := s.repo.AddRunToken(ctx, tenantID, run.ID, hash, truncate(c.JobID, 64), expires); err != nil {
			return nil, fmt.Errorf("add run token: %w", err)
		}
		return &ExchangeOutput{Run: run, Token: token, ExpiresAt: expires, JobID: truncate(c.JobID, 64)}, nil
	}
	if err := s.repo.RotateRunToken(ctx, tenantID, run.ID, hash, expires); err != nil {
		return nil, fmt.Errorf("rotate run token: %w", err)
	}
	run.TokenHash, run.TokenExpiresAt = hash, &expires
	return &ExchangeOutput{Run: run, Token: token, ExpiresAt: expires, JobID: run.ExternalJobID}, nil
}

// repositoryAsset finds the tenant's repository asset by its canonical name
// or creates it. The trust configuration admitted the repository, which is
// what entitles the run to add it to the inventory.
func (s *Service) repositoryAsset(ctx context.Context, tenantID shared.ID, name string) (*asset.Asset, error) {
	norm := asset.NormalizeName(name, asset.AssetTypeRepository, "")
	a, err := s.assets.GetByName(ctx, tenantID, norm)
	if err == nil && a != nil {
		if a.Type() != asset.AssetTypeRepository {
			return nil, fmt.Errorf("%w: asset %q is not a repository", shared.ErrConflict, norm)
		}
		return a, nil
	}
	if err != nil && !errors.Is(err, shared.ErrNotFound) {
		return nil, fmt.Errorf("find repository asset: %w", err)
	}
	created, err := asset.NewAssetWithTenant(tenantID, norm, asset.AssetTypeRepository, asset.CriticalityMedium)
	if err != nil {
		return nil, fmt.Errorf("new repository asset: %w", err)
	}
	if err := s.assets.Create(ctx, created); err != nil {
		// Another exchange created it first.
		if again, gerr := s.assets.GetByName(ctx, tenantID, norm); gerr == nil && again != nil {
			return again, nil
		}
		return nil, fmt.Errorf("create repository asset: %w", err)
	}
	return created, nil
}

func (s *Service) refuseUnverified(reason string) error {
	s.log.Info("ci exchange refused", "reason", reason)
	return ErrExchangeRefused
}

func (s *Service) auditRefusal(ctx context.Context, tenantID shared.ID, in ExchangeInput, c cirun.Claims, refusals []*cirun.Refusal) {
	codes := make([]string, 0, len(refusals))
	details := make([]string, 0, len(refusals))
	for _, r := range refusals {
		codes = append(codes, r.Code)
		details = append(details, r.Detail)
	}
	if len(codes) == 0 {
		codes = append(codes, "no_matching_configuration")
	}
	ev := auditapp.NewDeniedEvent(auditdom.ActionCIRunTokenRefused, auditdom.ResourceTypeCIRun, "",
		strings.Join(codes, ",")).
		WithResourceName(c.Repository).
		WithMessage(fmt.Sprintf("CI token from %s refused: %s", nonEmpty(c.Repository, "an unknown repository"), strings.Join(details, "; "))).
		WithMetadata("reasons", codes).
		WithMetadata("provider", string(c.Provider)).
		WithMetadata("repository", c.Repository).
		WithMetadata("ref", c.Ref).
		WithMetadata("event", c.Event).
		WithMetadata("actor", c.Actor).
		WithMetadata("pipeline_run_id", c.RunID).
		WithMetadata("run_attempt", c.RunAttempt).
		WithMetadata("job_id", c.JobID).
		WithMetadata("commit_sha", c.SHA).
		WithMetadata("commit_verified", c.CommitVerified)
	for _, code := range codes {
		if code == "replay" {
			ev = ev.WithSeverity(auditdom.SeverityHigh)
		}
	}
	s.logAudit(ctx, tenantID, Actor{Email: ciActor(c), IP: in.ClientIP, UserAgent: in.UserAgent}, ev)
}

// checkLegacyAudience admits a token with the configuration's legacy
// audience only for a pipeline that existed before audiences named the
// tenant and has not exchanged a token with the new audience since.
func (s *Service) checkLegacyAudience(ctx context.Context, tenantID shared.ID, cfg *cirun.TrustConfig, key cirun.PipelineKey) (*cirun.Refusal, error) {
	exists, upgraded, err := s.repo.PipelineAudienceState(ctx, tenantID, key)
	if err != nil {
		return nil, fmt.Errorf("load pipeline audience: %w", err)
	}
	if exists && !upgraded {
		return nil, nil
	}
	return &cirun.Refusal{Code: "legacy_audience", Detail: fmt.Sprintf(
		"the token's audience is the configuration's old one; this pipeline must request %s", cfg.Audience)}, nil
}

func (s *Service) auditIssued(ctx context.Context, tenantID shared.ID, in ExchangeInput, cfg *cirun.TrustConfig, out *ExchangeOutput, legacy bool) {
	r := out.Run
	ev := auditapp.NewSuccessEvent(auditdom.ActionCIRunTokenIssued, auditdom.ResourceTypeCIRun, r.ID.String()).
		WithResourceName(r.Repository).
		WithMessage(fmt.Sprintf("CI run on %s (%s) admitted by %q", r.Repository, nonEmpty(r.Branch, r.Ref), cfg.Name)).
		WithMetadata("trust_config_id", cfg.ID.String()).
		WithMetadata("trust_config", cfg.Name).
		WithMetadata("legacy_audience", legacy).
		WithMetadata("repository", r.Repository).
		WithMetadata("repository_asset_id", r.RepositoryAssetID.String()).
		WithMetadata("ref", r.Ref).
		WithMetadata("commit_sha", r.CommitSHA).
		WithMetadata("commit_verified", r.CommitVerified).
		WithMetadata("event", r.Event).
		WithMetadata("actor", r.Actor).
		WithMetadata("pipeline_run_id", r.ExternalRunID).
		WithMetadata("run_attempt", r.RunAttempt).
		WithMetadata("job_id", out.JobID).
		WithMetadata("continuation", strings.TrimSpace(in.RunID) != "").
		WithMetadata("token_exchanges", out.Exchanges).
		WithMetadata("aggregate", r.Aggregate).
		WithMetadata("joined", out.Joined).
		WithMetadata("pipeline_url", r.PipelineURL).
		WithMetadata("fork", r.Fork).
		WithMetadata("token_expires_at", out.ExpiresAt.Format(time.RFC3339))
	s.logAudit(ctx, tenantID, Actor{Email: ciActor(cirun.Claims{Provider: r.Provider, Actor: r.Actor}), IP: in.ClientIP,
		UserAgent: in.UserAgent}, ev)
}

// ciActor names the CI identity in the audit actor field.
func ciActor(c cirun.Claims) string {
	if c.Actor == "" {
		return "ci:" + string(c.Provider)
	}
	return "ci:" + string(c.Provider) + ":" + c.Actor
}

// purgeReplay drops expired token ids at most every ten minutes.
func (s *Service) purgeReplay(ctx context.Context) {
	s.purgeMu.Lock()
	if s.now().Sub(s.lastPurge) < 10*time.Minute {
		s.purgeMu.Unlock()
		return
	}
	s.lastPurge = s.now()
	s.purgeMu.Unlock()
	if _, err := s.repo.PurgeExpiredJTIs(ctx, s.now()); err != nil {
		s.log.Warn("ci replay purge failed", "error", logger.SanitizeError(err))
	}
}

// ------------------------------------------------------------- run access --

// Authenticate returns the run an unexpired upload token belongs to.
func (s *Service) Authenticate(ctx context.Context, token string) (*cirun.Run, error) {
	if !cirun.LooksLikeToken(token) {
		return nil, cirun.ErrRunNotFound
	}
	return s.repo.GetRunByTokenHash(ctx, cirun.HashToken(token), s.now())
}

// ------------------------------------------------------------------ upload --

// UploadReport applies a report to the run's repository and records what it
// sighted for the gate. The report may name only the run's repository; the
// branch and commit come from the verified token, never from the report.
func (s *Service) UploadReport(ctx context.Context, run *cirun.Run, report *ctis.Report) (*ingest.Output, error) {
	if report == nil {
		return nil, fmt.Errorf("%w: report is required", shared.ErrValidation)
	}
	if err := ScopeReport(report, run); err != nil {
		return nil, err
	}
	// The run status and report count on run are the snapshot of the token
	// lookup; the slot is taken atomically against the stored run, so
	// concurrent uploads (or the files of one ZIP) cannot pass the cap or
	// land after the verdict.
	if err := s.repo.ReserveRunReport(ctx, run.TenantID, run.ID); err != nil {
		return nil, err
	}
	out, err := s.ingester.IngestForCIRun(ctx, run.TenantID, run.ID, run.Repository, report)
	if err != nil {
		return nil, err
	}
	if err := s.repo.RecordRunReport(ctx, run.TenantID, run.ID, out.SightedFingerprints); err != nil {
		if errors.Is(err, cirun.ErrRunEvaluated) {
			// Judged while this report was ingested: the verdict did not
			// see it, and the job must know.
			return nil, err
		}
		return nil, fmt.Errorf("record run findings: %w", err)
	}
	// The tool block is self-declared: a label on the run, sanitized and
	// capped, never part of an identity.
	if report.Tool != nil && report.Tool.Name != "" {
		if err := s.repo.RecordRunTools(ctx, run.TenantID, run.ID,
			[]cirun.ToolLabel{{Name: report.Tool.Name, Version: report.Tool.Version}}); err != nil {
			s.log.Warn("ci run tools not recorded", "run_id", run.ID.String(), "error", logger.SanitizeError(err))
		}
		s.refreshPipeline(ctx, run.TenantID, run.PipelineID)
	}
	s.suggestImageLinks(ctx, run, report)
	s.requestInlineIgnores(ctx, run, report)
	s.auditUpload(ctx, run, report, out)
	return out, nil
}

// auditUpload records a report the run uploaded: who (the CI identity from
// the verified token), which job, the tool label and the counts.
func (s *Service) auditUpload(ctx context.Context, run *cirun.Run, report *ctis.Report, out *ingest.Output) {
	tool := ""
	if report.Tool != nil {
		tool = cirun.SanitizeLabel(report.Tool.Name, 100)
	}
	ev := auditapp.NewSuccessEvent(auditdom.ActionCIRunResultsUploaded, auditdom.ResourceTypeCIRun, run.ID.String()).
		WithResourceName(run.Repository).
		WithMessage(fmt.Sprintf("CI run on %s at %s uploaded %d finding(s)%s", run.Repository, shortSHA(run.CommitSHA),
			len(report.Findings), nonEmptyPrefix(" from ", tool))).
		WithMetadata("findings", len(report.Findings)).
		WithMetadata("findings_sighted", len(out.SightedFingerprints)).
		WithMetadata("tool", tool).
		WithMetadata("commit_sha", run.CommitSHA).
		WithMetadata("pipeline_run_id", run.ExternalRunID).
		WithMetadata("job_id", run.ExternalJobID)
	s.logAudit(ctx, run.TenantID, Actor{Email: ciActor(cirun.Claims{Provider: run.Provider, Actor: run.Actor})}, ev)
}

func nonEmptyPrefix(prefix, s string) string {
	if s == "" {
		return ""
	}
	return prefix + s
}

// repoAssetRef is the report-local id of the run's repository asset.
const repoAssetRef = "ci-repository"

// ScopeReport limits a report to the run's repository: every asset must be
// that repository (else ErrReportOutOfScope), every finding is attached to
// it, and the branch information is the run's.
func ScopeReport(report *ctis.Report, run *cirun.Run) error {
	want := asset.NormalizeName(run.Repository, asset.AssetTypeRepository, "")
	refs := map[string]bool{}
	repoAsset := ctis.Asset{Type: ctis.AssetTypeRepository, Value: run.Repository}
	for i := range report.Assets {
		a := &report.Assets[i]
		if a.Type != ctis.AssetTypeRepository || asset.NormalizeName(a.Value, asset.AssetTypeRepository, "") != want {
			return ErrReportOutOfScope
		}
		if a.ID != "" {
			refs[a.ID] = true
		}
		if i == 0 {
			repoAsset = *a
		}
	}
	repoAsset.ID, repoAsset.Value = repoAssetRef, run.Repository
	for i := range report.Findings {
		f := &report.Findings[i]
		if f.AssetRef != "" && !refs[f.AssetRef] {
			return ErrReportOutOfScope
		}
		if f.AssetValue != "" && asset.NormalizeName(f.AssetValue, asset.AssetTypeRepository, "") != want {
			return ErrReportOutOfScope
		}
		f.AssetRef, f.AssetValue, f.AssetType = repoAssetRef, "", ""
	}
	report.Assets = []ctis.Asset{repoAsset}
	report.Metadata.Branch = &ctis.BranchInfo{
		Name:            cirun.ReportBranchName(run.Branch, run.Event, run.PullRequest, run.Fork),
		IsDefaultBranch: run.IsDefaultBranch && !run.Fork,
		CommitSHA:       run.CommitSHA,
		BaseBranch:      run.DefaultBranch,
		RepositoryURL:   "https://" + run.Repository,
	}
	if n := parsePR(run.PullRequest); n > 0 {
		report.Metadata.Branch.PullRequestNumber = n
	}
	return nil
}

func parsePR(s string) int {
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' || n > 1_000_000_000 {
			return 0
		}
		n = n*10 + int(r-'0')
	}
	return n
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func nonEmpty(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

// CleanBaseRef is the base branch a run records: only for a run that is not
// on the branch itself.
func CleanBaseRef(c cirun.Claims) string {
	b := cirun.CleanBranchName(c.BaseRef)
	if b == c.Branch {
		return ""
	}
	return b
}
