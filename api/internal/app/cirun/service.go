// Package cirun runs the CI side of the platform: the OIDC token exchange
// that gives a pipeline run a short-lived upload token, the upload of its
// results, and the central gate verdict.
//
// Design: docs/rfcs/RFC-051-ci-runner-identity-and-gate.md.
package cirun

import (
	"context"
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
	// Versions is the sensor release channel a runner's version is judged
	// against (SENSOR_LATEST_VERSION, SENSOR_MIN_VERSION).
	Versions cirun.StatusPolicy
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
	RunID     string
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

	tok, claims, err := s.verify(ctx, in.IDToken, configs)
	if err != nil {
		s.log.Info("ci exchange refused: token did not verify", "tenant_id", tenantID.String(),
			"issuer", logger.SanitizeValue(issuer), "error", logger.SanitizeError(err))
		return nil, ErrExchangeRefused
	}

	cfg, refusals := admit(configs, tok, claims)
	if cfg == nil {
		s.auditRefusal(ctx, tenantID, in, claims, refusals)
		return nil, ErrExchangeRefused
	}
	// The pipeline's identity comes from the verified claims only: a token
	// without an immutable repository id or a usable workflow path is not
	// admitted, whatever the trust configuration says.
	key, refusal := cirun.PipelineKeyFromClaims(cfg.Provider, cfg.Issuer, claims)
	if refusal != nil {
		s.auditRefusal(ctx, tenantID, in, claims, []*cirun.Refusal{refusal})
		return nil, ErrExchangeRefused
	}
	fresh, err := s.repo.ClaimJTI(ctx, tok.Issuer, tok.JTI, tok.ExpiresAt.Add(time.Hour))
	if err != nil {
		return nil, fmt.Errorf("record token id: %w", err)
	}
	if !fresh {
		s.auditRefusal(ctx, tenantID, in, claims, []*cirun.Refusal{{Code: "replay", Detail: "this token was exchanged before"}})
		return nil, ErrExchangeRefused
	}

	var out *ExchangeOutput
	if strings.TrimSpace(in.RunID) != "" {
		out, err = s.continueRun(ctx, tenantID, cfg, claims, in.RunID)
		if errors.Is(err, ErrExchangeRefused) {
			s.auditRefusal(ctx, tenantID, in, claims, []*cirun.Refusal{{Code: "run_mismatch",
				Detail: "the token does not belong to the run it asked to continue"}})
		}
	} else {
		out, err = s.createRun(ctx, tenantID, cfg, claims, key, in.UserAgent)
		if errors.Is(err, cirun.ErrPipelineCap) {
			s.auditRefusal(ctx, tenantID, in, claims, []*cirun.Refusal{{Code: "pipeline_cap",
				Detail: "the organization or the trust configuration has the most CI pipelines it may have"}})
			return nil, ErrExchangeRefused
		}
	}
	if err != nil {
		return nil, err
	}
	_ = s.repo.TouchTrustConfig(ctx, tenantID, cfg.ID, s.now())
	s.auditIssued(ctx, tenantID, in, cfg, out)
	return out, nil
}

// verify tries the token against each distinct audience of the
// configurations; the first that verifies wins.
func (s *Service) verify(ctx context.Context, raw string, configs []cirun.TrustConfig) (*oidc.WorkloadToken, cirun.Claims, error) {
	if s.verifier == nil {
		return nil, cirun.Claims{}, errors.New("no token verifier")
	}
	tried := map[string]bool{}
	var lastErr error
	for _, c := range configs {
		if tried[c.Audience] {
			continue
		}
		tried[c.Audience] = true
		tok, err := s.verifier.VerifyWorkloadToken(ctx, raw, oidc.WorkloadExpectations{Issuer: c.Issuer, Audience: c.Audience})
		if err != nil {
			lastErr = err
			continue
		}
		var claims cirun.Claims
		switch c.Provider {
		case cirun.ProviderGitHub:
			claims = cirun.ParseGitHubClaims(tok.Claims)
		case cirun.ProviderGitLab:
			claims = cirun.ParseGitLabClaims(tok.Claims)
		}
		claims.Audience = c.Audience
		return tok, claims, nil
	}
	if lastErr == nil {
		lastErr = errors.New("no audience to verify against")
	}
	return nil, cirun.Claims{}, lastErr
}

// admit returns the first configuration (with the token's audience) whose
// rules admit the claims, or the refusals of each.
func admit(configs []cirun.TrustConfig, tok *oidc.WorkloadToken, claims cirun.Claims) (*cirun.TrustConfig, []*cirun.Refusal) {
	var refusals []*cirun.Refusal
	for i := range configs {
		c := &configs[i]
		if c.Audience != claims.Audience || c.Issuer != tok.Issuer {
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
	key cirun.PipelineKey, userAgent string) (*ExchangeOutput, error) {
	repoName := cirun.CanonicalRepository(cfg.Provider, cfg.Issuer, c.Repository)
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
	_, sensorVersion := sensor.ResolveBuild(sensor.BuildReport{}, "", userAgent, now)
	token, hash, err := cirun.NewToken()
	if err != nil {
		return nil, err
	}
	expires := now.Add(cirun.TokenTTL)
	run := &cirun.Run{
		ID:                shared.NewID(),
		TenantID:          tenantID,
		TrustConfigID:     &cfgID,
		RepositoryAssetID: repoAsset.ID(),
		Provider:          cfg.Provider,
		Issuer:            cfg.Issuer,
		Repository:        repoAsset.Name(),
		Ref:               truncate(c.Ref, 500),
		Branch:            truncate(c.Branch, 255),
		CommitSHA:         truncate(c.SHA, 64),
		PullRequest:       truncate(c.PullRequest, 32),
		DefaultBranch:     defaultBranch,
		IsDefaultBranch:   c.Branch != "" && c.PullRequest == "" && c.Branch == defaultBranch,
		Event:             truncate(c.Event, 64),
		Environment:       truncate(c.Environment, 255),
		Actor:             truncate(c.Actor, 255),
		ExternalRunID:     truncate(c.RunID, 64),
		RunAttempt:        truncate(c.RunAttempt, 16),
		Workflow:          truncate(c.Workflow, 500),
		PipelineURL:       truncate(cirun.PipelineURL(cfg.Provider, cfg.Issuer, c), 1000),
		Fork:              c.IsForkEvent(),
		TokenHash:         hash,
		TokenExpiresAt:    &expires,
		Status:            cirun.StatusRunning,
		PipelineID:        &pipeline.ID,
		SensorVersion:     sensor.NormalizeVersion(sensorVersion),
		TemplateRef:       templateRef,
		CreatedAt:         now,
		UpdatedAt:         now,
	}
	if err := s.repo.CreateRun(ctx, run); err != nil {
		return nil, fmt.Errorf("create run: %w", err)
	}
	s.refreshPipeline(ctx, tenantID, run.PipelineID)
	return &ExchangeOutput{Run: run, Token: token, ExpiresAt: expires}, nil
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

// continueRun issues a fresh token for an existing run of the same pipeline
// run: same tenant, repository, commit and CI run id, not yet evaluated and
// recent. Anything else is ErrExchangeRefused.
func (s *Service) continueRun(ctx context.Context, tenantID shared.ID, cfg *cirun.TrustConfig, c cirun.Claims, rawRunID string) (*ExchangeOutput, error) {
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
	if run.Repository != asset.NormalizeName(cirun.CanonicalRepository(cfg.Provider, cfg.Issuer, c.Repository), asset.AssetTypeRepository, "") ||
		run.CommitSHA != c.SHA || run.ExternalRunID == "" || run.ExternalRunID != c.RunID || run.Issuer != cfg.Issuer ||
		run.Status != cirun.StatusRunning || now.Sub(run.CreatedAt) > MaxRunContinuation {
		return nil, ErrExchangeRefused
	}
	token, hash, err := cirun.NewToken()
	if err != nil {
		return nil, err
	}
	expires := now.Add(cirun.TokenTTL)
	if err := s.repo.RotateRunToken(ctx, tenantID, run.ID, hash, expires); err != nil {
		return nil, fmt.Errorf("rotate run token: %w", err)
	}
	run.TokenHash, run.TokenExpiresAt = hash, &expires
	return &ExchangeOutput{Run: run, Token: token, ExpiresAt: expires}, nil
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
		WithMetadata("commit_sha", c.SHA)
	for _, code := range codes {
		if code == "replay" {
			ev = ev.WithSeverity(auditdom.SeverityHigh)
		}
	}
	s.logAudit(ctx, tenantID, Actor{Email: ciActor(c), IP: in.ClientIP, UserAgent: in.UserAgent}, ev)
}

func (s *Service) auditIssued(ctx context.Context, tenantID shared.ID, in ExchangeInput, cfg *cirun.TrustConfig, out *ExchangeOutput) {
	r := out.Run
	ev := auditapp.NewSuccessEvent(auditdom.ActionCIRunTokenIssued, auditdom.ResourceTypeCIRun, r.ID.String()).
		WithResourceName(r.Repository).
		WithMessage(fmt.Sprintf("CI run on %s (%s) admitted by %q", r.Repository, nonEmpty(r.Branch, r.Ref), cfg.Name)).
		WithMetadata("trust_config_id", cfg.ID.String()).
		WithMetadata("trust_config", cfg.Name).
		WithMetadata("repository", r.Repository).
		WithMetadata("repository_asset_id", r.RepositoryAssetID.String()).
		WithMetadata("ref", r.Ref).
		WithMetadata("commit_sha", r.CommitSHA).
		WithMetadata("event", r.Event).
		WithMetadata("actor", r.Actor).
		WithMetadata("pipeline_run_id", r.ExternalRunID).
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
	if run.Status == cirun.StatusEvaluated {
		return nil, fmt.Errorf("%w: the run was already evaluated", shared.ErrConflict)
	}
	if err := ScopeReport(report, run); err != nil {
		return nil, err
	}
	out, err := s.ingester.IngestForCIRun(ctx, run.TenantID, run.ID, run.Repository, report)
	if err != nil {
		return nil, err
	}
	if err := s.repo.RecordRunReport(ctx, run.TenantID, run.ID, out.SightedFingerprints); err != nil {
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
	return out, nil
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
		Name:            run.Branch,
		IsDefaultBranch: run.IsDefaultBranch,
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
