// Package contentsource is the application service of rule sources: an
// organization's git repositories of rules, templates and wordlists that the
// platform alone fetches, lints, signs and keeps as immutable snapshots, with
// candidates, promotion and rollback. Design and threat model:
// docs/architecture/content-sources.md.
//
// Isolation: every organization operation takes the tenant from the
// authenticated caller and reaches only that tenant's rows; platform sources
// (tenant_id NULL) are read-only here and shown through a projection that
// leaves out where and how they are fetched. A credential is write-only:
// encrypted with the installation key, bound to the source id and host, and
// never returned.
package contentsource

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/contentpack"
	"github.com/openctemio/openctem/api/internal/infra/fetchers"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	cpdom "github.com/openctemio/openctem/api/pkg/domain/contentpack"
	dom "github.com/openctemio/openctem/api/pkg/domain/contentsource"
	"github.com/openctemio/openctem/api/pkg/domain/limits"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// AuditLogger records audit events. *auditapp.AuditService implements it.
type AuditLogger interface {
	LogEvent(ctx context.Context, actx auditapp.AuditContext, event auditapp.AuditEvent) error
}

// PackStore stores snapshots as signed content packs
// (*contentpack.Service implements it).
type PackStore interface {
	StoreSnapshot(ctx context.Context, in contentpack.SnapshotInput) (*cpdom.Pack, error)
	DeleteSourcePack(ctx context.Context, tenantID, id shared.ID) error
}

// Limits is the entitlement service: per-organization limits and features
// (*entitlement.Service implements it). nil means no limits apply.
type Limits interface {
	Check(ctx context.Context, tenantID shared.ID, key limits.Key, delta int) error
	Limit(ctx context.Context, tenantID shared.ID, key limits.Key) (int, error)
	Allowed(ctx context.Context, tenantID shared.ID, feature string) (bool, error)
	Usable(ctx context.Context, tenantID shared.ID, feature string) (bool, error)
}

// Encryptor seals credentials (crypto.Encryptor implements it).
type Encryptor interface {
	EncryptString(plaintext string) (string, error)
	DecryptString(encoded string) (string, error)
}

// Service manages rule sources.
type Service struct {
	repo    dom.Repository
	packs   PackStore
	limits  Limits
	enc     Encryptor
	audit   AuditLogger
	logger  *logger.Logger
	now     func() time.Time
	jitter  func() float64
	fetch   func(context.Context, fetchers.GitRequest) (*fetchers.GitSnapshot, error)
	private func(rawURL string) (bool, error)

	modules   ModuleGuard
	syncing   sync.Map // source id -> struct{}: one sync per source per process
	fetches   chan struct{}
	testLimit *windowLimiter
	hookLimit *windowLimiter
}

// NewService creates the service. enc is required to store credentials;
// limits and audit may be nil (no limits; tests).
func NewService(repo dom.Repository, packs PackStore, lim Limits, enc Encryptor, audit AuditLogger, log *logger.Logger) *Service {
	return &Service{
		repo: repo, packs: packs, limits: lim, enc: enc, audit: audit,
		logger:    log.With("service", "content_source"),
		now:       time.Now,
		jitter:    randomJitter,
		fetch:     fetchers.SnapshotGit,
		private:   fetchers.RemoteIsPrivate,
		fetches:   make(chan struct{}, MaxConcurrentFetches),
		testLimit: newWindowLimiter(TestCallsPerHour, time.Hour),
		hookLimit: newWindowLimiter(WebhookCallsPerHour, time.Hour),
	}
}

// SetFetcher replaces how a source is fetched and how a private host is
// recognized (tests; a different transport).
func (s *Service) SetFetcher(fetch func(context.Context, fetchers.GitRequest) (*fetchers.GitSnapshot, error), private func(string) (bool, error)) {
	if fetch != nil {
		s.fetch = fetch
	}
	if private != nil {
		s.private = private
	}
}

// ModuleGuard answers which modules an organization turned off
// (*app.ModuleService implements it).
type ModuleGuard interface {
	TenantDisabledModules(ctx context.Context, tenantID string) map[string]bool
}

// SetModuleGuard makes the sync worker skip organizations that turned the
// rule sources module off: their sources are not fetched while it is off.
func (s *Service) SetModuleGuard(g ModuleGuard) { s.modules = g }

// SetClock replaces the clock (tests).
func (s *Service) SetClock(now func() time.Time) { s.now = now }

// Instance safety limits (they apply on every installation, whatever the
// organization's limits).
const (
	// TestCallsPerHour bounds Test per source (or per organization for an
	// unsaved source).
	TestCallsPerHour = 10
	// WebhookCallsPerHour bounds accepted webhook calls per source.
	WebhookCallsPerHour = 60
	// MaxConcurrentFetches bounds the repository fetches (Test and sync)
	// one server process runs at once: each clone lands on the server's
	// disk and in its memory. A Test over the cap is refused with 503 and
	// the sync worker waits for its next run.
	MaxConcurrentFetches = 3
)

// SetMaxConcurrentFetches replaces the cap of concurrent fetches (tests).
func (s *Service) SetMaxConcurrentFetches(n int) { s.fetches = make(chan struct{}, n) }

// acquireFetch takes a fetch slot without waiting; release gives it back.
func (s *Service) acquireFetch() (release func(), ok bool) {
	select {
	case s.fetches <- struct{}{}:
		return func() { <-s.fetches }, true
	default:
		return nil, false
	}
}

// Actor is the caller of an organization operation.
type Actor struct {
	TenantID shared.ID
	UserID   *shared.ID
	Audit    auditapp.AuditContext
	// CanApprove: the caller holds scans:sources:approve (set by the
	// handler from the request's permissions). Weakening a source's review
	// needs it.
	CanApprove bool
}

func (s *Service) logAudit(ctx context.Context, actx auditapp.AuditContext, tenantID *shared.ID, ev auditapp.AuditEvent) {
	if s.audit == nil {
		return
	}
	if tenantID != nil {
		actx.TenantID = tenantID.String()
	}
	if err := s.audit.LogEvent(ctx, actx, ev); err != nil {
		s.logger.Warn("failed to record audit event", "action", string(ev.Action), "error", err)
	}
}

func sourceEvent(action auditdom.Action, src *dom.Source, msg string) auditapp.AuditEvent {
	return auditapp.NewSuccessEvent(action, auditdom.ResourceTypeContentSource, src.ID.String()).
		WithResourceName(src.Slug).
		WithMessage(msg).
		WithMetadata("kind", string(src.Kind)).
		WithMetadata("host", src.Host())
}

// --- limits -----------------------------------------------------------------

func (s *Service) checkLimit(ctx context.Context, tenantID shared.ID, key limits.Key, delta int) error {
	if s.limits == nil {
		return nil
	}
	return s.limits.Check(ctx, tenantID, key, delta)
}

// limitValue reads an uncounted key (a floor or a per-item cap): Unlimited
// when no limit applies; an error refuses (fail-closed).
func (s *Service) limitValue(ctx context.Context, tenantID shared.ID, key limits.Key) (int, error) {
	if s.limits == nil {
		return limits.Unlimited, nil
	}
	v, err := s.limits.Limit(ctx, tenantID, key)
	if err != nil {
		return 0, &limits.ErrLimitReached{Key: key, Unavailable: true}
	}
	return v, nil
}

// requireFeature refuses a change that needs a denied feature.
func (s *Service) requireFeature(ctx context.Context, tenantID shared.ID, feature string) error {
	if s.limits == nil {
		return nil
	}
	ok, err := s.limits.Allowed(ctx, tenantID, feature)
	if err != nil {
		return &limits.ErrFeatureDenied{Feature: feature, Unavailable: true}
	}
	if !ok {
		return &limits.ErrFeatureDenied{Feature: feature}
	}
	return nil
}

// featureUsable reports whether a feature already in use may keep running
// (allowed, or inside its read-only grace). An error answers false.
func (s *Service) featureUsable(ctx context.Context, tenantID shared.ID, feature string) bool {
	if s.limits == nil {
		return true
	}
	ok, err := s.limits.Usable(ctx, tenantID, feature)
	return err == nil && ok
}

// syncFloor is the shortest schedule the organization may save.
func (s *Service) syncFloor(ctx context.Context, tenantID shared.ID) (int, error) {
	v, err := s.limitValue(ctx, tenantID, limits.ContentSyncFloorMinutes)
	if err != nil {
		return 0, err
	}
	if v < dom.MinSyncIntervalMinutes {
		return dom.MinSyncIntervalMinutes, nil
	}
	return v, nil
}

// checkHost refuses a host in a private network unless the organization
// has the private_git feature. The SSRF guard decides which private ranges
// are reachable at all.
func (s *Service) checkHost(ctx context.Context, tenantID shared.ID, rawURL string) error {
	private, err := s.private(rawURL)
	if err != nil {
		return shared.NewDomainError("VALIDATION", err.Error(), shared.ErrValidation)
	}
	if private {
		return s.requireFeature(ctx, tenantID, limits.FeatureContentPrivateGit)
	}
	return nil
}

// --- organization operations -----------------------------------------------

// CreateInput is a new organization source.
type CreateInput struct {
	Slug            string
	Name            string
	Description     string
	Kind            string
	URL             string
	Ref             string
	Path            string
	CAPEM           string
	LicenseSPDX     string
	LicenseService  *bool
	Policy          string
	SyncIntervalMin *int
	Enabled         *bool
}

// Create adds an organization source. It refuses an addition over the
// content_sources limit and a review policy or private host the
// organization may not use.
func (s *Service) Create(ctx context.Context, a Actor, in CreateInput) (*dom.Source, error) {
	now := s.now().UTC()
	src, err := dom.NewTenantSource(a.TenantID, strings.TrimSpace(in.Slug), in.Name, dom.Kind(in.Kind),
		dom.GitConfig{URL: in.URL, Ref: in.Ref, Path: in.Path}, a.UserID, now)
	if err != nil {
		return nil, err
	}
	if err := src.Rename(in.Name, in.Description); err != nil {
		return nil, err
	}
	if err := src.SetCAPEM(in.CAPEM); err != nil {
		return nil, err
	}
	serviceUse := true
	if in.LicenseService != nil {
		serviceUse = *in.LicenseService
	}
	if err := src.SetLicense(in.LicenseSPDX, serviceUse); err != nil {
		return nil, err
	}
	if in.Policy != "" {
		if err := src.SetPolicy(dom.PromotionPolicy(in.Policy)); err != nil {
			return nil, err
		}
	}
	if in.Enabled != nil {
		src.Enabled = *in.Enabled
	}
	floor, err := s.syncFloor(ctx, a.TenantID)
	if err != nil {
		return nil, err
	}
	interval := dom.DefaultSyncIntervalMinutes
	if interval < floor {
		interval = floor
	}
	if in.SyncIntervalMin != nil {
		interval = *in.SyncIntervalMin
	}
	if err := src.SetSchedule(interval, floor, now); err != nil {
		return nil, err
	}
	src.NextSyncAt = &now // first sync right away
	if src.SyncIntervalMin == 0 {
		src.NextSyncAt = nil
	}
	if src.Policy == dom.PolicyReview {
		if err := s.requireFeature(ctx, a.TenantID, limits.FeatureContentReviewPolicy); err != nil {
			return nil, err
		}
	}
	if err := s.checkHost(ctx, a.TenantID, src.URL); err != nil {
		return nil, err
	}
	if src.PlatformFetched() {
		if err := s.checkLimit(ctx, a.TenantID, limits.ContentSources, 1); err != nil {
			return nil, err
		}
	}
	if err := s.repo.Create(ctx, src); err != nil {
		return nil, err
	}
	if src.Enabled && src.SyncIntervalMin == 0 {
		_ = s.repo.RequestSync(ctx, a.TenantID, src.ID, now)
	}
	s.logAudit(ctx, a.Audit, src.TenantID, sourceEvent(auditdom.ActionContentSourceCreated, src,
		fmt.Sprintf("Rule source '%s' created (%s from %s)", src.Slug, src.Kind, src.Host())).
		WithMetadata("policy", string(src.Policy)))
	return src, nil
}

// Get returns a source visible to the organization: its own, or an offered
// platform source. Anything else is not found.
func (s *Service) Get(ctx context.Context, tenantID, id shared.ID) (*dom.Source, error) {
	return s.repo.GetVisible(ctx, tenantID, id)
}

// List returns the organization's sources and the offered platform sources.
func (s *Service) List(ctx context.Context, tenantID shared.ID, f dom.ListFilter) ([]*dom.Source, error) {
	return s.repo.ListVisible(ctx, tenantID, f)
}

// UpdateInput changes an organization source; nil fields stay.
type UpdateInput struct {
	Name            *string
	Description     *string
	URL             *string
	Ref             *string
	Path            *string
	CAPEM           *string
	LicenseSPDX     *string
	LicenseService  *bool
	Policy          *string
	SyncIntervalMin *int
	Enabled         *bool
}

// ownSource loads the organization's own source; a platform source answers
// ErrPlatformReadOnly when visible, not found otherwise.
func (s *Service) ownSource(ctx context.Context, tenantID, id shared.ID) (*dom.Source, error) {
	src, err := s.repo.Get(ctx, tenantID, id)
	if err == nil {
		return src, nil
	}
	if !errors.Is(err, dom.ErrNotFound) {
		return nil, err
	}
	if vis, verr := s.repo.GetVisible(ctx, tenantID, id); verr == nil && vis.IsPlatform() {
		return nil, dom.ErrPlatformReadOnly
	}
	return nil, err
}

// Update changes an organization source. A change of what it fetches (URL,
// ref, path, CA) records the caller as the last to change it (four-eyes) and
// queues a sync; a new host clears the stored credential.
func (s *Service) Update(ctx context.Context, a Actor, id shared.ID, in UpdateInput) (*dom.Source, error) {
	src, err := s.ownSource(ctx, a.TenantID, id)
	if err != nil {
		return nil, err
	}
	now := s.now().UTC()
	name, desc := src.Name, src.Description
	if in.Name != nil {
		name = *in.Name
	}
	if in.Description != nil {
		desc = *in.Description
	}
	if err := src.Rename(name, desc); err != nil {
		return nil, err
	}
	fetchChanged, hostChanged, err := s.applyFetchChanges(ctx, a.TenantID, src, in)
	if err != nil {
		return nil, err
	}
	if in.LicenseSPDX != nil || in.LicenseService != nil {
		spdx, use := src.LicenseSPDX, src.LicenseServiceUse
		if in.LicenseSPDX != nil {
			spdx = *in.LicenseSPDX
		}
		if in.LicenseService != nil {
			use = *in.LicenseService
		}
		if err := src.SetLicense(spdx, use); err != nil {
			return nil, err
		}
	}
	oldPolicy := src.Policy
	if in.Policy != nil {
		if err := src.SetPolicy(dom.PromotionPolicy(*in.Policy)); err != nil {
			return nil, err
		}
		if src.Policy == dom.PolicyReview && oldPolicy != dom.PolicyReview {
			if err := s.requireFeature(ctx, a.TenantID, limits.FeatureContentReviewPolicy); err != nil {
				return nil, err
			}
		}
		// SECURITY: review exists so a second member approves what the
		// source delivers. Turning it off lets the next sync promote on its
		// own, so it takes the approval permission, not only write.
		if oldPolicy == dom.PolicyReview && src.Policy != dom.PolicyReview && !a.CanApprove {
			s.logAudit(ctx, a.Audit, src.TenantID, auditapp.NewDeniedEvent(auditdom.ActionContentSourcePolicyChanged,
				auditdom.ResourceTypeContentSource, src.ID.String(), "weakening the promotion policy needs the approval permission").
				WithResourceName(src.Slug).WithMetadata("from", string(oldPolicy)).WithMetadata("to", string(src.Policy)))
			return nil, dom.ErrApprovalRequired
		}
	}
	if in.SyncIntervalMin != nil && *in.SyncIntervalMin != src.SyncIntervalMin {
		floor, err := s.syncFloor(ctx, a.TenantID)
		if err != nil {
			return nil, err
		}
		if err := src.SetSchedule(*in.SyncIntervalMin, floor, now); err != nil {
			return nil, err
		}
	}
	if in.Enabled != nil {
		src.Enabled = *in.Enabled
	}
	if fetchChanged || oldPolicy != src.Policy {
		src.MarkConfigChanged(a.UserID, now)
	}
	if err := s.repo.Update(ctx, src); err != nil {
		return nil, err
	}
	if fetchChanged && src.Enabled {
		_ = s.repo.RequestSync(ctx, a.TenantID, src.ID, now)
	}
	s.logAudit(ctx, a.Audit, src.TenantID, sourceEvent(auditdom.ActionContentSourceUpdated, src,
		fmt.Sprintf("Rule source '%s' updated", src.Slug)).
		WithMetadata("fetch_changed", fetchChanged).
		WithMetadata("enabled", src.Enabled))
	if hostChanged {
		s.logAudit(ctx, a.Audit, src.TenantID, sourceEvent(auditdom.ActionContentSourceCredentialCleared, src,
			fmt.Sprintf("Credential of rule source '%s' cleared: its host changed", src.Slug)).
			WithMetadata("reason", "host changed"))
	}
	if oldPolicy != src.Policy {
		ev := sourceEvent(auditdom.ActionContentSourcePolicyChanged, src,
			fmt.Sprintf("Promotion policy of rule source '%s' changed from %s to %s", src.Slug, oldPolicy, src.Policy)).
			WithMetadata("from", string(oldPolicy)).WithMetadata("to", string(src.Policy))
		if src.Policy == dom.PolicyAuto {
			ev = ev.WithSeverity(auditdom.SeverityHigh)
		}
		s.logAudit(ctx, a.Audit, src.TenantID, ev)
	}
	return src, nil
}

// applyFetchChanges applies the changes to what the source fetches (URL,
// ref, path, CA) and reports whether anything changed and whether the host
// did (which clears the credential).
func (s *Service) applyFetchChanges(ctx context.Context, tenantID shared.ID, src *dom.Source, in UpdateInput) (fetchChanged, hostChanged bool, err error) {
	if in.URL != nil || in.Ref != nil || in.Path != nil {
		c := dom.GitConfig{URL: src.URL, Ref: src.Ref, Path: src.Path}
		if in.URL != nil {
			c.URL = *in.URL
		}
		if in.Ref != nil {
			c.Ref = *in.Ref
		}
		if in.Path != nil {
			c.Path = *in.Path
		}
		before := [3]string{src.URL, src.Ref, src.Path}
		if hostChanged, err = src.SetGit(c); err != nil {
			return false, false, err
		}
		fetchChanged = before != [3]string{src.URL, src.Ref, src.Path}
		if in.URL != nil {
			if err := s.checkHost(ctx, tenantID, src.URL); err != nil {
				return false, false, err
			}
		}
	}
	if in.CAPEM != nil && strings.TrimSpace(*in.CAPEM) != src.CAPEM {
		if err := src.SetCAPEM(*in.CAPEM); err != nil {
			return false, false, err
		}
		fetchChanged = true
	}
	return fetchChanged, hostChanged, nil
}

// Delete deletes an organization source and its snapshots.
func (s *Service) Delete(ctx context.Context, a Actor, id shared.ID) error {
	src, err := s.ownSource(ctx, a.TenantID, id)
	if err != nil {
		return err
	}
	if err := s.repo.Delete(ctx, a.TenantID, id); err != nil {
		return err
	}
	s.logAudit(ctx, a.Audit, src.TenantID, sourceEvent(auditdom.ActionContentSourceDeleted, src,
		fmt.Sprintf("Rule source '%s' deleted", src.Slug)))
	return nil
}

// RequestSync queues a sync of an organization source ("Sync now"); the sync
// worker runs it within a minute.
func (s *Service) RequestSync(ctx context.Context, a Actor, id shared.ID) error {
	src, err := s.ownSource(ctx, a.TenantID, id)
	if err != nil {
		return err
	}
	if !src.Enabled {
		return dom.ErrDisabled
	}
	if err := s.repo.RequestSync(ctx, a.TenantID, id, s.now().UTC()); err != nil {
		return err
	}
	s.logAudit(ctx, a.Audit, src.TenantID, sourceEvent(auditdom.ActionContentSourceSyncRequested, src,
		fmt.Sprintf("Sync of rule source '%s' requested", src.Slug)))
	return nil
}

// ListSnapshots lists a visible source's snapshots, newest first.
func (s *Service) ListSnapshots(ctx context.Context, tenantID, sourceID shared.ID, limit, offset int) ([]*dom.Snapshot, int, error) {
	if limit <= 0 || limit > 100 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	if _, err := s.repo.GetVisible(ctx, tenantID, sourceID); err != nil {
		return nil, 0, err
	}
	return s.repo.ListSnapshotsVisible(ctx, tenantID, sourceID, limit, offset)
}

// GetSnapshot returns a snapshot of a visible source.
func (s *Service) GetSnapshot(ctx context.Context, tenantID, sourceID, id shared.ID) (*dom.Snapshot, error) {
	return s.repo.GetSnapshotVisible(ctx, tenantID, sourceID, id)
}

// Promote makes a candidate current. A snapshot that needs review cannot be
// promoted by a member who changed the configuration it was synced from
// (the snapshot records them), nor by the member who last changed what the
// source fetches, nor by a caller without a user (four-eyes).
func (s *Service) Promote(ctx context.Context, a Actor, sourceID, snapshotID shared.ID) error {
	src, err := s.ownSource(ctx, a.TenantID, sourceID)
	if err != nil {
		return err
	}
	var promoted *dom.Snapshot
	err = s.repo.Promote(ctx, a.TenantID, sourceID, snapshotID, a.UserID, s.now().UTC(), func(locked *dom.Source, sn *dom.Snapshot) error {
		if sn.ReviewRequired {
			if a.UserID == nil || sn.AuthoredBy(*a.UserID) ||
				(locked.ConfigChangedBy != nil && locked.ConfigChangedBy.Equals(*a.UserID)) {
				return dom.ErrFourEyes
			}
		}
		promoted = sn
		return nil
	})
	if err != nil {
		if errors.Is(err, dom.ErrFourEyes) {
			s.logAudit(ctx, a.Audit, src.TenantID, auditapp.NewDeniedEvent(auditdom.ActionContentSourcePromoted,
				auditdom.ResourceTypeContentSource, src.ID.String(), "four-eyes: the promoter changed the source configuration").
				WithResourceName(src.Slug).WithMetadata("snapshot_id", snapshotID.String()))
		}
		return err
	}
	s.logAudit(ctx, a.Audit, src.TenantID, sourceEvent(auditdom.ActionContentSourcePromoted, src,
		fmt.Sprintf("Snapshot %s of rule source '%s' promoted", shortSHA(promoted.UpstreamRevision), src.Slug)).
		WithMetadata("snapshot_id", promoted.ID.String()).
		WithMetadata("digest", promoted.Digest).
		WithMetadata("commit", promoted.UpstreamRevision).
		WithMetadata("review_required", promoted.ReviewRequired))
	return nil
}

// Reject rejects a candidate.
func (s *Service) Reject(ctx context.Context, a Actor, sourceID, snapshotID shared.ID, reason string) error {
	src, err := s.ownSource(ctx, a.TenantID, sourceID)
	if err != nil {
		return err
	}
	reason = strings.TrimSpace(reason)
	if len(reason) > 500 {
		return shared.NewDomainError("VALIDATION", "reason must be at most 500 characters", shared.ErrValidation)
	}
	if err := s.repo.Reject(ctx, a.TenantID, sourceID, snapshotID, a.UserID, reason, s.now().UTC()); err != nil {
		return err
	}
	s.logAudit(ctx, a.Audit, src.TenantID, sourceEvent(auditdom.ActionContentSourceRejected, src,
		fmt.Sprintf("Candidate snapshot of rule source '%s' rejected", src.Slug)).
		WithMetadata("snapshot_id", snapshotID.String()).WithMetadata("reason", reason))
	return nil
}

// Rollback makes the previous snapshot current again (and the current one
// previous, so the rollback can be undone the same way).
func (s *Service) Rollback(ctx context.Context, a Actor, sourceID shared.ID) (*dom.Source, error) {
	if _, err := s.ownSource(ctx, a.TenantID, sourceID); err != nil {
		return nil, err
	}
	src, err := s.repo.Rollback(ctx, a.TenantID, sourceID)
	if err != nil {
		return nil, err
	}
	s.logAudit(ctx, a.Audit, src.TenantID, sourceEvent(auditdom.ActionContentSourceRolledBack, src,
		fmt.Sprintf("Rule source '%s' rolled back to its previous snapshot", src.Slug)).
		WithMetadata("current_snapshot_id", idString(src.CurrentSnapshotID)))
	return src, nil
}

func idString(id *shared.ID) string {
	if id == nil {
		return ""
	}
	return id.String()
}

func shortSHA(sha string) string {
	if len(sha) > 12 {
		return sha[:12]
	}
	return sha
}
