// Package contentcatalog is the application service of the content
// catalog: offline import of signed bundles into the instance catalog, and
// per organization install, update, pin, rollback and uninstall with an
// optional approval step and an audit row per action.
//
// Design and threat model: docs/rfcs/RFC-099-content-packages.md.
package contentcatalog

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/contentpkg"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	dom "github.com/openctemio/openctem/api/pkg/domain/contentcatalog"
	notificationdom "github.com/openctemio/openctem/api/pkg/domain/notification"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Errors the handlers map.
var (
	// ErrVerification: the bundle did not verify (signature, digest, expiry,
	// format).
	ErrVerification = fmt.Errorf("%w: the content bundle was refused", shared.ErrValidation)
	// ErrRollback: the bundle is older than what the instance applied.
	ErrRollback = fmt.Errorf("%w: the content bundle is older than the applied catalog", shared.ErrConflict)
	// ErrRefused: an install, update or rollback is not allowed now.
	ErrRefused = fmt.Errorf("%w: refused", shared.ErrValidation)
	// ErrOwnRequest: nobody approves their own request.
	ErrOwnRequest = fmt.Errorf("%w: a request is approved by another person", shared.ErrForbidden)
)

const maxNote = 500

// AuditLogger records audit events. *auditapp.AuditService implements it.
type AuditLogger interface {
	LogEvent(ctx context.Context, actx auditapp.AuditContext, event auditapp.AuditEvent) error
}

// Service is the content catalog.
type Service struct {
	repo      dom.Repository
	roots     []string
	publisher contentpkg.PublisherVerifier
	audit     AuditLogger
	logger    *logger.Logger
	now       func() time.Time
	release   func() string
	importMu  sync.Mutex

	publishing *Publishing

	notifier Notifier
}

// NewService creates the service. roots are the key ids of the catalog
// roots this instance trusts (none: every import is refused). publisher
// verifies keyless publisher signatures. release returns the running
// platform release (compatibility checks).
func NewService(repo dom.Repository, roots []string, publisher contentpkg.PublisherVerifier, release func() string, audit AuditLogger, log *logger.Logger) *Service {
	return &Service{repo: repo, roots: slices.Clone(roots), publisher: publisher, release: release, audit: audit,
		logger: log.With("service", "content_catalog"), now: time.Now}
}

// UseClock replaces the clock (tests).
func (s *Service) UseClock(now func() time.Time) { s.now = now }

// ImportResult is what an import did.
type ImportResult struct {
	KeySetVersion    uint64
	IndexSequence    uint64
	Unchanged        bool
	Added            int
	Existing         int
	Refused          []contentpkg.Refused
	RevokedVersions  int
	RevokedInstalls  int
	AutoUpdated      int
	RevocationsStale bool
}

// Import verifies an offline bundle and stores it in the instance catalog.
// One import runs at a time; nothing is stored unless everything verifies.
func (s *Service) Import(ctx context.Context, r io.Reader, actor *shared.ID) (*ImportResult, error) {
	s.importMu.Lock()
	defer s.importMu.Unlock()
	now := s.now().UTC()
	b, err := contentpkg.ReadBundle(r)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrVerification, err)
	}
	trust, err := s.repo.GetTrust(ctx)
	if err != nil {
		return nil, err
	}
	revoked, err := s.repo.ListRevocations(ctx)
	if err != nil {
		return nil, err
	}
	v, err := contentpkg.Verify(b, contentpkg.VerifyOptions{
		Trust:             contentpkg.Trust{Roots: s.roots, MinKeySetVersion: trust.KeySetVersion},
		LastIndexSequence: trust.IndexSequence, LastIndexDigest: trust.IndexDigest,
		LastRevocationsSequence: trust.RevocationsSequence, LastRevocationsDigest: trust.RevocationsDigest,
		Revoked:   revoked,
		Publisher: s.publisher, Now: now,
	})
	if err != nil {
		if errors.Is(err, contentpkg.ErrRollback) {
			return nil, fmt.Errorf("%w: %v", ErrRollback, err)
		}
		return nil, fmt.Errorf("%w: %v", ErrVerification, err)
	}
	batch := &dom.ImportBatch{
		KeySetVersion: v.KeySetVersion, IndexSequence: v.Index.Sequence, IndexDigest: v.IndexDigest,
		IndexExpiresAt: v.Index.ExpiresAt, RevocationsSequence: v.Revocations.Sequence, RevocationsDigest: v.RevocationsDigest,
		RevocationsIssuedAt: v.Revocations.IssuedAt, RevocationsExpiresAt: v.Revocations.ExpiresAt,
		Revocations: v.Revocations.Entries, ImportedAt: now,
	}
	ids := make([]string, 0, len(v.Packages))
	for i := range v.Packages {
		batch.Packages = append(batch.Packages, packageRow(&v.Packages[i], actor, now))
		ids = append(ids, v.Packages[i].Manifest.ID)
	}
	out, err := s.repo.ApplyImport(ctx, batch)
	if err != nil {
		if errors.Is(err, dom.ErrStaleImport) {
			return nil, fmt.Errorf("%w: %v", ErrRollback, err)
		}
		return nil, err
	}
	res := &ImportResult{KeySetVersion: v.KeySetVersion, IndexSequence: v.Index.Sequence, Unchanged: v.Unchanged,
		Added: out.Added, Existing: out.Existing, Refused: v.Refused, RevokedVersions: out.RevokedVersions,
		RevokedInstalls: out.RevokedInstalls, RevocationsStale: v.RevocationsStale}
	res.AutoUpdated = s.follow(ctx, slices.Compact(ids))
	s.logger.Info("content catalog imported", "index_sequence", v.Index.Sequence, "added", out.Added,
		"existing", out.Existing, "refused", len(v.Refused), "revoked_versions", out.RevokedVersions,
		"revoked_installs", out.RevokedInstalls, "auto_updated", res.AutoUpdated)
	return res, nil
}

func packageRow(vp *contentpkg.VerifiedPackage, actor *shared.ID, now time.Time) *dom.Package {
	m, st := vp.Manifest, vp.Statement
	p := &dom.Package{
		ID: shared.NewID(), PackageID: m.ID, Version: m.Version, Type: m.Type, Origin: st.Origin, Title: m.Title,
		Manifest: m, ManifestRaw: vp.ManifestRaw, ManifestDigest: st.ManifestDigest,
		ArtifactMediaType: m.Artifact.MediaType, ArtifactDigest: m.Artifact.Digest, ArtifactSize: m.Artifact.Size,
		Statement: vp.StatementRaw, PublisherSignature: vp.PublisherRaw,
		PublisherIdentity: st.Publisher.Identity, PublisherIssuer: st.Publisher.Issuer,
		Tier: st.Permissions.Tier, ServiceUse: st.License.ServiceUse, CreatedBy: actor, CreatedAt: now,
	}
	if !vp.PublisherSigned.IsZero() {
		at := vp.PublisherSigned
		p.PublisherSignedAt = &at
	}
	return p
}

// TrustStatus is the applied signed state and its health.
type TrustStatus struct {
	RootsConfigured  int
	State            dom.TrustState
	IndexExpired     bool
	RevocationsStale bool
}

// Trust returns the applied signed state.
func (s *Service) Trust(ctx context.Context) (*TrustStatus, error) {
	t, err := s.repo.GetTrust(ctx)
	if err != nil {
		return nil, err
	}
	now := s.now()
	return &TrustStatus{RootsConfigured: len(s.roots), State: *t,
		IndexExpired:     t.IndexExpiresAt == nil || !t.IndexExpiresAt.After(now),
		RevocationsStale: t.RevocationsStale(now)}, nil
}

// List returns the catalog as the organization sees it.
func (s *Service) List(ctx context.Context, tenantID shared.ID, f dom.Filter) ([]dom.Listing, int, error) {
	return s.repo.ListPackages(ctx, tenantID, f)
}

// PackageView is one package: its versions, installation and pending
// request.
type PackageView struct {
	Versions []*dom.Package
	Install  *dom.Install
	Pending  *dom.Request
}

// Get returns one package as the organization sees it.
func (s *Service) Get(ctx context.Context, tenantID shared.ID, packageID string) (*PackageView, error) {
	if !contentpkg.ValidID(packageID) {
		return nil, dom.ErrNotFound
	}
	vs, err := s.repo.ListVersions(ctx, tenantID, packageID)
	if err != nil {
		return nil, err
	}
	if len(vs) == 0 {
		return nil, dom.ErrNotFound
	}
	view := &PackageView{Versions: vs}
	if in, err := s.repo.GetInstall(ctx, tenantID, packageID); err == nil {
		view.Install = in
	} else if !errors.Is(err, dom.ErrInstallNotFound) {
		return nil, err
	}
	reqs, err := s.repo.ListRequests(ctx, tenantID, dom.RequestPending, 200)
	if err != nil {
		return nil, err
	}
	for _, q := range reqs {
		if q.PackageID == packageID {
			view.Pending = q
		}
	}
	return view, nil
}

// Installs returns the organization's installations.
func (s *Service) Installs(ctx context.Context, tenantID shared.ID) ([]*dom.Install, error) {
	return s.repo.ListInstalls(ctx, tenantID)
}

// Requests returns the organization's requests.
func (s *Service) Requests(ctx context.Context, tenantID shared.ID, status dom.RequestStatus) ([]*dom.Request, error) {
	switch status {
	case "", dom.RequestPending, dom.RequestApproved, dom.RequestRejected, dom.RequestCanceled, dom.RequestFailed:
	default:
		return nil, fmt.Errorf("%w: unknown status", shared.ErrValidation)
	}
	return s.repo.ListRequests(ctx, tenantID, status, 100)
}

// GetSettings returns the organization's catalog settings.
func (s *Service) GetSettings(ctx context.Context, tenantID shared.ID) (*dom.Settings, error) {
	return s.repo.GetSettings(ctx, tenantID)
}

// Notifier delivers in-app notifications (*integration.NotificationService).
type Notifier interface {
	Notify(ctx context.Context, params notificationdom.NotificationParams) error
}

// SetNotifier enables the notice to the organization's owners and
// administrators when approval is switched off.
func (s *Service) SetNotifier(n Notifier) { s.notifier = n }

// PutSettings changes the approval option (audited high). Turning it on is
// immediate and cancels a pending switch-off; turning it off takes effect
// ApprovalOffDelay later, and the owners and administrators are told, so
// they can turn it back on before it applies.
func (s *Service) PutSettings(ctx context.Context, tenantID shared.ID, requireApproval bool, actx auditapp.AuditContext) (*dom.Settings, error) {
	before, err := s.repo.GetSettings(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	now := s.now().UTC()
	st := &dom.Settings{RequireApproval: requireApproval, UpdatedBy: actorID(actx), UpdatedAt: &now}
	switch {
	case requireApproval:
		// on: immediate, no pending switch-off
	case before.ApprovalRequired(now) && before.ApprovalOffAt != nil:
		// already switching off: keep the earlier time
		st.RequireApproval, st.ApprovalOffAt = true, before.ApprovalOffAt
	case before.ApprovalRequired(now):
		at := now.Add(dom.ApprovalOffDelay)
		st.RequireApproval, st.ApprovalOffAt = true, &at
	}
	if err := s.repo.PutSettings(ctx, tenantID, st); err != nil {
		return nil, err
	}
	ev := auditapp.NewSuccessEvent(auditdom.ActionContentCatalogSettings, auditdom.ResourceTypeContentPackage, tenantID.String()).
		WithMetadata("require_approval", requireApproval).WithMetadata("before", before.ApprovalRequired(now))
	if st.ApprovalOffAt != nil {
		ev = ev.WithMessage("Content catalog approval switched off from "+st.ApprovalOffAt.Format(time.RFC3339)).
			WithMetadata("approval_off_at", st.ApprovalOffAt.Format(time.RFC3339))
		if before.ApprovalOffAt == nil {
			s.noticeApprovalOff(ctx, tenantID, actorID(actx), *st.ApprovalOffAt)
		}
	} else {
		ev = ev.WithMessage(fmt.Sprintf("Content catalog approval set to %t", requireApproval))
	}
	s.logAudit(ctx, actx, ev)
	return st, nil
}

// noticeApprovalOff tells the organization's owners and administrators
// (except the actor) that approval goes off at a time.
func (s *Service) noticeApprovalOff(ctx context.Context, tenantID shared.ID, actor *shared.ID, at time.Time) {
	if s.notifier == nil {
		return
	}
	admins, err := s.repo.ListAdmins(ctx, tenantID)
	if err != nil {
		s.logger.Warn("content approval notice: list administrators", "error", err)
		return
	}
	for _, uid := range admins {
		if actor != nil && uid == *actor {
			continue
		}
		u := uid
		if err := s.notifier.Notify(ctx, notificationdom.NotificationParams{
			TenantID: tenantID, Audience: notificationdom.AudienceUser, AudienceID: &u,
			NotificationType: notificationdom.TypeSystemAlert, Severity: notificationdom.SeverityHigh,
			Title: "Content install approval is being switched off",
			Body: "Installs, updates, rollbacks and uninstalls of content will no longer need a second person from " +
				at.Format(time.RFC3339) + ". Turn approval back on before then to cancel.",
			ResourceType: "settings", URL: "/settings/content", ActorID: actor,
		}); err != nil {
			s.logger.Warn("content approval notice", "error", err)
		}
	}
}

// Change is an install, update or rollback.
type Change struct {
	PackageID string
	// Version is required for install and update; empty for a rollback
	// means the previous version.
	Version string
	Pinned  bool
	// AcknowledgeLicense is required for a package whose license does not
	// allow service use.
	AcknowledgeLicense bool
	Note               string
}

// Outcome is an action done now, or a request waiting for approval.
type Outcome struct {
	Install *dom.Install
	Request *dom.Request
}

// Install installs a package version for the organization.
func (s *Service) Install(ctx context.Context, tenantID shared.ID, c Change, actx auditapp.AuditContext) (*Outcome, error) {
	return s.submit(ctx, tenantID, dom.ActionInstall, c, actx)
}

// Update moves an installation to a newer version.
func (s *Service) Update(ctx context.Context, tenantID shared.ID, c Change, actx auditapp.AuditContext) (*Outcome, error) {
	return s.submit(ctx, tenantID, dom.ActionUpdate, c, actx)
}

// Rollback moves an installation to an older version (the previous one by
// default) and pins it.
func (s *Service) Rollback(ctx context.Context, tenantID shared.ID, c Change, actx auditapp.AuditContext) (*Outcome, error) {
	return s.submit(ctx, tenantID, dom.ActionRollback, c, actx)
}

// Uninstall removes an installation.
func (s *Service) Uninstall(ctx context.Context, tenantID shared.ID, packageID, note string, actx auditapp.AuditContext) (*Outcome, error) {
	return s.submit(ctx, tenantID, dom.ActionUninstall, Change{PackageID: packageID, Note: note}, actx)
}

// submit runs the action now, or files a request when the organization
// requires approval. Either way the action is checked first, so a request
// that could never succeed is refused at once.
func (s *Service) submit(ctx context.Context, tenantID shared.ID, action dom.RequestAction, c Change, actx auditapp.AuditContext) (*Outcome, error) {
	c.Note = strings.TrimSpace(c.Note)
	if len(c.Note) > maxNote {
		return nil, fmt.Errorf("%w: the note is over %d characters", shared.ErrValidation, maxNote)
	}
	if !contentpkg.ValidID(c.PackageID) {
		return nil, dom.ErrNotFound
	}
	plan, err := s.plan(ctx, tenantID, action, c)
	if err != nil {
		return nil, err
	}
	settings, err := s.repo.GetSettings(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if !settings.ApprovalRequired(s.now()) {
		in, err := s.apply(ctx, tenantID, plan, actorID(actx), actx)
		if err != nil {
			return nil, err
		}
		return &Outcome{Install: in}, nil
	}
	q := &dom.Request{ID: shared.NewID(), TenantID: tenantID, PackageID: c.PackageID, Action: action,
		Pinned: plan.pinned, LicenseAcknowledged: c.AcknowledgeLicense, Status: dom.RequestPending, Note: c.Note,
		RequestedBy: actorID(actx), CreatedAt: s.now().UTC()}
	if plan.target != nil {
		q.TargetRowID = &plan.target.ID
		q.Target = plan.target
	}
	if err := s.repo.CreateRequest(ctx, q); err != nil {
		return nil, err
	}
	s.logAudit(ctx, actx, s.event(auditdom.ActionContentPackageRequested, c.PackageID, plan.target).
		WithMessage(fmt.Sprintf("Requested %s of content package %s", action, c.PackageID)).
		WithMetadata("action", string(action)).WithMetadata("note", c.Note))
	return &Outcome{Request: q}, nil
}

// plan is a checked action.
type plan struct {
	action  dom.RequestAction
	current *dom.Install
	target  *dom.Package
	pinned  bool
	ack     bool
}

//nolint:cyclop // one decision per action
func (s *Service) plan(ctx context.Context, tenantID shared.ID, action dom.RequestAction, c Change) (*plan, error) {
	p := &plan{action: action, pinned: c.Pinned, ack: c.AcknowledgeLicense}
	cur, err := s.repo.GetInstall(ctx, tenantID, c.PackageID)
	switch {
	case err == nil:
		p.current = cur
	case errors.Is(err, dom.ErrInstallNotFound):
	default:
		return nil, err
	}
	if action != dom.ActionInstall && p.current == nil {
		return nil, dom.ErrInstallNotFound
	}
	switch action {
	case dom.ActionInstall:
		if p.current != nil {
			return nil, dom.ErrAlreadyInstalled
		}
		if p.target, err = s.version(ctx, tenantID, c.PackageID, c.Version); err != nil {
			return nil, err
		}
	case dom.ActionUpdate:
		if p.target, err = s.version(ctx, tenantID, c.PackageID, c.Version); err != nil {
			return nil, err
		}
		if contentpkg.CompareVersions(p.target.Version, p.current.Package.Version) <= 0 {
			return nil, fmt.Errorf("%w: %s is not newer than the installed %s; roll back instead", ErrRefused,
				p.target.Version, p.current.Package.Version)
		}
		p.pinned = p.current.Pinned
	case dom.ActionRollback:
		switch {
		case c.Version != "":
			p.target, err = s.version(ctx, tenantID, c.PackageID, c.Version)
		case p.current.PreviousRowID != nil:
			p.target, err = s.repo.GetPackageRow(ctx, tenantID, *p.current.PreviousRowID)
		default:
			return nil, fmt.Errorf("%w: there is no previous version; name one", ErrRefused)
		}
		if err != nil {
			return nil, err
		}
		if contentpkg.CompareVersions(p.target.Version, p.current.Package.Version) >= 0 {
			return nil, fmt.Errorf("%w: %s is not older than the installed %s", ErrRefused, p.target.Version, p.current.Package.Version)
		}
		p.pinned = true
	case dom.ActionUninstall:
		return p, s.checkDependents(ctx, tenantID, c.PackageID)
	}
	return p, s.checkTarget(ctx, tenantID, p.target, c.AcknowledgeLicense)
}

func (s *Service) version(ctx context.Context, tenantID shared.ID, packageID, version string) (*dom.Package, error) {
	if _, err := contentpkg.ParseVersion(version); err != nil {
		return nil, fmt.Errorf("%w: %v", shared.ErrValidation, err)
	}
	return s.repo.GetVersion(ctx, tenantID, packageID, version)
}

// checkTarget refuses a revoked or incompatible version, a license that
// needs an acknowledgement, missing dependencies, and an executable while
// the revocation list is stale.
func (s *Service) checkTarget(ctx context.Context, tenantID shared.ID, t *dom.Package, ack bool) error {
	if t.Revoked() {
		return fmt.Errorf("%w: %s@%s is revoked: %s", ErrRefused, t.PackageID, t.Version, t.RevokeReason)
	}
	revs, err := s.repo.ListRevocations(ctx)
	if err != nil {
		return err
	}
	if e, ok := contentpkg.RevokedBy(revs, t.PackageID, t.Version, t.ArtifactDigest); ok {
		return fmt.Errorf("%w: %s@%s is revoked: %s", ErrRefused, t.PackageID, t.Version, e.Reason)
	}
	if ok, err := contentpkg.Satisfies(t.Manifest.Compatibility.Platform, s.release()); err != nil || !ok {
		return fmt.Errorf("%w: %s@%s needs platform %s", ErrRefused, t.PackageID, t.Version, t.Manifest.Compatibility.Platform)
	}
	if !t.ServiceUse && !ack {
		return fmt.Errorf("%w: the license of %s (%s) does not allow use as a service; acknowledge it to install",
			ErrRefused, t.PackageID, t.Manifest.License.SPDX)
	}
	if t.Type.IsExecutable() {
		trust, err := s.repo.GetTrust(ctx)
		if err != nil {
			return err
		}
		if trust.RevocationsStale(s.now()) {
			return fmt.Errorf("%w: the revocation list is out of date; import a current bundle before installing %s",
				ErrRefused, t.Type)
		}
	}
	for _, d := range t.Manifest.Dependencies {
		in, err := s.repo.GetInstall(ctx, tenantID, d.ID)
		if errors.Is(err, dom.ErrInstallNotFound) {
			return fmt.Errorf("%w: install %s (%s) first", ErrRefused, d.ID, d.Version)
		}
		if err != nil {
			return err
		}
		if ok, _ := contentpkg.Satisfies(d.Version, in.Package.Version); !ok || in.Status != dom.InstallActive {
			return fmt.Errorf("%w: %s %s is needed, %s is installed", ErrRefused, d.ID, d.Version, in.Package.Version)
		}
	}
	return nil
}

// checkDependents refuses to uninstall a package another installed package
// depends on.
func (s *Service) checkDependents(ctx context.Context, tenantID shared.ID, packageID string) error {
	ins, err := s.repo.ListInstalls(ctx, tenantID)
	if err != nil {
		return err
	}
	for _, in := range ins {
		for _, d := range in.Package.Manifest.Dependencies {
			if d.ID == packageID {
				return fmt.Errorf("%w: %s depends on it; uninstall that first", ErrRefused, in.PackageID)
			}
		}
	}
	return nil
}

// apply carries out a checked action and audits it.
func (s *Service) apply(ctx context.Context, tenantID shared.ID, p *plan, by *shared.ID, actx auditapp.AuditContext) (*dom.Install, error) {
	in, ev, err := s.applyTo(ctx, s.repo, tenantID, p, by)
	if err != nil {
		return nil, err
	}
	s.logAudit(ctx, actx, ev)
	return in, nil
}

// applyTo writes a checked action through repo (which may be a
// transaction) and returns the audit event to record once it is committed.
func (s *Service) applyTo(ctx context.Context, repo dom.Repository, tenantID shared.ID, p *plan, by *shared.ID) (*dom.Install, auditapp.AuditEvent, error) {
	now := s.now().UTC()
	var (
		in     *dom.Install
		action auditdom.Action
		msg    string
	)
	switch p.action {
	case dom.ActionInstall:
		in = &dom.Install{ID: shared.NewID(), TenantID: tenantID, PackageID: p.target.PackageID, PackageRowID: p.target.ID,
			Pinned: p.pinned, Status: dom.InstallActive, LicenseAcknowledged: p.ack, InstalledBy: by, UpdatedBy: by,
			CreatedAt: now, UpdatedAt: now, Package: p.target}
		if err := repo.CreateInstall(ctx, in); err != nil {
			return nil, auditapp.AuditEvent{}, err
		}
		action, msg = auditdom.ActionContentPackageInstalled, "Installed content package %s@%s"
	case dom.ActionUpdate, dom.ActionRollback:
		in = p.current
		prev := in.PackageRowID
		in.PreviousRowID, in.Previous = &prev, in.Package
		in.PackageRowID, in.Package = p.target.ID, p.target
		in.Pinned, in.Status, in.UpdatedBy, in.UpdatedAt = p.pinned, dom.InstallActive, by, now
		in.LicenseAcknowledged = in.LicenseAcknowledged || p.ack
		if err := repo.UpdateInstall(ctx, in); err != nil {
			return nil, auditapp.AuditEvent{}, err
		}
		action, msg = auditdom.ActionContentPackageUpdated, "Updated content package %s to %s"
		if p.action == dom.ActionRollback {
			action, msg = auditdom.ActionContentPackageRolledBack, "Rolled content package %s back to %s"
		}
	case dom.ActionUninstall:
		if err := repo.DeleteInstall(ctx, tenantID, p.current.PackageID); err != nil {
			return nil, auditapp.AuditEvent{}, err
		}
		return nil, s.event(auditdom.ActionContentPackageUninstalled, p.current.PackageID, p.current.Package).
			WithMessage(fmt.Sprintf("Uninstalled content package %s", p.current.PackageID)), nil
	}
	ev := s.event(action, p.target.PackageID, p.target).WithMessage(fmt.Sprintf(msg, p.target.PackageID, p.target.Version))
	if p.ack && !p.target.ServiceUse {
		ev = ev.WithMetadata("license_acknowledged", p.target.Manifest.License.SPDX)
	}
	if p.target.Tier == "T2" || p.target.Type.IsExecutable() {
		ev = ev.WithSeverity(auditdom.SeverityHigh)
	}
	return in, ev, nil
}

// Pin pins or unpins an installation (no approval: it only stops or allows
// automatic updates).
func (s *Service) Pin(ctx context.Context, tenantID shared.ID, packageID string, pinned bool, actx auditapp.AuditContext) (*dom.Install, error) {
	in, err := s.repo.GetInstall(ctx, tenantID, packageID)
	if err != nil {
		return nil, err
	}
	if in.Pinned == pinned {
		return in, nil
	}
	in.Pinned, in.UpdatedBy, in.UpdatedAt = pinned, actorID(actx), s.now().UTC()
	if err := s.repo.UpdateInstall(ctx, in); err != nil {
		return nil, err
	}
	action := auditdom.ActionContentPackageUnpinned
	if pinned {
		action = auditdom.ActionContentPackagePinned
	}
	s.logAudit(ctx, actx, s.event(action, packageID, in.Package).WithMessage(fmt.Sprintf("Content package %s pinned: %t", packageID, pinned)))
	return in, nil
}

// Approve carries out another member's pending request.
func (s *Service) Approve(ctx context.Context, tenantID, requestID shared.ID, reason string, actx auditapp.AuditContext) (*dom.Request, *dom.Install, error) {
	q, err := s.decidable(ctx, tenantID, requestID, reason, actx)
	if err != nil {
		return nil, nil, err
	}
	c := Change{PackageID: q.PackageID, Pinned: q.Pinned, AcknowledgeLicense: q.LicenseAcknowledged}
	if q.Target != nil {
		c.Version = q.Target.Version
	} else if q.Action != dom.ActionUninstall {
		return nil, nil, dom.ErrNotFound
	}
	now := s.now().UTC()
	p, err := s.plan(ctx, tenantID, q.Action, c)
	if err == nil {
		// The decision and the change commit together: two approvers cannot
		// both run it, and a failed change never leaves an approved request.
		var (
			in *dom.Install
			ev auditapp.AuditEvent
		)
		err = s.repo.InTx(ctx, func(tx dom.Repository) error {
			if derr := tx.DecideRequest(ctx, tenantID, q.ID, dom.RequestApproved, actorID(actx), strings.TrimSpace(reason), now); derr != nil {
				return derr
			}
			var aerr error
			in, ev, aerr = s.applyTo(ctx, tx, tenantID, p, q.RequestedBy)
			return aerr
		})
		if errors.Is(err, dom.ErrRequestDecided) || errors.Is(err, dom.ErrRequestNotFound) {
			return nil, nil, err
		}
		if err == nil {
			s.logAudit(ctx, actx, ev)
			s.logAudit(ctx, actx, s.event(auditdom.ActionContentPackageRequestApprove, q.PackageID, q.Target).
				WithMessage(fmt.Sprintf("Approved %s of content package %s", q.Action, q.PackageID)).
				WithMetadata("request_id", q.ID.String()))
			q.Status = dom.RequestApproved
			return q, in, nil
		}
	}
	// The request can no longer be carried out (revoked, incompatible,
	// changed installation): it fails with the reason.
	if derr := s.repo.DecideRequest(ctx, tenantID, q.ID, dom.RequestFailed, actorID(actx), clip(err.Error()), now); derr != nil &&
		!errors.Is(derr, dom.ErrRequestDecided) {
		s.logger.Warn("mark content request failed", "error", derr)
	}
	return nil, nil, err
}

// Reject declines another member's pending request.
func (s *Service) Reject(ctx context.Context, tenantID, requestID shared.ID, reason string, actx auditapp.AuditContext) (*dom.Request, error) {
	q, err := s.decidable(ctx, tenantID, requestID, reason, actx)
	if err != nil {
		return nil, err
	}
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return nil, fmt.Errorf("%w: a reason is required", shared.ErrValidation)
	}
	if err := s.repo.DecideRequest(ctx, tenantID, q.ID, dom.RequestRejected, actorID(actx), reason, s.now().UTC()); err != nil {
		return nil, err
	}
	s.logAudit(ctx, actx, s.event(auditdom.ActionContentPackageRequestReject, q.PackageID, q.Target).
		WithMessage(fmt.Sprintf("Rejected %s of content package %s", q.Action, q.PackageID)).
		WithMetadata("request_id", q.ID.String()).WithMetadata("reason", reason))
	q.Status = dom.RequestRejected
	return q, nil
}

// Cancel withdraws the caller's own pending request.
func (s *Service) Cancel(ctx context.Context, tenantID, requestID shared.ID, actx auditapp.AuditContext) (*dom.Request, error) {
	q, err := s.repo.GetRequest(ctx, tenantID, requestID)
	if err != nil {
		return nil, err
	}
	me := actorID(actx)
	if me == nil || q.RequestedBy == nil || *me != *q.RequestedBy {
		return nil, fmt.Errorf("%w: only the requester can cancel a request", shared.ErrForbidden)
	}
	if err := s.repo.DecideRequest(ctx, tenantID, q.ID, dom.RequestCanceled, nil, "", s.now().UTC()); err != nil {
		return nil, err
	}
	s.logAudit(ctx, actx, s.event(auditdom.ActionContentPackageRequestCancel, q.PackageID, q.Target).
		WithMetadata("request_id", q.ID.String()))
	q.Status = dom.RequestCanceled
	return q, nil
}

func (s *Service) decidable(ctx context.Context, tenantID, requestID shared.ID, reason string, actx auditapp.AuditContext) (*dom.Request, error) {
	if len(strings.TrimSpace(reason)) > maxNote {
		return nil, fmt.Errorf("%w: the reason is over %d characters", shared.ErrValidation, maxNote)
	}
	q, err := s.repo.GetRequest(ctx, tenantID, requestID)
	if err != nil {
		return nil, err
	}
	if q.Status != dom.RequestPending {
		return nil, dom.ErrRequestDecided
	}
	me := actorID(actx)
	if me == nil || (q.RequestedBy != nil && *me == *q.RequestedBy) {
		return nil, ErrOwnRequest
	}
	return q, nil
}

// follow moves the unpinned installations of packageIDs to the newest
// compatible, non-revoked version when it asks for no more permissions and
// the organization does not require approval. It never fails the import.
func (s *Service) follow(ctx context.Context, packageIDs []string) int {
	ins, err := s.repo.ListFollowing(ctx, packageIDs)
	if err != nil {
		s.logger.Warn("list following content installs", "error", err)
		return 0
	}
	n := 0
	for _, in := range ins {
		if s.followOne(ctx, in) {
			n++
		}
	}
	return n
}

func (s *Service) followOne(ctx context.Context, in *dom.Install) bool {
	st, err := s.repo.GetSettings(ctx, in.TenantID)
	if err != nil || st.ApprovalRequired(s.now()) {
		return false
	}
	cur, err := s.repo.GetInstall(ctx, in.TenantID, in.PackageID)
	if err != nil || cur.Pinned || cur.Status != dom.InstallActive {
		return false
	}
	vs, err := s.repo.ListVersions(ctx, in.TenantID, in.PackageID)
	if err != nil {
		return false
	}
	for _, v := range vs { // newest first
		if contentpkg.CompareVersions(v.Version, cur.Package.Version) <= 0 {
			return false
		}
		if v.Revoked() || widens(cur.Package.Manifest.Permissions, v.Manifest.Permissions) ||
			(!v.ServiceUse && cur.Package.ServiceUse) || v.Type != cur.Package.Type {
			continue
		}
		if v.TenantID == nil && cur.Package.TenantID != nil {
			continue // a private package never moves to an instance package of the same id
		}
		actx := auditapp.AuditContext{TenantID: in.TenantID.String()}
		if s.checkTarget(ctx, in.TenantID, v, cur.LicenseAcknowledged) != nil {
			continue
		}
		p := &plan{action: dom.ActionUpdate, current: cur, target: v, pinned: false, ack: cur.LicenseAcknowledged}
		if _, err := s.apply(ctx, in.TenantID, p, nil, actx); err != nil {
			s.logger.Warn("automatic content update", "package", in.PackageID, "error", err)
			return false
		}
		return true
	}
	return false
}

// widens reports whether b asks for more than a: a higher tier, more side
// effects, a wider network class, or new hosts, credentials or data scopes.
func widens(a, b contentpkg.Permissions) bool {
	rank := func(v string, order ...string) int { return slices.Index(order, v) }
	if rank(b.Tier, "T0", "T1", "T2") > rank(a.Tier, "T0", "T1", "T2") ||
		rank(b.SideEffects, "none", "state-changing", "destructive") > rank(a.SideEffects, "none", "state-changing", "destructive") ||
		rank(b.Network, "none", "targets-only", "declared-hosts") > rank(a.Network, "none", "targets-only", "declared-hosts") {
		return true
	}
	for _, pair := range [][2][]string{{a.DeclaredHosts, b.DeclaredHosts}, {a.Credentials, b.Credentials}, {a.DataScopes, b.DataScopes}} {
		for _, x := range pair[1] {
			if !slices.Contains(pair[0], x) {
				return true
			}
		}
	}
	return false
}

func (s *Service) event(action auditdom.Action, packageID string, p *dom.Package) auditapp.AuditEvent {
	ev := auditapp.NewSuccessEvent(action, auditdom.ResourceTypeContentPackage, packageID).WithResourceName(packageID)
	if p != nil {
		ev = ev.WithResourceName(packageID+"@"+p.Version).
			WithMetadata("version", p.Version).
			WithMetadata("artifact_digest", p.ArtifactDigest).
			WithMetadata("origin", p.Origin)
	}
	return ev
}

func (s *Service) logAudit(ctx context.Context, actx auditapp.AuditContext, ev auditapp.AuditEvent) {
	if s.audit == nil {
		return
	}
	if err := s.audit.LogEvent(ctx, actx, ev); err != nil {
		s.logger.Error("write content catalog audit", "error", err)
	}
}

func actorID(actx auditapp.AuditContext) *shared.ID {
	id, err := shared.IDFromString(actx.ActorID)
	if err != nil || id.IsZero() {
		return nil
	}
	return &id
}

func clip(s string) string {
	if len(s) > maxNote {
		return s[:maxNote]
	}
	return s
}
