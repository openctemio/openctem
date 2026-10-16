// Package findinglifecycle manages an organization's finding lifecycles
// (docs/rfcs/RFC-110-tenant-lifecycles.md): the sub-status catalog, the
// schemes and their versions (draft, validate, publish, roll back). The
// tenant comes from the caller's context; every repository call is
// tenant-scoped. Publishing is audited, and the route asks for a recent
// sign-in (step-up) before it reaches this service.
package findinglifecycle

import (
	"context"
	"fmt"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	lc "github.com/openctemio/openctem/api/pkg/domain/findinglifecycle"
	"github.com/openctemio/openctem/api/pkg/domain/plan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// AuditLogger records audit events (*auditapp.AuditService).
type AuditLogger interface {
	LogEvent(ctx context.Context, actx auditapp.AuditContext, event auditapp.AuditEvent) error
}

// Service manages the catalog and the schemes.
type Service struct {
	subs    lc.SubStatusRepository
	schemes lc.SchemeRepository
	limits  plan.Checker
	audit   AuditLogger
	logger  *logger.Logger
	now     func() time.Time
}

// NewService returns the service. limits and audit may be nil (no plans, no audit).
func NewService(subs lc.SubStatusRepository, schemes lc.SchemeRepository, limits plan.Checker, audit AuditLogger, log *logger.Logger) *Service {
	return &Service{subs: subs, schemes: schemes, limits: limits, audit: audit, logger: log.With("service", "finding_lifecycle"), now: time.Now}
}

// Actor is who changes the definitions: the user (nil for an API key) and
// the audit context of the request.
type Actor struct {
	UserID *shared.ID
	Audit  auditapp.AuditContext
}

func (s *Service) checkLimit(ctx context.Context, tenantID shared.ID, key plan.Key) error {
	if s.limits == nil {
		return nil
	}
	return s.limits.Check(ctx, tenantID, key, 1)
}

func (s *Service) logAudit(ctx context.Context, a Actor, event auditapp.AuditEvent) {
	if s.audit == nil {
		return
	}
	if err := s.audit.LogEvent(ctx, a.Audit, event); err != nil {
		s.logger.Warn("failed to record audit event", "action", string(event.Action), "error", err)
	}
}

// ---- sub-status catalog ----

// ListSubStatuses returns the tenant's catalog.
func (s *Service) ListSubStatuses(ctx context.Context, tenantID shared.ID, includeArchived bool) ([]*lc.SubStatus, error) {
	return s.subs.List(ctx, tenantID, lc.SubStatusFilter{Kind: lc.ObjectKindFinding, IncludeArchived: includeArchived})
}

// CreateSubStatus adds a sub-status, within the platform's cap and the
// plan's limit.
func (s *Service) CreateSubStatus(ctx context.Context, tenantID shared.ID, in lc.SubStatusInput, a Actor) (*lc.SubStatus, error) {
	sub, err := lc.NewSubStatus(tenantID, in, a.UserID, s.now())
	if err != nil {
		return nil, err
	}
	if err := s.roomForSubStatus(ctx, tenantID); err != nil {
		return nil, err
	}
	if err := s.subs.Create(ctx, sub); err != nil {
		return nil, err
	}
	s.logAudit(ctx, a, auditapp.NewSuccessEvent(auditdom.ActionLifecycleSubStatusCreated, auditdom.ResourceTypeLifecycleSubStatus, sub.ID().String()).
		WithResourceName(sub.Name()).
		WithMessage(fmt.Sprintf("Sub-status '%s' created under %s", sub.Name(), sub.CanonicalStatus())).
		WithMetadata("key", sub.Key()).WithMetadata("canonical_status", string(sub.CanonicalStatus())).
		WithMetadata("closure_reason", string(sub.ClosureReason())))
	return sub, nil
}

func (s *Service) roomForSubStatus(ctx context.Context, tenantID shared.ID) error {
	n, err := s.subs.CountActive(ctx, tenantID, lc.ObjectKindFinding)
	if err != nil {
		return err
	}
	if n >= lc.MaxSubStatusesPerKind {
		return lc.ErrSubStatusLimit
	}
	return s.checkLimit(ctx, tenantID, plan.LifecycleSubStatuses)
}

// UpdateSubStatus changes a sub-status's presentation.
func (s *Service) UpdateSubStatus(ctx context.Context, tenantID, id shared.ID, u lc.SubStatusUpdate, a Actor) (*lc.SubStatus, error) {
	sub, err := s.subs.GetByID(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	if err := sub.Update(u, a.UserID, s.now()); err != nil {
		return nil, err
	}
	if err := s.subs.Update(ctx, sub); err != nil {
		return nil, err
	}
	s.logAudit(ctx, a, auditapp.NewSuccessEvent(auditdom.ActionLifecycleSubStatusUpdated, auditdom.ResourceTypeLifecycleSubStatus, sub.ID().String()).
		WithResourceName(sub.Name()).WithMessage(fmt.Sprintf("Sub-status '%s' updated", sub.Name())))
	return sub, nil
}

// ArchiveSubStatus retires a sub-status. A published lifecycle that uses it
// must be republished without it first; findings that carry it keep it until
// they move.
func (s *Service) ArchiveSubStatus(ctx context.Context, tenantID, id shared.ID, a Actor) (*lc.SubStatus, error) {
	sub, err := s.subs.GetByID(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	used, err := s.schemes.SubStatusPublished(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	if used {
		return nil, lc.ErrSubStatusInUseBy
	}
	sub.Archive(a.UserID, s.now())
	if err := s.subs.Update(ctx, sub); err != nil {
		return nil, err
	}
	s.logAudit(ctx, a, auditapp.NewSuccessEvent(auditdom.ActionLifecycleSubStatusArchived, auditdom.ResourceTypeLifecycleSubStatus, sub.ID().String()).
		WithResourceName(sub.Name()).WithMessage(fmt.Sprintf("Sub-status '%s' archived", sub.Name())))
	return sub, nil
}

// RestoreSubStatus brings an archived sub-status back (counts against the limits again).
func (s *Service) RestoreSubStatus(ctx context.Context, tenantID, id shared.ID, a Actor) (*lc.SubStatus, error) {
	sub, err := s.subs.GetByID(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	if !sub.IsArchived() {
		return sub, nil
	}
	if err := s.roomForSubStatus(ctx, tenantID); err != nil {
		return nil, err
	}
	sub.Restore(a.UserID, s.now())
	if err := s.subs.Update(ctx, sub); err != nil {
		return nil, err
	}
	s.logAudit(ctx, a, auditapp.NewSuccessEvent(auditdom.ActionLifecycleSubStatusUpdated, auditdom.ResourceTypeLifecycleSubStatus, sub.ID().String()).
		WithResourceName(sub.Name()).WithMessage(fmt.Sprintf("Sub-status '%s' restored", sub.Name())))
	return sub, nil
}

// ---- schemes ----

// SchemeView is a scheme with its published and draft versions.
type SchemeView struct {
	Scheme    *lc.Scheme
	Published *lc.Version
	Draft     *lc.Version
}

// ListSchemes returns the tenant's schemes with their current versions.
func (s *Service) ListSchemes(ctx context.Context, tenantID shared.ID, includeArchived bool) ([]SchemeView, error) {
	schemes, err := s.schemes.ListSchemes(ctx, tenantID, lc.ObjectKindFinding, includeArchived)
	if err != nil {
		return nil, err
	}
	out := make([]SchemeView, 0, len(schemes))
	for _, sc := range schemes {
		v, err := s.view(ctx, sc)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

// GetScheme returns one scheme with its current versions.
func (s *Service) GetScheme(ctx context.Context, tenantID, id shared.ID) (SchemeView, error) {
	sc, err := s.schemes.GetScheme(ctx, tenantID, id)
	if err != nil {
		return SchemeView{}, err
	}
	return s.view(ctx, sc)
}

func (s *Service) view(ctx context.Context, sc *lc.Scheme) (SchemeView, error) {
	versions, err := s.schemes.ListVersions(ctx, sc.TenantID(), sc.ID())
	if err != nil {
		return SchemeView{}, err
	}
	v := SchemeView{Scheme: sc}
	for _, ver := range versions {
		switch ver.State {
		case lc.VersionDraft:
			v.Draft = ver
		case lc.VersionPublished:
			v.Published = ver
		case lc.VersionSuperseded:
		}
	}
	return v, nil
}

// CreateScheme adds a scheme with an empty first draft.
func (s *Service) CreateScheme(ctx context.Context, tenantID shared.ID, in lc.SchemeInput, a Actor) (SchemeView, error) {
	sc, err := lc.NewScheme(tenantID, in, a.UserID, s.now())
	if err != nil {
		return SchemeView{}, err
	}
	n, err := s.schemes.CountLive(ctx, tenantID, lc.ObjectKindFinding)
	if err != nil {
		return SchemeView{}, err
	}
	if n >= lc.MaxSchemesPerKind {
		return SchemeView{}, lc.ErrSchemeLimit
	}
	if err := s.checkLimit(ctx, tenantID, plan.LifecycleSchemes); err != nil {
		return SchemeView{}, err
	}
	if err := s.schemes.CreateScheme(ctx, sc); err != nil {
		return SchemeView{}, err
	}
	draft, err := lc.NewDraft(sc, 1, lc.Spec{}, a.UserID, s.now())
	if err != nil {
		return SchemeView{}, err
	}
	if err := s.schemes.CreateVersion(ctx, draft); err != nil {
		return SchemeView{}, err
	}
	s.logAudit(ctx, a, auditapp.NewSuccessEvent(auditdom.ActionLifecycleCreated, auditdom.ResourceTypeLifecycle, sc.ID().String()).
		WithResourceName(sc.Name()).WithMessage(fmt.Sprintf("Lifecycle '%s' created", sc.Name())).
		WithMetadata("key", sc.Key()).WithMetadata("default", sc.IsDefault()))
	return SchemeView{Scheme: sc, Draft: draft}, nil
}

// UpdateScheme changes a scheme's name, description, priority or context.
func (s *Service) UpdateScheme(ctx context.Context, tenantID, id shared.ID, u lc.SchemeUpdate, a Actor) (SchemeView, error) {
	sc, err := s.schemes.GetScheme(ctx, tenantID, id)
	if err != nil {
		return SchemeView{}, err
	}
	if sc.IsArchived() {
		return SchemeView{}, lc.ErrSchemeArchived
	}
	if err := sc.Update(u, a.UserID, s.now()); err != nil {
		return SchemeView{}, err
	}
	if err := s.schemes.UpdateScheme(ctx, sc); err != nil {
		return SchemeView{}, err
	}
	s.logAudit(ctx, a, auditapp.NewSuccessEvent(auditdom.ActionLifecycleUpdated, auditdom.ResourceTypeLifecycle, sc.ID().String()).
		WithResourceName(sc.Name()).WithMessage(fmt.Sprintf("Lifecycle '%s' updated", sc.Name())).
		WithMetadata("priority", sc.Priority()).WithMetadata("context", sc.Context()))
	return s.view(ctx, sc)
}

// ArchiveScheme retires a scheme: it stops applying to findings.
func (s *Service) ArchiveScheme(ctx context.Context, tenantID, id shared.ID, a Actor) (SchemeView, error) {
	sc, err := s.schemes.GetScheme(ctx, tenantID, id)
	if err != nil {
		return SchemeView{}, err
	}
	sc.Archive(a.UserID, s.now())
	if err := s.schemes.UpdateScheme(ctx, sc); err != nil {
		return SchemeView{}, err
	}
	s.logAudit(ctx, a, auditapp.NewSuccessEvent(auditdom.ActionLifecycleArchived, auditdom.ResourceTypeLifecycle, sc.ID().String()).
		WithResourceName(sc.Name()).WithMessage(fmt.Sprintf("Lifecycle '%s' archived", sc.Name())))
	return s.view(ctx, sc)
}

// ---- versions ----

// ListVersions returns a scheme's versions, newest first.
func (s *Service) ListVersions(ctx context.Context, tenantID, schemeID shared.ID) ([]*lc.Version, error) {
	if _, err := s.schemes.GetScheme(ctx, tenantID, schemeID); err != nil {
		return nil, err
	}
	return s.schemes.ListVersions(ctx, tenantID, schemeID)
}

// GetVersion returns one version.
func (s *Service) GetVersion(ctx context.Context, tenantID, schemeID shared.ID, number int) (*lc.Version, error) {
	return s.schemes.GetVersion(ctx, tenantID, schemeID, number)
}

// CreateDraft starts a new draft from a version (0 = the published one, or
// an empty spec when nothing is published). A scheme has one draft at a time.
func (s *Service) CreateDraft(ctx context.Context, tenantID, schemeID shared.ID, from int, a Actor) (*lc.Version, error) {
	sc, err := s.schemes.GetScheme(ctx, tenantID, schemeID)
	if err != nil {
		return nil, err
	}
	if sc.IsArchived() {
		return nil, lc.ErrSchemeArchived
	}
	spec := lc.Spec{}
	switch {
	case from > 0:
		src, err := s.schemes.GetVersion(ctx, tenantID, schemeID, from)
		if err != nil {
			return nil, err
		}
		spec = src.Spec
	default:
		view, err := s.view(ctx, sc)
		if err != nil {
			return nil, err
		}
		if view.Draft != nil {
			return nil, lc.ErrDraftExists
		}
		if view.Published != nil {
			spec = view.Published.Spec
		}
	}
	n, err := s.schemes.NextVersionNumber(ctx, tenantID, schemeID)
	if err != nil {
		return nil, err
	}
	draft, err := lc.NewDraft(sc, n, spec, a.UserID, s.now())
	if err != nil {
		return nil, err
	}
	if err := s.schemes.CreateVersion(ctx, draft); err != nil {
		return nil, err
	}
	return draft, nil
}

// UpdateDraft replaces a draft's spec. ifMatch is the spec hash the editor
// read; a draft changed since answers ErrStaleDraft.
func (s *Service) UpdateDraft(ctx context.Context, tenantID, schemeID shared.ID, number int, raw []byte, note, ifMatch string) (*lc.Version, lc.Validation, error) {
	v, err := s.schemes.GetVersion(ctx, tenantID, schemeID, number)
	if err != nil {
		return nil, lc.Validation{}, err
	}
	if v.State != lc.VersionDraft {
		return nil, lc.Validation{}, lc.ErrNotDraft
	}
	if ifMatch == "" {
		return nil, lc.Validation{}, fmt.Errorf("%w: send the draft's spec_hash as If-Match", shared.ErrValidation)
	}
	spec, err := lc.ParseSpec(raw)
	if err != nil {
		return nil, lc.Validation{}, err
	}
	n, err := plainNote(note)
	if err != nil {
		return nil, lc.Validation{}, err
	}
	v.Spec, v.Note = spec, n
	if err := s.schemes.UpdateDraft(ctx, v, ifMatch); err != nil {
		return nil, lc.Validation{}, err
	}
	validation, err := s.validate(ctx, tenantID, spec)
	if err != nil {
		return nil, lc.Validation{}, err
	}
	return v, validation, nil
}

// ValidateVersion compiles a version against the current catalog.
func (s *Service) ValidateVersion(ctx context.Context, tenantID, schemeID shared.ID, number int) (lc.Validation, error) {
	v, err := s.schemes.GetVersion(ctx, tenantID, schemeID, number)
	if err != nil {
		return lc.Validation{}, err
	}
	return s.validate(ctx, tenantID, v.Spec)
}

func (s *Service) validate(ctx context.Context, tenantID shared.ID, spec lc.Spec) (lc.Validation, error) {
	refs, err := s.catalogRefs(ctx, tenantID)
	if err != nil {
		return lc.Validation{}, err
	}
	_, v := lc.Compile(spec, refs, lc.Meta{})
	return v, nil
}

func (s *Service) catalogRefs(ctx context.Context, tenantID shared.ID) ([]lc.SubStatusRef, error) {
	subs, err := s.subs.List(ctx, tenantID, lc.SubStatusFilter{Kind: lc.ObjectKindFinding, IncludeArchived: true})
	if err != nil {
		return nil, err
	}
	refs := make([]lc.SubStatusRef, 0, len(subs))
	for _, sub := range subs {
		refs = append(refs, sub.Ref())
	}
	return refs, nil
}

// ErrInvalidLifecycle carries the validation of a version that cannot be
// published.
type ErrInvalidLifecycle struct {
	Validation lc.Validation
}

func (e *ErrInvalidLifecycle) Error() string { return e.Validation.Err().Error() }

// Unwrap makes the error a validation error.
func (e *ErrInvalidLifecycle) Unwrap() error { return shared.ErrValidation }

// PublishVersion publishes a draft. It must compile against the current
// catalog; the previous published version becomes superseded. Audited with
// the old and new spec hashes.
func (s *Service) PublishVersion(ctx context.Context, tenantID, schemeID shared.ID, number int, note string, a Actor) (*lc.Version, error) {
	sc, err := s.schemes.GetScheme(ctx, tenantID, schemeID)
	if err != nil {
		return nil, err
	}
	if sc.IsArchived() {
		return nil, lc.ErrSchemeArchived
	}
	v, err := s.schemes.GetVersion(ctx, tenantID, schemeID, number)
	if err != nil {
		return nil, err
	}
	if v.State != lc.VersionDraft {
		return nil, lc.ErrNotDraft
	}
	validation, err := s.validate(ctx, tenantID, v.Spec)
	if err != nil {
		return nil, err
	}
	if !validation.OK() {
		return nil, &ErrInvalidLifecycle{Validation: validation}
	}
	n, err := plainNote(note)
	if err != nil {
		return nil, err
	}
	previous := ""
	if view, err := s.view(ctx, sc); err == nil && view.Published != nil {
		previous = fmt.Sprintf("v%d (%s)", view.Published.Number, view.Published.SpecHash)
	}
	if err := s.schemes.Publish(ctx, v, n, a.UserID, s.now()); err != nil {
		return nil, err
	}
	s.logAudit(ctx, a, auditapp.NewSuccessEvent(auditdom.ActionLifecyclePublished, auditdom.ResourceTypeLifecycle, sc.ID().String()).
		WithResourceName(sc.Name()).
		WithMessage(fmt.Sprintf("Lifecycle '%s' version %d published", sc.Name(), v.Number)).
		WithMetadata("version", v.Number).WithMetadata("spec_hash", v.SpecHash).
		WithMetadata("previous", previous).WithMetadata("note", n).
		WithMetadata("transitions", len(v.Spec.Transitions)).WithMetadata("sub_statuses", len(v.Spec.SubStatuses)))
	return v, nil
}

// Rollback publishes an older version again, as a new version copied from
// it (history stays linear and every published spec is a row of its own).
func (s *Service) Rollback(ctx context.Context, tenantID, schemeID shared.ID, to int, note string, a Actor) (*lc.Version, error) {
	view, err := s.GetScheme(ctx, tenantID, schemeID)
	if err != nil {
		return nil, err
	}
	if view.Draft != nil {
		return nil, lc.ErrDraftExists
	}
	draft, err := s.CreateDraft(ctx, tenantID, schemeID, to, a)
	if err != nil {
		return nil, err
	}
	if note == "" {
		note = fmt.Sprintf("Roll back to version %d", to)
	}
	// A version that no longer compiles (a sub-status archived since)
	// stays as the draft for the admin to fix.
	return s.PublishVersion(ctx, tenantID, schemeID, draft.Number, note, a)
}

func plainNote(note string) (string, error) {
	if len([]rune(note)) > lc.MaxDescriptionLen {
		return "", fmt.Errorf("%w: a note is at most %d characters", shared.ErrValidation, lc.MaxDescriptionLen)
	}
	return note, nil
}

// ErrAlreadyPublished: the version is the one in force.
var ErrAlreadyPublished = fmt.Errorf("%w: this version is already published", shared.ErrConflict)

// Publish puts version number in force: a draft is published; a superseded
// version is published again as a new version copied from it (a roll back).
func (s *Service) Publish(ctx context.Context, tenantID, schemeID shared.ID, number int, note string, a Actor) (*lc.Version, error) {
	v, err := s.schemes.GetVersion(ctx, tenantID, schemeID, number)
	if err != nil {
		return nil, err
	}
	switch v.State {
	case lc.VersionDraft:
		return s.PublishVersion(ctx, tenantID, schemeID, number, note, a)
	case lc.VersionSuperseded:
		return s.Rollback(ctx, tenantID, schemeID, number, note, a)
	case lc.VersionPublished:
		return nil, ErrAlreadyPublished
	}
	return nil, ErrAlreadyPublished
}
