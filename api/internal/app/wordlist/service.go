// Package wordlist manages an organization's own wordlists
// (docs/architecture/wordlists.md, "Organization lists"): create, edit,
// switch on or off and delete, each change audited.
//
// Threat model and isolation. The tenant always comes from the caller's
// authenticated context (AuditContext.TenantID), never from a request field;
// every repository call is scoped to it, so another organization's list is
// not found (404). Text is normalised and bounded by the domain package
// before anything is stored. Audit events carry the name, version and line
// count only, never the labels.
package wordlist

import (
	"context"
	"fmt"
	"strings"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	dom "github.com/openctemio/openctem/api/pkg/domain/wordlist"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// AuditLogger records audit events. *auditapp.AuditService implements it.
type AuditLogger interface {
	LogEvent(ctx context.Context, actx auditapp.AuditContext, event auditapp.AuditEvent) error
}

// Service manages organization wordlists.
type Service struct {
	repo   dom.Repository
	audit  AuditLogger
	logger *logger.Logger
	now    func() time.Time
}

// NewService creates a Service. audit may be nil (tests).
func NewService(repo dom.Repository, audit AuditLogger, log *logger.Logger) *Service {
	return &Service{repo: repo, audit: audit, logger: log.With("service", "wordlist"), now: time.Now}
}

// Report says what normalising a list's text kept and dropped.
type Report struct {
	Kept       int
	Invalid    int
	Secrets    int
	Duplicates int
	Examples   []string
}

func reportOf(n *dom.Normalized) *Report {
	return &Report{Kept: len(n.Labels), Invalid: n.Invalid, Secrets: n.Secrets, Duplicates: n.Duplicates, Examples: n.Examples}
}

// CreateInput creates a list.
type CreateInput struct {
	Name        string
	Description string
	Text        string
	Enabled     *bool
}

// UpdateInput changes a list; nil fields are unchanged.
type UpdateInput struct {
	Name        *string
	Description *string
	Text        *string
	Enabled     *bool
}

func tenantOf(actx auditapp.AuditContext) (shared.ID, error) {
	tid, err := shared.IDFromString(actx.TenantID)
	if err != nil {
		return shared.ID{}, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	return tid, nil
}

func actorOf(actx auditapp.AuditContext) *shared.ID {
	if id, err := shared.IDFromString(actx.ActorID); err == nil {
		return &id
	}
	return nil
}

// List returns the caller's organization's lists.
func (s *Service) List(ctx context.Context, actx auditapp.AuditContext) ([]*dom.Wordlist, error) {
	tid, err := tenantOf(actx)
	if err != nil {
		return nil, err
	}
	return s.repo.List(ctx, tid)
}

// Get returns one list of the caller's organization; a malformed id or a
// list of another organization is ErrNotFound.
func (s *Service) Get(ctx context.Context, actx auditapp.AuditContext, id string) (*dom.Wordlist, error) {
	tid, err := tenantOf(actx)
	if err != nil {
		return nil, err
	}
	lid, err := shared.IDFromString(id)
	if err != nil {
		return nil, dom.ErrNotFound
	}
	return s.repo.Get(ctx, tid, lid)
}

// Create stores a new list from pasted or uploaded text.
func (s *Service) Create(ctx context.Context, actx auditapp.AuditContext, in CreateInput) (*dom.Wordlist, *Report, error) {
	tid, err := tenantOf(actx)
	if err != nil {
		return nil, nil, err
	}
	name, desc := strings.TrimSpace(in.Name), strings.TrimSpace(in.Description)
	if err := dom.ValidateName(name); err != nil {
		return nil, nil, err
	}
	if err := dom.ValidateDescription(desc); err != nil {
		return nil, nil, err
	}
	n, err := dom.Normalize(in.Text)
	if err != nil {
		return nil, nil, err
	}
	now := s.now().UTC()
	w := &dom.Wordlist{ID: shared.NewID(), TenantID: tid, Name: name, Description: desc, Purpose: dom.PurposeDNSLabels,
		Enabled: in.Enabled == nil || *in.Enabled, Version: 1, Lines: len(n.Labels), SHA256: n.SHA256, Content: n.Content,
		CreatedBy: actorOf(actx), UpdatedBy: actorOf(actx), CreatedAt: now, UpdatedAt: now}
	if err := s.repo.Create(ctx, w); err != nil {
		return nil, nil, err
	}
	s.logAudit(ctx, actx, auditapp.NewSuccessEvent(auditdom.ActionWordlistCreated, auditdom.ResourceTypeWordlist, w.ID.String()).
		WithResourceName(w.Name).
		WithMessage(fmt.Sprintf("Wordlist '%s' created", w.Name)).
		WithMetadata("version", w.Version).
		WithMetadata("lines", w.Lines).
		WithMetadata("enabled", w.Enabled).
		WithSeverity(auditdom.SeverityMedium))
	return w, reportOf(n), nil
}

// Update changes a list. The version rises only when the labels change.
func (s *Service) Update(ctx context.Context, actx auditapp.AuditContext, id string, in UpdateInput) (*dom.Wordlist, *Report, error) {
	w, err := s.Get(ctx, actx, id)
	if err != nil {
		return nil, nil, err
	}
	changes := auditdom.NewChanges()
	if in.Name != nil {
		name := strings.TrimSpace(*in.Name)
		if err := dom.ValidateName(name); err != nil {
			return nil, nil, err
		}
		if name != w.Name {
			changes.Set("name", w.Name, name)
			w.Name = name
		}
	}
	if in.Description != nil {
		desc := strings.TrimSpace(*in.Description)
		if err := dom.ValidateDescription(desc); err != nil {
			return nil, nil, err
		}
		w.Description = desc
	}
	if in.Enabled != nil && *in.Enabled != w.Enabled {
		changes.Set("enabled", w.Enabled, *in.Enabled)
		w.Enabled = *in.Enabled
	}
	var rep *Report
	if in.Text != nil {
		n, err := dom.Normalize(*in.Text)
		if err != nil {
			return nil, nil, err
		}
		rep = reportOf(n)
		if n.SHA256 != w.SHA256 {
			changes.Set("version", w.Version, w.Version+1)
			changes.Set("lines", w.Lines, len(n.Labels))
			w.Version++
			w.Lines, w.SHA256, w.Content = len(n.Labels), n.SHA256, n.Content
		}
	}
	w.UpdatedBy, w.UpdatedAt = actorOf(actx), s.now().UTC()
	if err := s.repo.Update(ctx, w); err != nil {
		return nil, nil, err
	}
	s.logAudit(ctx, actx, auditapp.NewSuccessEvent(auditdom.ActionWordlistUpdated, auditdom.ResourceTypeWordlist, w.ID.String()).
		WithResourceName(w.Name).
		WithMessage(fmt.Sprintf("Wordlist '%s' updated", w.Name)).
		WithChanges(changes).
		WithMetadata("version", w.Version).
		WithSeverity(auditdom.SeverityMedium))
	return w, rep, nil
}

// Delete removes a list.
func (s *Service) Delete(ctx context.Context, actx auditapp.AuditContext, id string) error {
	w, err := s.Get(ctx, actx, id)
	if err != nil {
		return err
	}
	if err := s.repo.Delete(ctx, w.TenantID, w.ID); err != nil {
		return err
	}
	s.logAudit(ctx, actx, auditapp.NewSuccessEvent(auditdom.ActionWordlistDeleted, auditdom.ResourceTypeWordlist, w.ID.String()).
		WithResourceName(w.Name).
		WithMessage(fmt.Sprintf("Wordlist '%s' deleted", w.Name)).
		WithMetadata("version", w.Version).
		WithMetadata("lines", w.Lines).
		WithSeverity(auditdom.SeverityMedium))
	return nil
}

func (s *Service) logAudit(ctx context.Context, actx auditapp.AuditContext, ev auditapp.AuditEvent) {
	if s.audit == nil {
		return
	}
	if err := s.audit.LogEvent(ctx, actx, ev); err != nil {
		s.logger.Error("failed to write wordlist audit event", "action", string(ev.Action), "error", err)
	}
}
