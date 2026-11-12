// Package sourceretire runs "stop using this source"
// (docs/architecture/source-retirement.md): it resolves and authorizes the
// source, previews what retiring it does, archives the findings only it
// reported in batches with a journal, and restores exactly that set when the
// source is used again.
package sourceretire

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	auditapp "github.com/openctemio/openctem/server/internal/app/audit"
	auditdom "github.com/openctemio/openctem/server/pkg/domain/audit"
	"github.com/openctemio/openctem/server/pkg/domain/sensor"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	dom "github.com/openctemio/openctem/server/pkg/domain/sourceretire"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// RequestBudget is how long a request runs archive or restore batches
// before it answers with the progress; the controller finishes the rest.
const RequestBudget = 3 * time.Second

// SensorReader reads a tenant's sensor.
type SensorReader interface {
	GetByTenantAndID(ctx context.Context, tenantID, id shared.ID) (*sensor.Sensor, error)
}

// ConnectorSources resolves a connector integration of the tenant to the
// sensor and tool it imports through (tenablesc.Service).
type ConnectorSources interface {
	ConnectorSource(ctx context.Context, tenantID, integrationID shared.ID) (sensorID shared.ID, tool, name string, err error)
}

// ScopeResolver resolves the caller's data scope (datascope.Enforcer); it
// fails closed when it is not wired.
type ScopeResolver interface {
	ResolveStrict(ctx context.Context, tenantID shared.ID) (*shared.DataScope, error)
}

// Auditor writes audit events.
type Auditor interface {
	LogEvent(ctx context.Context, actx auditapp.AuditContext, event auditapp.AuditEvent) error
}

// Actor is who asks.
type Actor struct {
	UserID    string
	Email     string
	IP        string
	UserAgent string
	RequestID string
}

// Source is how a request names a source: a selector, or a connector
// integration (resolved here, never trusted from the client).
type Source struct {
	Selector      dom.Selector
	IntegrationID *shared.ID
}

// RetireInput is the dialog's apply.
type RetireInput struct {
	Source          Source
	Options         dom.Options
	Reason          string
	ConfirmCritical bool
}

// Service implements the use cases.
type Service struct {
	repo       dom.Repository
	sensors    SensorReader
	connectors ConnectorSources
	scope      ScopeResolver
	audit      Auditor
	log        *logger.Logger
	now        func() time.Time
	budget     time.Duration
}

// NewService returns the service. connectors may be nil (no connector
// integrations in this build).
func NewService(repo dom.Repository, sensors SensorReader, connectors ConnectorSources, scope ScopeResolver,
	audit Auditor, log *logger.Logger,
) *Service {
	return &Service{repo: repo, sensors: sensors, connectors: connectors, scope: scope, audit: audit,
		log: log.With("service", "source_retire"), now: time.Now, budget: RequestBudget}
}

// resolved is a source after validation.
type resolved struct {
	sel           dom.Selector
	integrationID *shared.ID
	label         string
}

// authorize refuses a caller whose data scope is restricted: the source's
// findings are the whole organization's, so a scoped caller could neither
// see the counts nor be allowed to change findings outside the scope.
func (s *Service) authorize(ctx context.Context, tenantID shared.ID) error {
	if s.scope == nil {
		return dom.ErrFullDataAccessRequired
	}
	scope, err := s.scope.ResolveStrict(ctx, tenantID)
	if err != nil {
		return fmt.Errorf("resolve data scope: %w", err)
	}
	if scope.Restricted() {
		return dom.ErrFullDataAccessRequired
	}
	return nil
}

// resolve validates the source in the tenant: a sensor must be one of the
// tenant's own, an integration one of its connector integrations;
// anything else is not found.
func (s *Service) resolve(ctx context.Context, tenantID shared.ID, src Source) (*resolved, error) {
	out := &resolved{}
	if src.IntegrationID != nil {
		if s.connectors == nil {
			return nil, dom.ErrSourceNotFound
		}
		sensorID, tool, name, err := s.connectors.ConnectorSource(ctx, tenantID, *src.IntegrationID)
		if err != nil {
			if errors.Is(err, shared.ErrNotFound) {
				return nil, dom.ErrSourceNotFound
			}
			return nil, err
		}
		id := *src.IntegrationID
		out.sel = dom.Selector{Kind: dom.KindSensorTool, SensorID: &sensorID, Tool: tool}
		out.integrationID, out.label = &id, name
	} else {
		out.sel = src.Selector.Normalize()
	}
	if err := out.sel.Validate(); err != nil {
		return nil, err
	}
	if out.sel.Kind == dom.KindSensorTool {
		sn, err := s.sensors.GetByTenantAndID(ctx, tenantID, *out.sel.SensorID)
		if err != nil || sn == nil || sn.TenantID == nil || *sn.TenantID != tenantID {
			return nil, dom.ErrSourceNotFound
		}
		if out.label == "" {
			out.label = clip(sn.Name+" "+out.sel.Tool, dom.MaxLabel)
		}
	}
	if out.label == "" {
		switch out.sel.Kind {
		case dom.KindUpload:
			out.label = clip("upload "+out.sel.Tool, dom.MaxLabel)
		default:
			out.label = clip(out.sel.Sender, dom.MaxLabel)
		}
	}
	return out, nil
}

// Preview says what retiring the source would do (the same query the
// archive runs).
func (s *Service) Preview(ctx context.Context, tenantID shared.ID, src Source, opts dom.Options) (*dom.Preview, string, error) {
	if err := s.authorize(ctx, tenantID); err != nil {
		return nil, "", err
	}
	r, err := s.resolve(ctx, tenantID, src)
	if err != nil {
		return nil, "", err
	}
	opts, err = opts.Normalize()
	if err != nil {
		return nil, "", err
	}
	p, err := s.repo.Preview(ctx, tenantID, r.sel, opts, nil)
	if err != nil {
		return nil, "", err
	}
	return p, r.label, nil
}

// Retire stops using the source: from now on its data is refused, and the
// findings only it reported are archived (in batches; the retirement says
// how far it got). A second call for a live retirement returns it.
func (s *Service) Retire(ctx context.Context, tenantID shared.ID, in RetireInput, a Actor) (*dom.Retirement, *dom.Preview, error) {
	if err := s.authorize(ctx, tenantID); err != nil {
		return nil, nil, err
	}
	reason := strings.TrimSpace(in.Reason)
	if n := len([]rune(reason)); n < dom.MinReason || n > dom.MaxReason {
		return nil, nil, fmt.Errorf("%w: a reason of %d to %d characters is required", shared.ErrValidation, dom.MinReason, dom.MaxReason)
	}
	r, err := s.resolve(ctx, tenantID, in.Source)
	if err != nil {
		return nil, nil, err
	}
	opts, err := in.Options.Normalize()
	if err != nil {
		return nil, nil, err
	}
	p, err := s.repo.Preview(ctx, tenantID, r.sel, opts, nil)
	if err != nil {
		return nil, nil, err
	}
	if p.CriticalOrKEV > 0 && !in.ConfirmCritical {
		return nil, p, dom.ErrConfirmCriticalRequired
	}
	var by *shared.ID
	if uid, err := shared.IDFromString(a.UserID); err == nil && !uid.IsZero() {
		by = &uid
	}
	ret, err := s.repo.Create(ctx, &dom.Retirement{TenantID: tenantID, Selector: r.sel, IntegrationID: r.integrationID,
		Label: r.label, Options: opts, Reason: reason, PlannedCount: p.Archive, RetiredBy: by})
	if err != nil {
		return nil, nil, err
	}
	if ret.AlreadyRetired {
		return ret, p, nil
	}
	archived, err := s.runBatches(ctx, tenantID, ret.ID, dom.StateApplying)
	if err != nil {
		// The retirement stands (data is blocked); the controller retries.
		s.log.Warn("source retirement batches failed; the controller retries", "tenant_id", tenantID.String(),
			"retirement_id", ret.ID.String(), "error", logger.SanitizeError(err))
	}
	s.logAudit(ctx, tenantID, a, auditapp.NewSuccessEvent(auditdom.ActionSourceRetired, auditdom.ResourceTypeImportSource, ret.ID.String()).
		WithResourceName(r.label).
		WithMessage(fmt.Sprintf("Import source %s retired; %d finding(s) only it reported to archive as source retired", r.label, p.Archive)).
		WithMetadata("reason", reason).
		WithMetadata("kind", string(r.sel.Kind)).
		WithMetadata("mode", string(opts.Mode)).
		WithMetadata("severities", opts.SeverityStrings()).
		WithMetadata("include_engaged", opts.IncludeEngaged).
		WithMetadata("preview", p).
		WithMetadata("finding_ids", auditIDs(archived)).
		WithSeverity(auditdom.SeverityHigh))
	got, err := s.repo.Get(ctx, tenantID, ret.ID)
	if err != nil {
		return nil, nil, err
	}
	return got, p, nil
}

// Restore uses the source again: its data is accepted at once, and the
// findings the retirement archived are restored (in batches) unless
// someone changed them since.
func (s *Service) Restore(ctx context.Context, tenantID, id shared.ID, reason string, a Actor) (*dom.Retirement, error) {
	if err := s.authorize(ctx, tenantID); err != nil {
		return nil, err
	}
	reason = strings.TrimSpace(reason)
	if len([]rune(reason)) > dom.MaxReason {
		return nil, fmt.Errorf("%w: the reason is too long", shared.ErrValidation)
	}
	var by *shared.ID
	if uid, err := shared.IDFromString(a.UserID); err == nil && !uid.IsZero() {
		by = &uid
	}
	ret, err := s.repo.StartRestore(ctx, tenantID, id, by, reason)
	if err != nil {
		return nil, err
	}
	restored, err := s.runBatches(ctx, tenantID, id, dom.StateRestoring)
	if err != nil {
		s.log.Warn("source restore batches failed; the controller retries", "tenant_id", tenantID.String(),
			"retirement_id", id.String(), "error", logger.SanitizeError(err))
	}
	s.logAudit(ctx, tenantID, a, auditapp.NewSuccessEvent(auditdom.ActionSourceRestored, auditdom.ResourceTypeImportSource, id.String()).
		WithResourceName(ret.Label).
		WithMessage(fmt.Sprintf("Import source %s used again; its archived findings are restored", ret.Label)).
		WithMetadata("reason", reason).
		WithMetadata("finding_ids", auditIDs(restored)).
		WithSeverity(auditdom.SeverityHigh))
	return s.repo.Get(ctx, tenantID, id)
}

// Get returns one retirement.
func (s *Service) Get(ctx context.Context, tenantID, id shared.ID) (*dom.Retirement, error) {
	if err := s.authorize(ctx, tenantID); err != nil {
		return nil, err
	}
	return s.repo.Get(ctx, tenantID, id)
}

// List returns the tenant's retirements.
func (s *Service) List(ctx context.Context, tenantID shared.ID, includeRestored bool) ([]*dom.Retirement, error) {
	if err := s.authorize(ctx, tenantID); err != nil {
		return nil, err
	}
	return s.repo.List(ctx, tenantID, includeRestored, 500)
}

// runBatches runs the batches of the state for at most the budget and
// returns the finding ids it moved.
func (s *Service) runBatches(ctx context.Context, tenantID, id shared.ID, state dom.State) ([]shared.ID, error) {
	deadline := s.now().Add(s.budget)
	var moved []shared.ID
	for {
		var (
			res *dom.BatchResult
			err error
		)
		if state == dom.StateApplying {
			res, err = s.repo.ArchiveBatch(ctx, tenantID, id, s.now().UTC())
		} else {
			res, err = s.repo.RestoreBatch(ctx, tenantID, id, s.now().UTC())
		}
		if err != nil {
			return moved, err
		}
		moved = append(moved, res.IDs...)
		if res.Finished || !s.now().Before(deadline) {
			return moved, nil
		}
	}
}

// ProcessPending resumes retirements with batches left (the controller):
// a request that ran out of budget, or a process that stopped mid-way.
func (s *Service) ProcessPending(ctx context.Context, limit int) (int, error) {
	refs, err := s.repo.Pending(ctx, limit)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, ref := range refs {
		moved, err := s.runBatches(ctx, ref.TenantID, ref.ID, ref.State)
		n += len(moved)
		if err != nil {
			s.log.Warn("source retirement batch failed", "tenant_id", ref.TenantID.String(),
				"retirement_id", ref.ID.String(), "error", logger.SanitizeError(err))
		}
	}
	return n, nil
}

func (s *Service) logAudit(ctx context.Context, tenantID shared.ID, a Actor, ev auditapp.AuditEvent) {
	if s.audit == nil {
		return
	}
	if err := s.audit.LogEvent(ctx, auditapp.AuditContext{TenantID: tenantID.String(), ActorID: a.UserID,
		ActorEmail: a.Email, ActorIP: a.IP, UserAgent: a.UserAgent, RequestID: a.RequestID}, ev); err != nil {
		s.log.Warn("source retirement audit record not written", "action", ev.Action.String(), "error", logger.SanitizeError(err))
	}
}

func auditIDs(ids []shared.ID) []string {
	out := make([]string, 0, min(len(ids), dom.MaxAuditedIDs))
	for i, id := range ids {
		if i == dom.MaxAuditedIDs {
			break
		}
		out = append(out, id.String())
	}
	return out
}

func clip(s string, n int) string {
	r := []rune(strings.TrimSpace(s))
	if len(r) > n {
		return string(r[:n])
	}
	return string(r)
}
