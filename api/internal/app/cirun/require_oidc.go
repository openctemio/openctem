package cirun

import (
	"context"
	"fmt"
	"sync"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Settings are a tenant's CI settings.
type Settings struct {
	// RequireOIDC refuses CI results sent with a sensor key: a CI job must
	// prove its identity with its provider's OIDC token. On for every
	// organization created after migration 001120; existing ones opt in.
	RequireOIDC bool `json:"require_oidc"`
}

// SettingsStore reads and writes the tenant's CI settings.
type SettingsStore interface {
	CIRequireOIDC(ctx context.Context, tenantID shared.ID) (bool, error)
	SetCIRequireOIDC(ctx context.Context, tenantID shared.ID, require bool) error
}

// GetSettings returns the tenant's CI settings.
func (s *Service) GetSettings(ctx context.Context, tenantID shared.ID) (Settings, error) {
	v, err := s.repo.CIRequireOIDC(ctx, tenantID)
	if err != nil {
		return Settings{}, err
	}
	return Settings{RequireOIDC: v}, nil
}

// UpdateSettings writes the tenant's CI settings (audited).
func (s *Service) UpdateSettings(ctx context.Context, tenantID shared.ID, in Settings, a Actor) (Settings, error) {
	cur, err := s.GetSettings(ctx, tenantID)
	if err != nil {
		return Settings{}, err
	}
	if err := s.repo.SetCIRequireOIDC(ctx, tenantID, in.RequireOIDC); err != nil {
		return Settings{}, err
	}
	if cur != in {
		ev := auditapp.NewSuccessEvent(auditdom.ActionCISettingsUpdated, auditdom.ResourceTypeCISettings, tenantID.String()).
			WithMessage(fmt.Sprintf("CI settings: OIDC required for CI results %t -> %t", cur.RequireOIDC, in.RequireOIDC)).
			WithMetadata("require_oidc", in.RequireOIDC).
			WithMetadata("previous_require_oidc", cur.RequireOIDC)
		if !in.RequireOIDC {
			ev = ev.WithSeverity(auditdom.SeverityHigh)
		}
		s.logAudit(ctx, tenantID, a, ev)
	}
	return in, nil
}

// runnerKeyAuditEvery bounds the refusal audit to one row per sensor per
// period: a CI loop retrying with a refused key cannot fill the audit log.
const runnerKeyAuditEvery = 10 * time.Minute

// maxRunnerKeyAuditMemory bounds the de-duplication map.
const maxRunnerKeyAuditMemory = 10_000

// RunnerKeyPolicy decides whether a sensor key may authenticate a CI
// (one-shot, runner) sensor: not when its organization requires OIDC for CI.
type RunnerKeyPolicy struct {
	store SettingsStore
	audit Auditor
	log   *logger.Logger
	now   func() time.Time

	mu      sync.Mutex
	audited map[shared.ID]time.Time
}

// NewRunnerKeyPolicy creates the policy. audit may be nil.
func NewRunnerKeyPolicy(store SettingsStore, audit Auditor, log *logger.Logger) *RunnerKeyPolicy {
	if log == nil {
		log = logger.NewNop()
	}
	return &RunnerKeyPolicy{store: store, audit: audit, log: log.With("component", "ci-runner-key-policy"),
		now: time.Now, audited: map[shared.ID]time.Time{}}
}

// Refused reports whether the sensor's request must be refused: a CI
// (one-shot) sensor of an organization that requires OIDC for CI. A setting
// that cannot be read refuses (fail closed). Every other sensor passes
// without a lookup.
func (p *RunnerKeyPolicy) Refused(ctx context.Context, s *sensor.Sensor, clientIP, userAgent string) bool {
	if p == nil || s == nil || s.TenantID == nil || !s.IsOneShot() {
		return false
	}
	require, err := p.store.CIRequireOIDC(ctx, *s.TenantID)
	if err != nil {
		p.log.Warn("ci runner key policy: setting unreadable, refusing", "sensor_id", s.ID.String(),
			"error", logger.SanitizeError(err))
		require = true
	}
	if require {
		p.auditRefusal(ctx, s, clientIP, userAgent)
	}
	return require
}

func (p *RunnerKeyPolicy) auditRefusal(ctx context.Context, s *sensor.Sensor, clientIP, userAgent string) {
	if p.audit == nil {
		return
	}
	now := p.now()
	p.mu.Lock()
	if last, ok := p.audited[s.ID]; ok && now.Sub(last) < runnerKeyAuditEvery {
		p.mu.Unlock()
		return
	}
	if len(p.audited) >= maxRunnerKeyAuditMemory {
		for id, at := range p.audited {
			if now.Sub(at) >= runnerKeyAuditEvery {
				delete(p.audited, id)
			}
		}
		if len(p.audited) >= maxRunnerKeyAuditMemory {
			p.audited = map[shared.ID]time.Time{}
		}
	}
	p.audited[s.ID] = now
	p.mu.Unlock()
	ev := auditapp.NewDeniedEvent(auditdom.ActionCIRunnerKeyRefused, auditdom.ResourceTypeSensor, s.ID.String(),
		"the organization requires OIDC for CI").
		WithResourceName(s.Name).
		WithMessage(fmt.Sprintf("CI sensor %q refused: this organization requires the CI job's OIDC identity, not a sensor key", s.Name)).
		WithMetadata("sensor_type", string(s.Type))
	if err := p.audit.LogEvent(ctx, auditapp.AuditContext{TenantID: s.TenantID.String(), ActorEmail: "sensor:" + s.ID.String(),
		ActorIP: clientIP, UserAgent: userAgent}, ev); err != nil {
		p.log.Warn("ci runner key refusal not audited", "error", logger.SanitizeError(err))
	}
}
