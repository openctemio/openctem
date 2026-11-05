// Package toolsource is the application service of the organization keys
// of third-party tool sources: write-only storage (encrypted with the
// credentials key), the console's list and changes, and the delivery of an
// organization's keys to the sensor holding a task of its job.
// Design: docs/architecture/tool-source-keys.md.
package toolsource

import (
	"context"
	"errors"
	"fmt"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/crypto"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	dom "github.com/openctemio/openctem/api/pkg/domain/toolsource"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// AuditLogger records audit events. *auditapp.AuditService implements it.
type AuditLogger interface {
	LogEvent(ctx context.Context, actx auditapp.AuditContext, event auditapp.AuditEvent) error
}

// sensorAuditActor names the sensor channel as the actor of a delivery.
const sensorAuditActor = "sensor"

// ErrUnavailable: keys cannot be stored because no credentials key is
// configured (nothing is ever stored in clear).
var ErrUnavailable = shared.NewDomainError("TOOL_SOURCE_KEYS_UNAVAILABLE",
	"tool source keys cannot be stored: the platform has no encryption key configured", shared.ErrValidation)

// Service manages an organization's tool source keys.
type Service struct {
	repo   dom.Repository
	enc    crypto.Encryptor
	audit  AuditLogger
	logger *logger.Logger
	now    func() time.Time
}

// NewService creates the service. enc encrypts keys; a nil or no-op
// encryptor refuses every key. audit may be nil (tests).
func NewService(repo dom.Repository, enc crypto.Encryptor, audit AuditLogger, log *logger.Logger) *Service {
	return &Service{repo: repo, enc: enc, audit: audit, logger: log.With("service", "tool_source_keys"), now: time.Now}
}

func (s *Service) canEncrypt() bool {
	if s.enc == nil {
		return false
	}
	_, noop := s.enc.(*crypto.NoOpEncryptor)
	return !noop
}

// SourceView is one catalog source with the organization's key facts (nil
// Key: none stored). It never carries the key.
type SourceView struct {
	Source dom.Source
	Key    *KeyFacts
}

// KeyFacts are what the console shows of a stored key.
type KeyFacts struct {
	Last4         string
	Enabled       bool
	UpdatedAt     time.Time
	UpdatedByName string
	LastUsedAt    *time.Time
}

func factsOf(k *dom.Key) *KeyFacts {
	if k == nil {
		return nil
	}
	return &KeyFacts{Last4: k.Last4, Enabled: k.Enabled, UpdatedAt: k.UpdatedAt, UpdatedByName: k.UpdatedByName, LastUsedAt: k.LastUsedAt}
}

func parseTenant(tenantID string) (shared.ID, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return shared.ID{}, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	return tid, nil
}

func actorID(actx auditapp.AuditContext) *shared.ID {
	if id, err := shared.IDFromString(actx.ActorID); err == nil {
		return &id
	}
	return nil
}

// lookup is the catalog source id names; an unknown id is not found.
func lookup(id string) (dom.Source, error) {
	src, ok := dom.Lookup(id)
	if !ok {
		return dom.Source{}, shared.ErrNotFound
	}
	return src, nil
}

// List returns every catalog source with the organization's key facts.
func (s *Service) List(ctx context.Context, tenantID string) ([]SourceView, error) {
	tid, err := parseTenant(tenantID)
	if err != nil {
		return nil, err
	}
	keys, err := s.repo.List(ctx, tid)
	if err != nil {
		return nil, err
	}
	byID := make(map[string]*dom.Key, len(keys))
	for i := range keys {
		byID[keys[i].Source] = &keys[i]
	}
	cat := dom.Catalog()
	out := make([]SourceView, 0, len(cat))
	for _, src := range cat {
		out = append(out, SourceView{Source: src, Key: factsOf(byID[src.ID])})
	}
	return out, nil
}

func (s *Service) view(ctx context.Context, tid shared.ID, src dom.Source) (SourceView, error) {
	k, err := s.repo.Get(ctx, tid, src.ID)
	if err != nil && !errors.Is(err, shared.ErrNotFound) {
		return SourceView{}, err
	}
	return SourceView{Source: src, Key: factsOf(k)}, nil
}

// StoreKey stores or replaces (rotates) the organization's key of a source.
func (s *Service) StoreKey(ctx context.Context, tenantID, sourceID, value string, actx auditapp.AuditContext) (SourceView, error) {
	tid, err := parseTenant(tenantID)
	if err != nil {
		return SourceView{}, err
	}
	src, err := lookup(sourceID)
	if err != nil {
		return SourceView{}, err
	}
	if err := src.ValidateValue(value); err != nil {
		return SourceView{}, err
	}
	if !s.canEncrypt() {
		return SourceView{}, ErrUnavailable
	}
	enc, err := s.enc.EncryptString(value)
	if err != nil {
		return SourceView{}, fmt.Errorf("encrypt tool source key: %w", err)
	}
	_, getErr := s.repo.Get(ctx, tid, src.ID)
	rotated := getErr == nil
	by := actorID(actx)
	k := &dom.Key{TenantID: tid, Source: src.ID, KeyEnc: enc, Last4: src.Last4(value), Enabled: true,
		CreatedBy: by, UpdatedBy: by, UpdatedAt: s.now()}
	if err := s.repo.Upsert(ctx, k); err != nil {
		return SourceView{}, err
	}
	msg := fmt.Sprintf("Key of tool source '%s' set", src.Name)
	if rotated {
		msg = fmt.Sprintf("Key of tool source '%s' replaced", src.Name)
	}
	s.logAudit(ctx, actx, auditapp.NewSuccessEvent(auditdom.ActionToolSourceKeySet, auditdom.ResourceTypeToolSourceKey, src.ID).
		WithResourceName(src.Name).WithMessage(msg).WithMetadata("rotated", rotated).WithMetadata("last4", k.Last4))
	return s.view(ctx, tid, src)
}

// SwitchKey switches the organization's key of a source on or off.
func (s *Service) SwitchKey(ctx context.Context, tenantID, sourceID string, enabled bool, actx auditapp.AuditContext) (SourceView, error) {
	tid, err := parseTenant(tenantID)
	if err != nil {
		return SourceView{}, err
	}
	src, err := lookup(sourceID)
	if err != nil {
		return SourceView{}, err
	}
	if err := s.repo.SetEnabled(ctx, tid, src.ID, enabled, actorID(actx)); err != nil {
		return SourceView{}, err
	}
	action, word := auditdom.ActionToolSourceKeyDisabled, "disabled"
	if enabled {
		action, word = auditdom.ActionToolSourceKeyEnabled, "enabled"
	}
	s.logAudit(ctx, actx, auditapp.NewSuccessEvent(action, auditdom.ResourceTypeToolSourceKey, src.ID).
		WithResourceName(src.Name).WithMessage(fmt.Sprintf("Key of tool source '%s' %s", src.Name, word)))
	return s.view(ctx, tid, src)
}

// DeleteKey removes the organization's key of a source.
func (s *Service) DeleteKey(ctx context.Context, tenantID, sourceID string, actx auditapp.AuditContext) error {
	tid, err := parseTenant(tenantID)
	if err != nil {
		return err
	}
	src, err := lookup(sourceID)
	if err != nil {
		return err
	}
	if err := s.repo.Delete(ctx, tid, src.ID); err != nil {
		return err
	}
	s.logAudit(ctx, actx, auditapp.NewSuccessEvent(auditdom.ActionToolSourceKeyDeleted, auditdom.ResourceTypeToolSourceKey, src.ID).
		WithResourceName(src.Name).WithMessage(fmt.Sprintf("Key of tool source '%s' removed", src.Name)))
	return nil
}

// Credential is one key delivered to a task, by the credential name the
// tool's manifest declares.
type Credential struct {
	Name  string
	Value string
}

// Delivery names who receives the keys, for the audit trail.
type Delivery struct {
	SensorID  shared.ID
	CommandID shared.ID
}

// ForTask returns the organization's enabled keys of tool for one task of
// its job. tenantID is the job's organization, read from the command by the
// caller, never from the sensor. A key that cannot be decrypted is skipped
// (never used as stored). Every delivery is audited (sources only) and
// marks the keys used.
func (s *Service) ForTask(ctx context.Context, tenantID shared.ID, tool string, d Delivery) ([]Credential, error) {
	sources := dom.ForTool(tool)
	if len(sources) == 0 || tenantID.IsZero() || !s.canEncrypt() {
		return nil, nil
	}
	keys, err := s.repo.Enabled(ctx, tenantID, sources)
	if err != nil {
		return nil, err
	}
	out := make([]Credential, 0, len(keys))
	names := make([]string, 0, len(keys))
	for _, k := range keys {
		v, err := s.enc.DecryptString(k.KeyEnc)
		if err != nil || v == "" {
			s.logger.Warn("tool source key cannot be decrypted; not delivered", "tenant_id", tenantID.String(), "source", k.Source)
			continue
		}
		out = append(out, Credential{Name: k.Source, Value: v})
		names = append(names, k.Source)
	}
	if len(names) == 0 {
		return out, nil
	}
	if err := s.repo.MarkUsed(ctx, tenantID, names, s.now()); err != nil {
		s.logger.Warn("cannot record tool source key use", "tenant_id", tenantID.String(), "error", err)
	}
	s.logAudit(ctx, auditapp.AuditContext{TenantID: tenantID.String(), ActorEmail: sensorAuditActor},
		auditapp.NewSuccessEvent(auditdom.ActionToolSourceKeyDelivered, auditdom.ResourceTypeToolSourceKey, tool).
			WithResourceName(tool).
			WithMessage(fmt.Sprintf("%d tool source keys delivered to a sensor for a %s task", len(names), tool)).
			WithMetadata("sources", names).WithMetadata("sensor_id", d.SensorID.String()).
			WithMetadata("command_id", d.CommandID.String()))
	return out, nil
}

func (s *Service) logAudit(ctx context.Context, actx auditapp.AuditContext, ev auditapp.AuditEvent) {
	if s.audit == nil {
		return
	}
	if err := s.audit.LogEvent(ctx, actx, ev); err != nil {
		s.logger.Error("failed to write tool source key audit event", "action", string(ev.Action), "error", err)
	}
}
