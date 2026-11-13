// Package toolsource is the application service of the organization keys
// of third-party tool sources: write-only storage (encrypted with the
// credentials key, bound to the organization and the source), the console's
// list and changes, and the values the task secrets fetch delivers.
// Design: docs/architecture/task-secrets.md.
package toolsource

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/contract/secretref"

	auditapp "github.com/openctemio/openctem/server/internal/app/audit"
	"github.com/openctemio/openctem/server/pkg/crypto"
	auditdom "github.com/openctemio/openctem/server/pkg/domain/audit"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	dom "github.com/openctemio/openctem/server/pkg/domain/toolsource"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// AuditLogger records audit events. *auditapp.AuditService implements it.
type AuditLogger interface {
	LogEvent(ctx context.Context, actx auditapp.AuditContext, event auditapp.AuditEvent) error
}

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
	enc, err := s.sealKey(tid, src.ID, value)
	if err != nil {
		return SourceView{}, err
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

// boundKey is the plaintext a key's ciphertext holds. The organization and
// the source bind it to its row: a ciphertext copied onto another
// organization's row, or another source's, does not open there.
type boundKey struct {
	V      int    `json:"v"`
	Tenant string `json:"tid"`
	Source string `json:"source"`
	Value  string `json:"value"`
}

// boundKeyVersion is boundKey.V.
const boundKeyVersion = 1

func (s *Service) sealKey(tid shared.ID, source, value string) (string, error) {
	b, err := json.Marshal(boundKey{V: boundKeyVersion, Tenant: tid.String(), Source: source, Value: value})
	if err != nil {
		return "", err
	}
	ct, err := s.enc.EncryptString(string(b))
	if err != nil {
		return "", fmt.Errorf("encrypt tool source key: %w", err)
	}
	return ct, nil
}

// errKeyUnreadable: a stored key does not open for its row.
var errKeyUnreadable = errors.New("tool source key does not open")

// openKey returns the value of k, only when its ciphertext opens and names
// k's organization and source.
func (s *Service) openKey(k *dom.Key) (string, error) {
	if !s.canEncrypt() {
		return "", errKeyUnreadable
	}
	pt, err := s.enc.DecryptString(k.KeyEnc)
	if err != nil {
		return "", errKeyUnreadable
	}
	var b boundKey
	if json.Unmarshal([]byte(pt), &b) != nil || b.V != boundKeyVersion || b.Tenant != k.TenantID.String() ||
		b.Source != k.Source || b.Value == "" {
		return "", errKeyUnreadable
	}
	return b.Value, nil
}

// EnabledSources returns which of sources the organization holds an enabled
// key for, in sources order. tenantID is the job's organization (the
// claim reads it from the command).
func (s *Service) EnabledSources(ctx context.Context, tenantID shared.ID, sources []string) ([]string, error) {
	if len(sources) == 0 || tenantID.IsZero() || !s.canEncrypt() {
		return nil, nil
	}
	keys, err := s.repo.Enabled(ctx, tenantID, sources)
	if err != nil {
		return nil, err
	}
	have := make(map[string]bool, len(keys))
	for _, k := range keys {
		have[k.Source] = true
	}
	var out []string
	for _, src := range sources {
		if have[src] {
			out = append(out, src)
		}
	}
	return out, nil
}

// Resolved is the state of one source's key at a delivery: the value, or
// why there is none (secretref.Missing*).
type Resolved struct {
	Value   string
	Missing string
}

// ForDelivery returns the organization's key of each of sources for a task
// of its job: the value, or the reason it has none (absent: not_set;
// switched off: disabled; does not open for its row: undecryptable, never
// used as stored). tenantID is read from the command by the caller, never
// from the sensor. Nothing is audited here: the caller audits the delivery
// and calls MarkDelivered for what it sent.
func (s *Service) ForDelivery(ctx context.Context, tenantID shared.ID, sources []string) (map[string]Resolved, error) {
	out := make(map[string]Resolved, len(sources))
	for _, src := range sources {
		out[src] = Resolved{Missing: secretref.MissingNotSet}
	}
	if len(sources) == 0 || tenantID.IsZero() {
		return out, nil
	}
	keys, err := s.repo.List(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	for i := range keys {
		k := &keys[i]
		if _, asked := out[k.Source]; !asked || !k.TenantID.Equals(tenantID) {
			continue
		}
		if !k.Enabled {
			out[k.Source] = Resolved{Missing: secretref.MissingDisabled}
			continue
		}
		v, err := s.openKey(k)
		if err != nil {
			// Never sent, never logged with its value.
			s.logger.Warn("tool source key does not open for its row; not delivered", "tenant_id", tenantID.String(), "source", k.Source)
			out[k.Source] = Resolved{Missing: secretref.MissingUndecryptable}
			continue
		}
		out[k.Source] = Resolved{Value: v}
	}
	return out, nil
}

// MarkDelivered records that the organization's keys of sources were
// delivered (last used). A failure is logged: the delivery stands.
func (s *Service) MarkDelivered(ctx context.Context, tenantID shared.ID, sources []string) {
	if len(sources) == 0 {
		return
	}
	if err := s.repo.MarkUsed(ctx, tenantID, sources, s.now()); err != nil {
		s.logger.Warn("cannot record tool source key use", "tenant_id", tenantID.String(), "error", err)
	}
}

func (s *Service) logAudit(ctx context.Context, actx auditapp.AuditContext, ev auditapp.AuditEvent) {
	if s.audit == nil {
		return
	}
	if err := s.audit.LogEvent(ctx, actx, ev); err != nil {
		s.logger.Error("failed to write tool source key audit event", "action", string(ev.Action), "error", err)
	}
}
