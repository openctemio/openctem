// Package contentpack is the application service of the content pack store:
// ingest (canonical archive, lint, tier, credential scan), signing, storage,
// listing and revocation, with audit. Design and threat model:
// docs/rfcs/RFC-061-content-packs.md.
package contentpack

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	dom "github.com/openctemio/openctem/api/pkg/domain/contentpack"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Quotas and bounds.
const (
	MaxPacksPerTenant = 500
	MaxBytesPerTenant = int64(2) << 30
	// ingestTimeout bounds one ingest (unpack, lint, sign).
	ingestTimeout = 60 * time.Second
	// concurrentIngests bounds the memory uploads can hold at once.
	concurrentIngests = 2
	maxRevokeReason   = 500
	maxListLimit      = 100
)

// AuditLogger records audit events. *auditapp.AuditService implements it.
type AuditLogger interface {
	LogEvent(ctx context.Context, actx auditapp.AuditContext, event auditapp.AuditEvent) error
}

// Storage keeps the canonical archives in each tenant's namespace
// (attachment.FileStorage implements it).
type Storage interface {
	Upload(ctx context.Context, tenantID, filename, contentType string, r io.Reader) (string, error)
	Download(ctx context.Context, tenantID, storageKey string) (io.ReadCloser, string, error)
	Delete(ctx context.Context, tenantID, storageKey string) error
}

// Service manages a tenant's content packs.
type Service struct {
	repo   dom.Repository
	store  Storage
	signer *dom.Signer
	audit  AuditLogger
	logger *logger.Logger
	now    func() time.Time
	limits dom.Limits
	ingest chan struct{}
}

// NewService creates the service. signer nil (no content signing key)
// refuses every upload: an unsigned pack is never stored. audit may be nil
// (tests).
func NewService(repo dom.Repository, store Storage, signer *dom.Signer, audit AuditLogger, log *logger.Logger) *Service {
	return &Service{
		repo: repo, store: store, signer: signer, audit: audit,
		logger: log.With("service", "content_pack"),
		now:    time.Now,
		limits: dom.DefaultLimits,
		ingest: make(chan struct{}, concurrentIngests),
	}
}

// Limits are the archive limits of an upload.
func (s *Service) Limits() dom.Limits { return s.limits }

// UploadInput is a tenant upload.
type UploadInput struct {
	TenantID string
	Name     string
	Version  string
	Kind     string
	Archive  io.Reader // tar or tar.gz
	// AcknowledgeSecrets stores a pack in which lint found what look like
	// credentials (recorded in the lint report and the audit log).
	AcknowledgeSecrets bool
	CreatedBy          string
}

// LintError is a refused pack with its report (code CONTENT_LINT_FAILED or
// CONTENT_SECRETS_FOUND).
func lintError(code string, base error, rep dom.LintReport) error {
	return shared.NewDomainError(code, strings.TrimPrefix(base.Error(), shared.ErrValidation.Error()+": "), base).WithDetails(rep)
}

// Upload ingests, lints, signs and stores a pack.
func (s *Service) Upload(ctx context.Context, in UploadInput, actx auditapp.AuditContext) (*dom.Pack, error) {
	if err := errors.Join(dom.ValidateName(in.Name), dom.ValidateVersion(in.Version), dom.ValidateKind(in.Kind)); err != nil {
		return nil, err
	}
	if s.signer == nil {
		return nil, dom.ErrSigningKey
	}
	tid, err := parseTenant(in.TenantID)
	if err != nil {
		return nil, err
	}
	packs, used, err := s.repo.Usage(ctx, tid)
	if err != nil {
		return nil, err
	}
	if packs >= MaxPacksPerTenant {
		return nil, fmt.Errorf("%w (%d packs)", dom.ErrQuota, MaxPacksPerTenant)
	}

	select {
	case s.ingest <- struct{}{}:
		defer func() { <-s.ingest }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	ictx, cancel := context.WithTimeout(ctx, ingestTimeout)
	defer cancel()

	arc, err := dom.Canonicalize(in.Archive, s.limits)
	if err != nil {
		return nil, err
	}
	rep := Lint(ictx, in.Kind, arc.Files)
	if len(rep.Errors) > 0 {
		return nil, lintError("CONTENT_LINT_FAILED", dom.ErrLintFailed, rep)
	}
	if len(rep.Secrets) > 0 {
		if !in.AcknowledgeSecrets {
			return nil, lintError("CONTENT_SECRETS_FOUND", dom.ErrSecretsFound, rep)
		}
		rep.SecretsAcknowledged = true
	}

	blob, err := s.storeBlob(ictx, tid, arc, used)
	if err != nil {
		return nil, err
	}
	now := s.now().UTC()
	p := &dom.Pack{
		ID: shared.NewID(), TenantID: tid, Name: in.Name, Version: in.Version, Kind: in.Kind,
		Digest: arc.Digest, SizeBytes: blob.SizeBytes, FileCount: blob.FileCount,
		Tier: rep.Tier, Status: dom.StatusActive, Source: dom.SourceUpload, Lint: rep, CreatedAt: now,
	}
	if uid, err := shared.IDFromString(in.CreatedBy); err == nil && !uid.IsZero() {
		p.CreatedBy = &uid
	}
	p.Signature, err = s.signer.Sign(dom.Statement{
		TenantID: tid.String(), PackID: p.ID.String(), Name: p.Name, Version: p.Version, Content: p.Kind,
		Digest: p.Digest, Size: p.SizeBytes, Files: p.FileCount, Tier: p.Tier, CreatedAt: now,
	})
	if err != nil {
		return nil, fmt.Errorf("sign content pack: %w", err)
	}
	if err := s.repo.Create(ctx, p); err != nil {
		return nil, err
	}

	ev := auditapp.NewSuccessEvent(auditdom.ActionContentPackCreated, auditdom.ResourceTypeContentPack, p.ID.String()).
		WithResourceName(p.Name+"@"+p.Version).
		WithMessage(fmt.Sprintf("Content pack '%s@%s' uploaded (%s, %s)", p.Name, p.Version, p.Kind, p.Tier)).
		WithMetadata("kind", p.Kind).
		WithMetadata("digest", p.Digest).
		WithMetadata("tier", string(p.Tier)).
		WithMetadata("files", p.FileCount).
		WithMetadata("size_bytes", p.SizeBytes)
	if rep.SecretsAcknowledged {
		ev = ev.WithMetadata("secrets_acknowledged", len(rep.Secrets)).WithSeverity(auditdom.SeverityHigh)
	}
	s.logAudit(ctx, actx, ev)
	return p, nil
}

// storeBlob stores the canonical archive once per tenant and digest.
func (s *Service) storeBlob(ctx context.Context, tid shared.ID, arc *dom.Archive, used int64) (*dom.Blob, error) {
	b, err := s.repo.GetBlob(ctx, tid, arc.Digest)
	if err == nil {
		return b, nil
	}
	if !errors.Is(err, dom.ErrNotFound) {
		return nil, err
	}
	if used+arc.Size() > MaxBytesPerTenant {
		return nil, fmt.Errorf("%w (%d bytes stored)", dom.ErrQuota, MaxBytesPerTenant)
	}
	name := strings.TrimPrefix(arc.Digest, "sha256:") + ".tar"
	key, err := s.store.Upload(ctx, tid.String(), name, "application/x-tar", bytes.NewReader(arc.Canonical))
	if err != nil {
		return nil, fmt.Errorf("store content pack: %w", err)
	}
	b = &dom.Blob{TenantID: tid, Digest: arc.Digest, SizeBytes: arc.Size(), FileCount: len(arc.Files), StorageKey: key, CreatedAt: s.now().UTC()}
	created, err := s.repo.CreateBlob(ctx, b)
	if err != nil || !created {
		// A concurrent upload stored the same digest first (or the row
		// failed): ours is unused.
		if derr := s.store.Delete(ctx, tid.String(), key); derr != nil {
			s.logger.Warn("failed to delete an unused content pack object", "error", derr)
		}
		if err != nil {
			return nil, err
		}
		return s.repo.GetBlob(ctx, tid, arc.Digest)
	}
	return b, nil
}

// Get returns a pack of the tenant.
func (s *Service) Get(ctx context.Context, tenantID, id string) (*dom.Pack, error) {
	tid, pid, err := parseIDs(tenantID, id)
	if err != nil {
		return nil, err
	}
	return s.repo.GetByID(ctx, tid, pid)
}

// ListInput filters and pages a list.
type ListInput struct {
	TenantID string
	Kind     string
	Name     string
	Status   string
	Limit    int
	Offset   int
}

// List returns a page of the tenant's packs and the total.
func (s *Service) List(ctx context.Context, in ListInput) ([]*dom.Pack, int, error) {
	tid, err := parseTenant(in.TenantID)
	if err != nil {
		return nil, 0, err
	}
	switch dom.Status(in.Status) {
	case "", dom.StatusActive, dom.StatusRevoked:
	default:
		return nil, 0, fmt.Errorf("%w: status must be active or revoked", shared.ErrValidation)
	}
	if in.Limit <= 0 || in.Limit > maxListLimit {
		in.Limit = maxListLimit
	}
	if in.Offset < 0 {
		in.Offset = 0
	}
	return s.repo.List(ctx, tid, dom.Filter{Kind: in.Kind, Name: in.Name, Status: dom.Status(in.Status)}, in.Limit, in.Offset)
}

// Revoke revokes a pack: it stays listed, with who revoked it and why, and
// is never delivered again.
func (s *Service) Revoke(ctx context.Context, tenantID, id, reason string, actx auditapp.AuditContext) (*dom.Pack, error) {
	tid, pid, err := parseIDs(tenantID, id)
	if err != nil {
		return nil, err
	}
	reason = strings.TrimSpace(reason)
	if reason == "" || len(reason) > maxRevokeReason {
		return nil, fmt.Errorf("%w: a reason of 1 to %d characters is required", shared.ErrValidation, maxRevokeReason)
	}
	var by *shared.ID
	if uid, err := shared.IDFromString(actx.ActorID); err == nil && !uid.IsZero() {
		by = &uid
	}
	if err := s.repo.Revoke(ctx, tid, pid, by, reason, s.now().UTC()); err != nil {
		return nil, err
	}
	p, err := s.repo.GetByID(ctx, tid, pid)
	if err != nil {
		return nil, err
	}
	s.logAudit(ctx, actx, auditapp.NewSuccessEvent(auditdom.ActionContentPackRevoked, auditdom.ResourceTypeContentPack, p.ID.String()).
		WithResourceName(p.Name+"@"+p.Version).
		WithMessage(fmt.Sprintf("Content pack '%s@%s' revoked", p.Name, p.Version)).
		WithMetadata("digest", p.Digest).
		WithMetadata("reason", reason))
	return p, nil
}

// Archive returns a pack's canonical archive, checked against its digest
// (tampered storage is an error, never served).
func (s *Service) Archive(ctx context.Context, tenantID, id string) (*dom.Pack, []byte, error) {
	p, err := s.Get(ctx, tenantID, id)
	if err != nil {
		return nil, nil, err
	}
	b, err := s.repo.GetBlob(ctx, p.TenantID, p.Digest)
	if err != nil {
		return nil, nil, err
	}
	rc, _, err := s.store.Download(ctx, p.TenantID.String(), b.StorageKey)
	if err != nil {
		return nil, nil, fmt.Errorf("read content pack: %w", err)
	}
	defer rc.Close()
	data, err := io.ReadAll(io.LimitReader(rc, b.SizeBytes+1))
	if err != nil {
		return nil, nil, fmt.Errorf("read content pack: %w", err)
	}
	if _, err := dom.ReadCanonical(data, p.Digest); err != nil {
		s.logger.Error("stored content pack does not match its digest", "pack_id", p.ID.String(), "digest", p.Digest)
		return nil, nil, fmt.Errorf("%w: stored content pack is corrupt", shared.ErrInternal)
	}
	return p, data, nil
}

// SigningKey is the tenant's content-signing public key (base64) and its id,
// what the tenant's sensors pin.
func (s *Service) SigningKey(tenantID string) (string, string, error) {
	if s.signer == nil {
		return "", "", dom.ErrSigningKey
	}
	tid, err := parseTenant(tenantID)
	if err != nil {
		return "", "", err
	}
	pub, id, err := s.signer.PublicKey(tid.String())
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(pub), id, nil
}

func parseTenant(tenantID string) (shared.ID, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil || tid.IsZero() {
		return shared.ID{}, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	return tid, nil
}

// parseIDs parses ids; a malformed pack id cannot name a pack of the
// tenant, so it is not found.
func parseIDs(tenantID, id string) (shared.ID, shared.ID, error) {
	tid, err := parseTenant(tenantID)
	if err != nil {
		return shared.ID{}, shared.ID{}, err
	}
	pid, err := shared.IDFromString(id)
	if err != nil {
		return shared.ID{}, shared.ID{}, dom.ErrNotFound
	}
	return tid, pid, nil
}

func (s *Service) logAudit(ctx context.Context, actx auditapp.AuditContext, event auditapp.AuditEvent) {
	if s.audit == nil {
		return
	}
	if err := s.audit.LogEvent(ctx, actx, event); err != nil {
		s.logger.Warn("failed to record audit event", "action", string(event.Action), "error", err)
	}
}
