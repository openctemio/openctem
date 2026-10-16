package contentcatalog

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	packapp "github.com/openctemio/openctem/api/internal/app/contentpack"
	"github.com/openctemio/openctem/api/pkg/contentpkg"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	dom "github.com/openctemio/openctem/api/pkg/domain/contentcatalog"
	packdom "github.com/openctemio/openctem/api/pkg/domain/contentpack"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// TenantPacks stores an organization's content packs (*contentpack.Service).
type TenantPacks interface {
	Upload(ctx context.Context, in packapp.UploadInput, actx auditapp.AuditContext) (*packdom.Pack, error)
}

// PlatformPacks stores the instance's content packs
// (*contentpack.PlatformService).
type PlatformPacks interface {
	Upload(ctx context.Context, in packapp.PlatformInput, archive io.Reader) (*packdom.PlatformPack, error)
}

// StatementSigner signs private package statements (*contentpack.Signer).
type StatementSigner interface {
	SignTenantPayload(tenantID, payloadType string, payload []byte) ([]byte, error)
	SignPlatformPayload(payloadType string, payload []byte) ([]byte, error)
}

// TenantSlug returns an organization's slug: the namespace of its private
// packages.
type TenantSlug func(ctx context.Context, tenantID shared.ID) (string, error)

// Publishing wires private publishing. Without it every publish is refused.
type Publishing struct {
	TenantPacks   TenantPacks
	PlatformPacks PlatformPacks
	Signer        StatementSigner
	Slug          TenantSlug
}

// SetPublishing enables private publishing.
func (s *Service) SetPublishing(p *Publishing) { s.publishing = p }

// ErrPublishingUnavailable: no content signing key or pack store.
var ErrPublishingUnavailable = errors.New("private content publishing is not configured on this platform")

// PublishInput is a private package: its manifest bytes and its artifact.
type PublishInput struct {
	ManifestRaw        []byte
	Artifact           []byte
	AcknowledgeSecrets bool
}

// packName is the content pack name of a package: within the pack name
// rules (64 characters), unique per id.
func packName(id, name string) string {
	sum := sha256.Sum256([]byte(id))
	return "pkg-" + name + "-" + hex.EncodeToString(sum[:4])
}

// checkPrivate validates a private package: the manifest, the artifact
// digest, a pack type (other types have no importer yet), the namespace.
func checkPrivate(in PublishInput) (*contentpkg.Manifest, error) {
	m, err := contentpkg.ParseManifest(in.ManifestRaw)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRefused, err)
	}
	if !m.Type.IsPack() {
		return nil, fmt.Errorf("%w: private packages of type %s are not supported yet (rules, templates and wordlists are)", ErrRefused, m.Type)
	}
	if err := contentpkg.CheckArtifact(in.Artifact, m.Artifact); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRefused, err)
	}
	if contentpkg.IsReservedNamespace(m.Namespace()) {
		return nil, fmt.Errorf("%w: namespace %q is reserved for first-party packages", ErrRefused, m.Namespace())
	}
	if m.Type.IsExecutable() || len(m.Permissions.Credentials) > 0 || len(m.Permissions.DataScopes) > 0 {
		return nil, fmt.Errorf("%w: a private package cannot ask for credentials or data scopes", ErrRefused)
	}
	return m, nil
}

// checkTier refuses a package whose content lints to a higher tier than it
// declares: the declared tier is what people approve.
func checkTier(m *contentpkg.Manifest, linted packdom.Tier) error {
	if linted.Rank() > packdom.Tier(m.Permissions.Tier).Rank() {
		return fmt.Errorf("%w: the content lints as %s but the manifest declares %s", ErrRefused, linted, m.Permissions.Tier)
	}
	return nil
}

func privateRow(m *contentpkg.Manifest, raw []byte, origin string, st []byte, by *shared.ID, now time.Time) *dom.Package {
	return &dom.Package{
		ID: shared.NewID(), PackageID: m.ID, Version: m.Version, Type: m.Type, Origin: origin, Title: m.Title,
		Manifest: m, ManifestRaw: raw, ManifestDigest: contentpkg.Digest(raw),
		ArtifactMediaType: m.Artifact.MediaType, ArtifactDigest: m.Artifact.Digest, ArtifactSize: m.Artifact.Size,
		Statement: st, Tier: m.Permissions.Tier, ServiceUse: m.License.ServiceUse, CreatedBy: by, CreatedAt: now,
	}
}

// PublishOrganization publishes a package to the organization only. Its
// namespace must be the organization's slug; its artifact becomes one of
// the organization's content packs (lint, credential scan, tier); the
// statement is signed with the organization's content key.
func (s *Service) PublishOrganization(ctx context.Context, tenantID shared.ID, in PublishInput, actx auditapp.AuditContext) (*dom.Package, error) {
	pub := s.publishing
	if pub == nil || pub.TenantPacks == nil || pub.Signer == nil || pub.Slug == nil {
		return nil, ErrPublishingUnavailable
	}
	m, err := checkPrivate(in)
	if err != nil {
		return nil, err
	}
	slug, err := pub.Slug(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if m.Namespace() != strings.ToLower(slug) {
		return nil, fmt.Errorf("%w: the namespace of the organization's packages is %q", ErrRefused, strings.ToLower(slug))
	}
	if err := s.idFree(ctx, tenantID, m, contentpkg.OriginOrganization); err != nil {
		return nil, err
	}
	pack, err := pub.TenantPacks.Upload(ctx, packapp.UploadInput{TenantID: tenantID.String(), Name: packName(m.ID, m.Name()),
		Version: m.Version, Kind: m.ContentKind, Archive: bytes.NewReader(in.Artifact),
		AcknowledgeSecrets: in.AcknowledgeSecrets, CreatedBy: actx.ActorID}, actx)
	if err != nil {
		return nil, err
	}
	if err := checkTier(m, pack.Tier); err != nil {
		return nil, err
	}
	now := s.now().UTC()
	st := contentpkg.NewStatement(m, in.ManifestRaw, contentpkg.OriginOrganization, now)
	st.Publisher = contentpkg.Publisher{}
	payload, err := json.Marshal(st)
	if err != nil {
		return nil, err
	}
	env, err := pub.Signer.SignTenantPayload(tenantID.String(), contentpkg.StatementPayloadType, payload)
	if err != nil {
		return nil, err
	}
	p := privateRow(m, in.ManifestRaw, contentpkg.OriginOrganization, env, actorID(actx), now)
	p.TenantID, p.ContentPackID = &tenantID, &pack.ID
	if err := s.repo.CreatePrivate(ctx, p); err != nil {
		return nil, err
	}
	s.logAudit(ctx, actx, s.event(auditdom.ActionContentPackagePublished, m.ID, p).
		WithMessage(fmt.Sprintf("Published private content package %s@%s", m.ID, m.Version)).
		WithMetadata("pack_digest", pack.Digest).WithMetadata("tier", string(pack.Tier)).
		WithMetadata("acknowledge_secrets", in.AcknowledgeSecrets))
	return p, nil
}

// PublishInstance publishes a package to every organization of this
// instance (a platform super administrator; the admin route writes the
// audit row). Its artifact becomes a platform content pack, refused when
// lint leaves any file out; the statement is signed with the platform
// content key.
func (s *Service) PublishInstance(ctx context.Context, in PublishInput, actor *shared.ID) (*dom.Package, error) {
	pub := s.publishing
	if pub == nil || pub.PlatformPacks == nil || pub.Signer == nil {
		return nil, ErrPublishingUnavailable
	}
	m, err := checkPrivate(in)
	if err != nil {
		return nil, err
	}
	pack, err := pub.PlatformPacks.Upload(ctx, packapp.PlatformInput{Name: packName(m.ID, m.Name()), Version: m.Version,
		Kind: m.ContentKind, AcknowledgeSecrets: in.AcknowledgeSecrets}, bytes.NewReader(in.Artifact))
	if err != nil {
		return nil, err
	}
	if pack.Lint.Excluded > 0 {
		return nil, fmt.Errorf("%w: lint left %d files out; fix them and publish a new version", ErrRefused, pack.Lint.Excluded)
	}
	if err := checkTier(m, pack.Tier); err != nil {
		return nil, err
	}
	now := s.now().UTC()
	st := contentpkg.NewStatement(m, in.ManifestRaw, contentpkg.OriginInstance, now)
	st.Publisher = contentpkg.Publisher{}
	payload, err := json.Marshal(st)
	if err != nil {
		return nil, err
	}
	env, err := pub.Signer.SignPlatformPayload(contentpkg.StatementPayloadType, payload)
	if err != nil {
		return nil, err
	}
	p := privateRow(m, in.ManifestRaw, contentpkg.OriginInstance, env, actor, now)
	p.PlatformPackID = &pack.ID
	if err := s.repo.CreatePrivate(ctx, p); err != nil {
		return nil, err
	}
	return p, nil
}

// RevokeOrganization revokes one of the organization's private versions
// and every installation of it.
func (s *Service) RevokeOrganization(ctx context.Context, tenantID shared.ID, packageID, version, reason string, actx auditapp.AuditContext) (*dom.Package, error) {
	reason = strings.TrimSpace(reason)
	if reason == "" || len(reason) > maxNote {
		return nil, fmt.Errorf("%w: a reason of 1 to %d characters is required", shared.ErrValidation, maxNote)
	}
	p, err := s.repo.RevokePrivate(ctx, &tenantID, packageID, version, reason, s.now().UTC())
	if err != nil {
		return nil, err
	}
	s.logAudit(ctx, actx, s.event(auditdom.ActionContentPackageRevoked, packageID, p).
		WithMessage(fmt.Sprintf("Revoked private content package %s@%s", packageID, version)).
		WithMetadata("reason", reason))
	return p, nil
}

// RevokeInstance revokes an instance private version (the admin route
// writes the audit row).
func (s *Service) RevokeInstance(ctx context.Context, packageID, version, reason string) (*dom.Package, error) {
	reason = strings.TrimSpace(reason)
	if reason == "" || len(reason) > maxNote {
		return nil, fmt.Errorf("%w: a reason of 1 to %d characters is required", shared.ErrValidation, maxNote)
	}
	return s.repo.RevokePrivate(ctx, nil, packageID, version, reason, s.now().UTC())
}

// idFree refuses, before anything is stored, an id that another origin
// uses in the organization's view or a version that exists.
func (s *Service) idFree(ctx context.Context, tenantID shared.ID, m *contentpkg.Manifest, origin string) error {
	vs, err := s.repo.ListVersions(ctx, tenantID, m.ID)
	if err != nil {
		return err
	}
	for _, v := range vs {
		if v.Origin != origin {
			return dom.ErrIDTaken
		}
		if v.Version == m.Version {
			return dom.ErrVersionConflict
		}
	}
	return nil
}
