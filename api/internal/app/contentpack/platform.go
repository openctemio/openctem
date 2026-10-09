package contentpack

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	dom "github.com/openctemio/openctem/api/pkg/domain/contentpack"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/httpsec"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// platformNamespace is the storage namespace of platform packs. It is not a
// tenant id, so erasing an organization's storage can never reach it.
const platformNamespace = "platform-content"

// platformIngestTimeout bounds one platform ingest (fetch, unpack, lint,
// sign): an upstream release is large.
const platformIngestTimeout = 5 * time.Minute

// PlatformService manages the platform content packs (RFC-061 §3.2): the
// packs platform administrators ingest, from an upload or from an upstream
// release fetched by URL with a required digest, and the stable and canary
// channels that name one pack each. Writes are audited by the admin route
// layer. One ingest runs at a time.
type PlatformService struct {
	repo   dom.PlatformRepository
	store  Storage
	signer *dom.Signer
	logger *logger.Logger
	now    func() time.Time
	limits dom.Limits
	ingest chan struct{}
	// fetch opens an https URL through the SSRF guard (replaced in tests).
	fetch func(ctx context.Context, rawURL string) (io.ReadCloser, error)
}

// NewPlatformService creates the service; signer nil refuses every ingest.
func NewPlatformService(repo dom.PlatformRepository, store Storage, signer *dom.Signer, log *logger.Logger) *PlatformService {
	return &PlatformService{
		repo: repo, store: store, signer: signer,
		logger: log.With("service", "platform_content_pack"),
		now:    time.Now,
		limits: dom.PlatformLimits,
		ingest: make(chan struct{}, 1),
		fetch:  safeFetch,
	}
}

// Limits are the archive limits of a platform pack.
func (s *PlatformService) Limits() dom.Limits { return s.limits }

// safeFetch GETs an https URL through httpsec: public addresses only (the
// check is at dial time, so a redirect or a DNS change cannot reach a private
// one).
func safeFetch(ctx context.Context, rawURL string) (io.ReadCloser, error) {
	if _, err := httpsec.ValidateURL(rawURL); err != nil {
		return nil, fmt.Errorf("%w: %v", shared.ErrValidation, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid url", shared.ErrValidation)
	}
	req.Header.Set("User-Agent", "openctem-content-ingest/1")
	resp, err := httpsec.SafeHTTPClient(platformIngestTimeout).Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: fetch failed: %v", shared.ErrValidation, err)
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("%w: fetch answered %d", shared.ErrValidation, resp.StatusCode)
	}
	return resp.Body, nil
}

// PlatformInput is a platform pack to ingest. AcknowledgeSecrets as for a
// tenant upload.
type PlatformInput struct {
	Name, Version, Kind string
	AcknowledgeSecrets  bool
}

// Upload ingests an uploaded archive as a platform pack.
func (s *PlatformService) Upload(ctx context.Context, in PlatformInput, archive io.Reader) (*dom.PlatformPack, error) {
	if err := s.check(in); err != nil {
		return nil, err
	}
	return s.ingestArchive(ctx, in, archive, dom.SourceUpload, "", "")
}

// Import fetches an upstream release over https and ingests it. digest
// (sha256:<hex>) is required and checked against the fetched bytes before
// anything is parsed: a changed release, or one tampered with in transit,
// is refused.
func (s *PlatformService) Import(ctx context.Context, in PlatformInput, rawURL, digest string) (*dom.PlatformPack, error) {
	if err := s.check(in); err != nil {
		return nil, err
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || len(rawURL) > 2048 {
		return nil, fmt.Errorf("%w: url must be an https URL without credentials", shared.ErrValidation)
	}
	if err := dom.ValidateDigest(digest); err != nil {
		return nil, fmt.Errorf("%w: digest must be sha256:<64 hex> of the file at the url", shared.ErrValidation)
	}
	if err := s.acquire(ctx); err != nil {
		return nil, err
	}
	defer s.release()
	ictx, cancel := context.WithTimeout(ctx, platformIngestTimeout)
	defer cancel()
	body, err := s.fetch(ictx, rawURL)
	if err != nil {
		return nil, err
	}
	defer body.Close()
	data, err := io.ReadAll(io.LimitReader(body, s.limits.MaxUpload+1))
	if err != nil {
		return nil, fmt.Errorf("%w: fetch failed: %v", shared.ErrValidation, err)
	}
	if int64(len(data)) > s.limits.MaxUpload {
		return nil, fmt.Errorf("%w: the file is larger than %d bytes", shared.ErrValidation, s.limits.MaxUpload)
	}
	sum := sha256.Sum256(data)
	if got := "sha256:" + hex.EncodeToString(sum[:]); got != digest {
		return nil, shared.NewDomainError("CONTENT_DIGEST_MISMATCH",
			fmt.Sprintf("the file at the url has digest %s, not %s", got, digest), shared.ErrValidation)
	}
	return s.ingestLocked(ictx, in, bytes.NewReader(data), dom.SourceHTTPS, rawURL, digest)
}

func (s *PlatformService) check(in PlatformInput) error {
	if err := errors.Join(dom.ValidateName(in.Name), dom.ValidateVersion(in.Version), dom.ValidateKind(in.Kind)); err != nil {
		return err
	}
	if s.signer == nil {
		return dom.ErrSigningKey
	}
	return nil
}

func (s *PlatformService) acquire(ctx context.Context) error {
	select {
	case s.ingest <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *PlatformService) release() { <-s.ingest }

func (s *PlatformService) ingestArchive(ctx context.Context, in PlatformInput, r io.Reader, src dom.Source, ref, srcDigest string) (*dom.PlatformPack, error) {
	if err := s.acquire(ctx); err != nil {
		return nil, err
	}
	defer s.release()
	ictx, cancel := context.WithTimeout(ctx, platformIngestTimeout)
	defer cancel()
	return s.ingestLocked(ictx, in, r, src, ref, srcDigest)
}

// ingestLocked canonicalises, lints (leaving out the files that fail),
// signs with the platform key and stores the pack.
func (s *PlatformService) ingestLocked(ctx context.Context, in PlatformInput, r io.Reader, src dom.Source, ref, srcDigest string) (*dom.PlatformPack, error) {
	arc, err := dom.Canonicalize(r, s.limits)
	if err != nil {
		return nil, err
	}
	rep, excluded := LintExcluding(ctx, in.Kind, arc.Files)
	if len(rep.Errors) > 0 {
		return nil, lintError("CONTENT_LINT_FAILED", dom.ErrLintFailed, rep)
	}
	if len(rep.Secrets) > 0 {
		if !in.AcknowledgeSecrets {
			return nil, lintError("CONTENT_SECRETS_FOUND", dom.ErrSecretsFound, rep)
		}
		rep.SecretsAcknowledged = true
	}
	if arc, err = arc.Without(excluded); err != nil {
		return nil, err
	}
	blob, err := s.storeBlob(ctx, arc)
	if err != nil {
		return nil, err
	}
	now := s.now().UTC()
	p := &dom.PlatformPack{Pack: dom.Pack{
		ID: shared.NewID(), Name: in.Name, Version: in.Version, Kind: in.Kind,
		Digest: arc.Digest, SizeBytes: blob.SizeBytes, FileCount: blob.FileCount,
		Tier: rep.Tier, Status: dom.StatusActive, Source: src, SourceRef: ref, Lint: rep, CreatedAt: now,
	}, SourceDigest: srcDigest}
	p.Signature, err = s.signer.SignPlatform(dom.Statement{
		PackID: p.ID.String(), Name: p.Name, Version: p.Version, Content: p.Kind,
		Digest: p.Digest, Size: p.SizeBytes, Files: p.FileCount, Tier: p.Tier, CreatedAt: now,
	})
	if err != nil {
		return nil, fmt.Errorf("sign content pack: %w", err)
	}
	if err := s.repo.Create(ctx, p); err != nil {
		return nil, err
	}
	s.logger.Info("platform content pack ingested", "pack_id", p.ID.String(), "name", p.Name, "version", p.Version,
		"digest", p.Digest, "tier", string(p.Tier), "files", p.FileCount, "excluded", rep.Excluded)
	return p, nil
}

func (s *PlatformService) storeBlob(ctx context.Context, arc *dom.Archive) (*dom.Blob, error) {
	b, err := s.repo.GetBlob(ctx, arc.Digest)
	if err == nil {
		return b, nil
	}
	if !errors.Is(err, dom.ErrNotFound) {
		return nil, err
	}
	name := strings.TrimPrefix(arc.Digest, "sha256:") + ".tar"
	key, err := s.store.Upload(ctx, platformNamespace, name, "application/x-tar", bytes.NewReader(arc.Canonical))
	if err != nil {
		return nil, fmt.Errorf("store content pack: %w", err)
	}
	b = &dom.Blob{Digest: arc.Digest, SizeBytes: arc.Size(), FileCount: len(arc.Files), StorageKey: key, CreatedAt: s.now().UTC()}
	created, err := s.repo.CreateBlob(ctx, b)
	if err != nil || !created {
		if derr := s.store.Delete(ctx, platformNamespace, key); derr != nil {
			s.logger.Warn("failed to delete an unused content pack object", "error", derr)
		}
		if err != nil {
			return nil, err
		}
		return s.repo.GetBlob(ctx, arc.Digest)
	}
	return b, nil
}

// Get returns a platform pack.
func (s *PlatformService) Get(ctx context.Context, id string) (*dom.PlatformPack, error) {
	pid, err := shared.IDFromString(id)
	if err != nil {
		return nil, dom.ErrNotFound
	}
	return s.repo.GetByID(ctx, pid)
}

// List returns a page of platform packs and the total.
func (s *PlatformService) List(ctx context.Context, f dom.Filter, limit, offset int) ([]*dom.PlatformPack, int, error) {
	switch f.Status {
	case "", dom.StatusActive, dom.StatusRevoked:
	default:
		return nil, 0, fmt.Errorf("%w: status must be active or revoked", shared.ErrValidation)
	}
	if limit <= 0 || limit > maxListLimit {
		limit = maxListLimit
	}
	return s.repo.List(ctx, f, limit, max(offset, 0))
}

// Revoke revokes a platform pack. Every channel naming it moves to the
// newest older active pack of the name (removed when there is none); the
// returned channels are the name's channels afterwards.
func (s *PlatformService) Revoke(ctx context.Context, id, reason string) (*dom.PlatformPack, []dom.ChannelPointer, error) {
	pid, err := shared.IDFromString(id)
	if err != nil {
		return nil, nil, dom.ErrNotFound
	}
	reason = strings.TrimSpace(reason)
	if reason == "" || len(reason) > maxRevokeReason {
		return nil, nil, fmt.Errorf("%w: a reason of 1 to %d characters is required", shared.ErrValidation, maxRevokeReason)
	}
	channels, err := s.repo.Revoke(ctx, pid, reason, s.now().UTC())
	if err != nil {
		return nil, nil, err
	}
	p, err := s.repo.GetByID(ctx, pid)
	if err != nil {
		return nil, nil, err
	}
	s.logger.Warn("platform content pack revoked", "pack_id", p.ID.String(), "name", p.Name, "version", p.Version, "digest", p.Digest)
	return p, channels, nil
}

// MoveChannel points channel of a pack's name at that (active) pack.
func (s *PlatformService) MoveChannel(ctx context.Context, id string, channel dom.Channel) (*dom.ChannelPointer, error) {
	if err := dom.ValidateChannel(channel); err != nil {
		return nil, err
	}
	pid, err := shared.IDFromString(id)
	if err != nil {
		return nil, dom.ErrNotFound
	}
	return s.repo.SetChannel(ctx, pid, channel, s.now().UTC())
}

// Channels lists every channel.
func (s *PlatformService) Channels(ctx context.Context) ([]dom.ChannelPointer, error) {
	return s.repo.Channels(ctx)
}

// Archive returns a platform pack's canonical archive, checked against its
// digest.
func (s *PlatformService) Archive(ctx context.Context, id string) (*dom.PlatformPack, []byte, error) {
	p, err := s.Get(ctx, id)
	if err != nil {
		return nil, nil, err
	}
	b, err := s.repo.GetBlob(ctx, p.Digest)
	if err != nil {
		return nil, nil, err
	}
	rc, _, err := s.store.Download(ctx, platformNamespace, b.StorageKey)
	if err != nil {
		return nil, nil, fmt.Errorf("read content pack: %w", err)
	}
	defer rc.Close()
	data, err := io.ReadAll(io.LimitReader(rc, b.SizeBytes+1))
	if err != nil {
		return nil, nil, fmt.Errorf("read content pack: %w", err)
	}
	if _, err := dom.ReadPlatformCanonical(data, p.Digest); err != nil {
		s.logger.Error("stored platform content pack does not match its digest", "pack_id", p.ID.String())
		return nil, nil, fmt.Errorf("%w: stored content pack is corrupt", shared.ErrInternal)
	}
	return p, data, nil
}

// SigningKey is the platform content-signing public key (base64) and id.
func (s *PlatformService) SigningKey() (string, string, error) {
	if s.signer == nil {
		return "", "", dom.ErrSigningKey
	}
	pub, id, err := s.signer.PlatformPublicKey()
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(pub), id, nil
}
