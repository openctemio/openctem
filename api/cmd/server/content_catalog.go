package main

// The content catalog (docs/rfcs/RFC-099-content-packages.md): trusted
// roots, the publisher verifier, and an admin audit row whenever an
// operator changes the trust anchors through the environment.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"time"

	catalogapp "github.com/openctemio/openctem/api/internal/app/contentcatalog"
	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/internal/versions"
	"github.com/openctemio/openctem/api/pkg/contentpkg"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/contentcatalog"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// AdminActionContentTrustOverride records that the operator added catalog
// roots or replaced the Sigstore trusted root at startup.
const AdminActionContentTrustOverride = "content_catalog.trust_override"

func initContentCatalog(cfg *config.Config, repo contentcatalog.Repository, audit catalogapp.AuditLogger,
	adminAudit admin.AuditLogRepository, log *logger.Logger) *catalogapp.Service {
	roots := append([]string(nil), contentpkg.PinnedRoots...)
	var extra []string
	for _, r := range cfg.Encryption.ContentTrustRootKeyIDs {
		if r = strings.TrimSpace(r); r != "" {
			extra = append(extra, r)
		}
	}
	roots = append(roots, extra...)
	path := cfg.Encryption.ContentSigstoreTrustedRoot
	verifier, err := contentpkg.NewSigstoreVerifier(path)
	if err != nil {
		// Fail closed: without a verifier every package with a publisher
		// signature is refused.
		log.Error("content catalog: the Sigstore trusted root does not load; imports are refused", "error", err)
		verifier = nil
	}
	if len(extra) > 0 || path != "" {
		recordTrustOverride(adminAudit, extra, path, log)
	}
	if len(roots) == 0 {
		log.Warn("content catalog: no catalog root is trusted; bundle imports are refused until one is configured")
	}
	var pv contentpkg.PublisherVerifier
	if verifier != nil {
		pv = verifier
	}
	return catalogapp.NewService(repo, roots, pv, versions.PlatformRelease, audit, log)
}

// recordTrustOverride logs and audits (high) an operator change of the
// catalog trust anchors: extra roots and a replaced Sigstore trusted root,
// named by its SHA-256.
func recordTrustOverride(adminAudit admin.AuditLogRepository, roots []string, path string, log *logger.Logger) {
	body := map[string]any{"extra_roots": roots}
	if path != "" {
		body["sigstore_trusted_root"] = path
		if b, err := os.ReadFile(path); err == nil { // #nosec G304 -- operator-configured trust file
			sum := sha256.Sum256(b)
			body["sigstore_trusted_root_sha256"] = hex.EncodeToString(sum[:])
		}
	}
	log.Warn("content catalog: trust anchors overridden by the environment", "extra_roots", roots, "sigstore_trusted_root", path)
	if adminAudit == nil {
		return
	}
	entry := admin.NewAuditLogBuilder(nil, AdminActionContentTrustOverride).
		Resource("content_catalog", nil, "instance").
		Request("STARTUP", "CONTENT_TRUST_ROOT_KEY_IDS,CONTENT_SIGSTORE_TRUSTED_ROOT", body).
		High()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := adminAudit.Create(ctx, entry.Build()); err != nil {
		log.Error("write admin audit for the content trust override", "error", err)
	}
}
