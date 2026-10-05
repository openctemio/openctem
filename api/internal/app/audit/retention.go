package audit

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Audit retention: checkpoint-and-prune (docs/architecture/audit-hash-chain.md,
// "Retention"). The oldest contiguous prefix of each chain past the retention
// window is written to a gzip JSONL archive, the chain head it leaves behind
// is recorded as an anchor, and the prefix is deleted in the same transaction
// as the anchor insert. Verification, classification and rebaseline start
// from the newest anchor, so the remaining chain still verifies end to end.

// ErrNoAuditArchiveDir means retention is configured without an archive
// location. Nothing is deleted without an archive (fail safe).
var ErrNoAuditArchiveDir = errors.New("audit retention needs AUDIT_ARCHIVE_DIR; nothing was pruned")

// RetentionConfig configures one retention run.
type RetentionConfig struct {
	// RetentionDays below auditdom.MinAuditRetentionDays is raised to it.
	RetentionDays int
	// ArchiveDir receives <tenant>/audit-<first>-<last>-<time>.jsonl.gz.
	ArchiveDir string
	// BatchSize is the number of entries pruned per transaction (default 1000).
	BatchSize int
	// Now is the clock (tests); zero means time.Now.
	Now func() time.Time
}

// RetentionResult summarizes one run.
type RetentionResult struct {
	Chains   int
	Pruned   int
	Archives []string
}

// archiveLine is one JSONL line: the chain entry and the audit row as stored.
type archiveLine struct {
	TenantID      string          `json:"tenant_id"`
	AuditLogID    string          `json:"audit_log_id"`
	ChainPosition int64           `json:"chain_position"`
	PrevHash      string          `json:"prev_hash"`
	Hash          string          `json:"hash"`
	ChainedAt     time.Time       `json:"chained_at"`
	Row           json.RawMessage `json:"row"`
}

// EffectiveRetentionDays applies the platform minimum.
func EffectiveRetentionDays(days int) int {
	if days < auditdom.MinAuditRetentionDays {
		return auditdom.MinAuditRetentionDays
	}
	return days
}

// PruneExpiredChains prunes every chain's entries older than the retention
// window. A chain that changed mid-run (ErrChainPruneConflict) is skipped and
// retried on the next run; its archive file is removed.
func (s *AuditService) PruneExpiredChains(ctx context.Context, cfg RetentionConfig) (RetentionResult, error) {
	var res RetentionResult
	repo, ok := s.auditRepo.(auditdom.ChainRetentionRepository)
	if !ok {
		return res, nil
	}
	if cfg.ArchiveDir == "" {
		return res, ErrNoAuditArchiveDir
	}
	tenants, err := repo.ChainTenantsWithEntriesBefore(ctx, cfg.cutoff())
	if err != nil {
		return res, err
	}
	for _, tid := range tenants {
		res.Chains++
		n, archives, err := s.PruneChain(ctx, tid, cfg)
		res.Pruned += n
		res.Archives = append(res.Archives, archives...)
		if err != nil {
			return res, err
		}
	}
	return res, nil
}

// PruneChain prunes one chain (tenant id, or auditdom.SystemChainTenantID)
// in batches and returns the number of entries pruned and the archives
// written.
func (s *AuditService) PruneChain(ctx context.Context, tenantID shared.ID, cfg RetentionConfig) (int, []string, error) {
	repo, ok := s.auditRepo.(auditdom.ChainRetentionRepository)
	if !ok {
		return 0, nil, nil
	}
	if cfg.ArchiveDir == "" {
		return 0, nil, ErrNoAuditArchiveDir
	}
	batch := cfg.BatchSize
	if batch <= 0 {
		batch = 1000
	}
	before := cfg.cutoff()
	total := 0
	var archives []string
	for {
		if err := ctx.Err(); err != nil {
			return total, archives, err
		}
		n, path, err := s.pruneChainBatch(ctx, repo, tenantID, before, batch, cfg.ArchiveDir, cfg.clock())
		if err != nil {
			return total, archives, fmt.Errorf("prune chain %s: %w", tenantID, err)
		}
		if n == 0 {
			return total, archives, nil
		}
		total += n
		archives = append(archives, path)
		if n < batch {
			return total, archives, nil
		}
	}
}

func (c RetentionConfig) clock() func() time.Time {
	if c.Now != nil {
		return c.Now
	}
	return time.Now
}

// cutoff is the moment before which entries are pruned.
func (c RetentionConfig) cutoff() time.Time {
	return c.clock()().AddDate(0, 0, -EffectiveRetentionDays(c.RetentionDays))
}

func (s *AuditService) pruneChainBatch(ctx context.Context, repo auditdom.ChainRetentionRepository, tenantID shared.ID,
	before time.Time, batch int, dir string, now func() time.Time,
) (int, string, error) {
	entries, err := repo.ChainPrefixOlderThan(ctx, tenantID, before, batch)
	if err != nil || len(entries) == 0 {
		return 0, "", err
	}
	first, last := entries[0], entries[len(entries)-1]
	path := filepath.Join(dir, tenantID.String(),
		fmt.Sprintf("audit-%020d-%020d-%s.jsonl.gz", first.Entry.ChainPosition, last.Entry.ChainPosition, now().UTC().Format("20060102T150405Z")))
	sum, err := writeAuditArchive(path, tenantID, entries)
	if err != nil {
		return 0, "", err
	}

	anchor := auditdom.ChainAnchor{
		TenantID:          tenantID,
		AnchorHash:        last.Entry.Hash,
		LastChainPosition: last.Entry.ChainPosition,
		PrunedCount:       len(entries),
		OldestLoggedAt:    first.LoggedAt,
		NewestLoggedAt:    first.LoggedAt,
		ArchivePath:       path,
		ArchiveSHA256:     sum,
	}
	ids := make([]shared.ID, len(entries))
	for i, e := range entries {
		ids[i] = e.Entry.AuditLogID
		if e.LoggedAt.Before(anchor.OldestLoggedAt) {
			anchor.OldestLoggedAt = e.LoggedAt
		}
		if e.LoggedAt.After(anchor.NewestLoggedAt) {
			anchor.NewestLoggedAt = e.LoggedAt
		}
	}
	if err := repo.PruneChainPrefix(ctx, anchor, ids); err != nil {
		_ = os.Remove(path)
		if errors.Is(err, auditdom.ErrChainPruneConflict) {
			s.logger.Warn("audit chain changed while pruning; retrying next run", "tenant_id", tenantID.String())
			return 0, "", nil
		}
		return 0, "", err
	}
	s.logger.Info("audit chain pruned",
		"tenant_id", tenantID.String(), "pruned", len(entries),
		"last_chain_position", anchor.LastChainPosition, "archive", path)
	return len(entries), path, nil
}

// writeAuditArchive writes the entries as gzip JSONL (0600, directory 0700),
// syncs the file to disk and returns the SHA-256 of the file bytes.
func writeAuditArchive(path string, tenantID shared.ID, entries []auditdom.PrunableEntry) (string, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", fmt.Errorf("create archive dir: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", fmt.Errorf("create archive: %w", err)
	}
	ok := false
	defer func() {
		if !ok {
			_ = f.Close()
			_ = os.Remove(path)
		}
	}()
	h := sha256.New()
	zw := gzip.NewWriter(io.MultiWriter(f, h))
	enc := json.NewEncoder(zw)
	for _, e := range entries {
		if err := enc.Encode(archiveLine{
			TenantID:      tenantID.String(),
			AuditLogID:    e.Entry.AuditLogID.String(),
			ChainPosition: e.Entry.ChainPosition,
			PrevHash:      e.Entry.PrevHash,
			Hash:          e.Entry.Hash,
			ChainedAt:     e.Entry.CreatedAt,
			Row:           e.Row,
		}); err != nil {
			return "", fmt.Errorf("write archive: %w", err)
		}
	}
	if err := zw.Close(); err != nil {
		return "", fmt.Errorf("close archive: %w", err)
	}
	if err := f.Sync(); err != nil {
		return "", fmt.Errorf("sync archive: %w", err)
	}
	if err := f.Close(); err != nil {
		return "", fmt.Errorf("close archive: %w", err)
	}
	ok = true
	return hex.EncodeToString(h.Sum(nil)), nil
}
