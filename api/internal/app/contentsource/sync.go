package contentsource

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/contentpack"
	"github.com/openctemio/openctem/api/internal/infra/fetchers"
	"github.com/openctemio/openctem/api/internal/metrics"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	cpdom "github.com/openctemio/openctem/api/pkg/domain/contentpack"
	dom "github.com/openctemio/openctem/api/pkg/domain/contentsource"
	"github.com/openctemio/openctem/api/pkg/domain/limits"
	moduledom "github.com/openctemio/openctem/api/pkg/domain/module"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Sync bounds.
const (
	// syncTimeout bounds one sync: fetch, lint, sign and store.
	syncTimeout = 5 * time.Minute
	// lintTimeout bounds the lint of one snapshot.
	lintTimeout = 60 * time.Second
	// claimBatch is how many sources one worker run syncs, one claim at a
	// time.
	claimBatch = 5
	// claimLease outlives one sync (syncTimeout bounds it) with a wide
	// margin, so a crashed worker's claim expires but a live sync's does not.
	claimLease = 3 * syncTimeout
	// collectAfter keeps superseded and rejected snapshots this long.
	collectAfter = 24 * time.Hour
	collectBatch = 100
)

// Report is what a sync or a Test found.
type Report struct {
	Commit    string             `json:"commit"`
	Digest    string             `json:"digest"`
	Files     int                `json:"files"`
	SizeBytes int64              `json:"size_bytes"`
	Rules     int                `json:"rules"`
	Tier      cpdom.Tier         `json:"tier"`
	License   string             `json:"license,omitempty"`
	Lint      cpdom.LintReport   `json:"lint"`
	Skipped   []fetchers.Skipped `json:"skipped,omitempty"`
	Unchanged bool               `json:"unchanged,omitempty"`
	Snapshot  *dom.Snapshot      `json:"-"`
}

// SyncError is a sync that did not produce a snapshot, with its report when
// lint refused the content.
type SyncError struct {
	Code    string
	Message string
	Report  *Report
}

func (e *SyncError) Error() string { return e.Message }

// Unwrap makes a refused sync a validation error.
func (e *SyncError) Unwrap() error { return shared.ErrValidation }

func syncErr(code, format string, args ...any) *SyncError {
	return &SyncError{Code: code, Message: fmt.Sprintf(format, args...)}
}

// fetchAndBuild fetches the source at its ref and builds the canonical,
// linted archive. It persists nothing.
func (s *Service) fetchAndBuild(ctx context.Context, src *dom.Source, token string) (*Report, *cpdom.Archive, []dom.Rule, bool, error) {
	if src.Origin != dom.OriginGit {
		return nil, nil, nil, false, dom.ErrUnsupportedOrigin
	}
	tenantID := src.TenantID
	private, err := s.private(src.URL)
	if err != nil {
		return nil, nil, nil, false, syncErr("HOST_REFUSED", "%s", err.Error())
	}
	// SECURITY: private-range access is decided per organization, and again
	// per connection at dial time (PrivateOK), so a host that resolves
	// elsewhere when the connection is made is still judged by the feature.
	privateOK := tenantID != nil && s.featureUsable(ctx, *tenantID, limits.FeatureContentPrivateGit)
	if private && !privateOK {
		return nil, nil, nil, false, &limits.ErrFeatureDenied{Feature: limits.FeatureContentPrivateGit}
	}
	lim := cpdom.DefaultLimits
	// The archive is built here from at most MaxTotal bytes of files; allow
	// for the tar headers.
	lim.MaxUpload = lim.MaxTotal + int64(lim.MaxFiles)*1536 + 1<<20
	snap, err := s.fetch(ctx, fetchers.GitRequest{
		URL: src.URL, Ref: src.Ref, Path: src.Path, Username: src.AuthUsername, Token: token,
		CABundle: []byte(src.CAPEM), PrivateOK: privateOK, MaxFiles: lim.MaxFiles, MaxFile: lim.MaxFileSize, MaxTotal: lim.MaxTotal,
	})
	if errors.Is(err, fetchers.ErrLowDisk) {
		return nil, nil, nil, false, dom.ErrLowDisk
	}
	if err != nil {
		return nil, nil, nil, false, syncErr("FETCH_FAILED", "fetch failed: %s", err.Error())
	}
	if len(snap.Files) == 0 {
		return nil, nil, nil, false, syncErr("EMPTY", "the ref has no files under the path")
	}
	tarball, err := tarOf(snap.Files)
	if err != nil {
		return nil, nil, nil, false, err
	}
	arc, err := cpdom.Canonicalize(bytes.NewReader(tarball), lim)
	if err != nil {
		return nil, nil, nil, false, syncErr("ARCHIVE_REFUSED", "%s", err.Error())
	}
	lctx, cancel := context.WithTimeout(ctx, lintTimeout)
	defer cancel()
	lint := contentpack.Lint(lctx, string(src.Kind), arc.Files)
	rules, dup := dom.ExtractRules(src.Kind, arc.Files)
	rep := &Report{
		Commit: snap.Commit, Digest: arc.Digest, Files: len(arc.Files), SizeBytes: arc.Size(),
		Rules: len(rules), Tier: lint.Tier, License: dom.DetectLicense(snap.License), Lint: lint, Skipped: snap.Skipped,
	}
	for _, r := range rules {
		if len(r.ID) > dom.MaxRuleIDLen {
			lint.Error(r.Path, "RULE_ID_TOO_LONG", fmt.Sprintf("rule id %.40q... is longer than %d characters", r.ID, dom.MaxRuleIDLen))
		}
	}
	rep.Lint = lint
	if len(lint.Errors) > 0 {
		return rep, nil, nil, false, &SyncError{Code: "LINT_FAILED", Message: fmt.Sprintf("lint refused %d issue(s)", len(lint.Errors)), Report: rep}
	}
	if len(lint.Secrets) > 0 {
		return rep, nil, nil, false, &SyncError{Code: "SECRETS_FOUND", Message: fmt.Sprintf("the content holds %d value(s) that look like credentials", len(lint.Secrets)), Report: rep}
	}
	return rep, arc, rules, dup, nil
}

func tarOf(files []fetchers.File) ([]byte, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, f := range files {
		if err := tw.WriteHeader(&tar.Header{Name: f.Path, Mode: 0o644, Size: int64(len(f.Data)), Typeflag: tar.TypeReg}); err != nil {
			return nil, err
		}
		if _, err := tw.Write(f.Data); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// TestInput is a source configuration to try. With SourceID it starts from
// that saved source (its stored credential is used only while the host stays
// the same); without, from the fields alone.
type TestInput struct {
	SourceID *shared.ID
	Kind     string
	URL      string
	Ref      string
	Path     string
	Username string
	Token    string
	CAPEM    string
}

// Test fetches, lints and counts a source configuration without storing
// anything: what a save would sync. At most TestCallsPerHour per source.
func (s *Service) Test(ctx context.Context, a Actor, in TestInput) (*Report, error) {
	now := s.now().UTC()
	var src *dom.Source
	limitKey := "t:" + a.TenantID.String()
	if in.SourceID != nil {
		saved, err := s.ownSource(ctx, a.TenantID, *in.SourceID)
		if err != nil {
			return nil, err
		}
		limitKey = "s:" + saved.ID.String()
		cp := *saved
		src = &cp
		c := dom.GitConfig{URL: src.URL, Ref: src.Ref, Path: src.Path}
		if in.URL != "" {
			c.URL = in.URL
		}
		if in.Ref != "" {
			c.Ref = in.Ref
		}
		if in.Path != "" {
			c.Path = in.Path
		}
		if _, err := src.SetGit(c); err != nil { // a new host clears the stored credential
			return nil, err
		}
		if in.CAPEM != "" {
			if err := src.SetCAPEM(in.CAPEM); err != nil {
				return nil, err
			}
		}
	} else {
		var err error
		src, err = dom.NewTenantSource(a.TenantID, "test", "test", dom.Kind(in.Kind), dom.GitConfig{URL: in.URL, Ref: in.Ref, Path: in.Path}, a.UserID, now)
		if err != nil {
			return nil, err
		}
		if err := src.SetCAPEM(in.CAPEM); err != nil {
			return nil, err
		}
	}
	token := ""
	if in.Token != "" {
		if err := dom.ValidateToken(in.Token); err != nil {
			return nil, err
		}
		user, err := dom.ResolveUsername(in.Username, in.Token)
		if err != nil {
			return nil, err
		}
		token, src.AuthUsername = in.Token, user
	} else if src.HasCredential() {
		t, err := s.unseal(src)
		if err != nil {
			return nil, syncErr("CREDENTIAL_UNUSABLE", "%s", err.Error())
		}
		token = t
	}
	if err := s.checkHost(ctx, a.TenantID, src.URL); err != nil {
		return nil, err
	}
	releaseTenant, ok := s.tenantTests.acquire(a.TenantID)
	if !ok {
		return nil, dom.ErrFetchBusy
	}
	defer releaseTenant()
	release, ok := s.acquireFetch()
	if !ok {
		return nil, dom.ErrFetchBusy
	}
	defer release()
	if !s.testLimit.allow(limitKey, now) {
		return nil, dom.ErrRateLimited
	}
	tctx, cancel := context.WithTimeout(ctx, syncTimeout)
	defer cancel()
	rep, arc, _, _, err := s.fetchAndBuild(tctx, src, token)
	if err != nil {
		var se *SyncError
		if errors.As(err, &se) && se.Report != nil {
			return se.Report, err
		}
		return nil, err
	}
	if max, lerr := s.limitValue(ctx, a.TenantID, limits.ContentSnapshotMaxMB); lerr == nil && max != limits.Unlimited && arc.Size() > int64(max)<<20 {
		return rep, &limits.ErrLimitReached{Key: limits.ContentSnapshotMaxMB, Limit: max, Used: int(ceilMiB(arc.Size()))}
	}
	return rep, nil
}

func ceilMiB(n int64) int64 { return (n + (1 << 20) - 1) >> 20 }

// syncSource syncs one organization source: fetch, build, lint, store a
// candidate snapshot with its diff and checks, and promote it when the
// policy and checks allow. actor is nil for a scheduled sync.
func (s *Service) syncSource(ctx context.Context, src *dom.Source, actor *shared.ID) (*Report, error) {
	if src.IsPlatform() || src.TenantID == nil {
		return nil, dom.ErrPlatformReadOnly
	}
	if src.StorageMode != dom.StorageModeMirror {
		return nil, syncErr("STORAGE_MODE", "storage mode %q is not synced by the platform yet", src.StorageMode)
	}
	if _, busy := s.syncing.LoadOrStore(src.ID.String(), struct{}{}); busy {
		return nil, dom.ErrSyncInProgress
	}
	defer s.syncing.Delete(src.ID.String())
	tenantID := *src.TenantID
	ctx, cancel := context.WithTimeout(ctx, syncTimeout)
	defer cancel()

	token, err := s.unseal(src)
	if err != nil {
		return nil, syncErr("CREDENTIAL_UNUSABLE", "%s", err.Error())
	}
	rep, arc, rules, dup, err := s.fetchAndBuild(ctx, src, token)
	if err != nil {
		return rep, err
	}
	if max, err := s.limitValue(ctx, tenantID, limits.ContentSnapshotMaxMB); err != nil {
		return rep, err
	} else if max != limits.Unlimited && arc.Size() > int64(max)<<20 {
		return rep, &limits.ErrLimitReached{Key: limits.ContentSnapshotMaxMB, Limit: max, Used: int(ceilMiB(arc.Size()))}
	}

	// Unchanged content: nothing new to store.
	if existing, err := s.repo.FindSnapshotByDigestUnscoped(ctx, src.ID, arc.Digest); err == nil {
		rep.Unchanged, rep.Snapshot = true, existing
		return rep, nil
	} else if !errors.Is(err, dom.ErrSnapshotNotFound) {
		return rep, err
	}
	if err := s.checkLimit(ctx, tenantID, limits.ContentStorageMB, int(ceilMiB(arc.Size()))); err != nil {
		return rep, err
	}

	var base *dom.Snapshot
	if src.CurrentSnapshotID != nil {
		if base, err = s.repo.GetSnapshotUnscoped(ctx, *src.CurrentSnapshotID); err != nil && !errors.Is(err, dom.ErrSnapshotNotFound) {
			return rep, err
		}
	}
	pack, err := s.packs.StoreSnapshot(ctx, contentpack.SnapshotInput{
		TenantID: tenantID, Name: src.Slug,
		Version: shortSHA(rep.Commit) + "-" + strings.TrimPrefix(arc.Digest, "sha256:")[:12],
		Kind:    string(src.Kind), Archive: arc, Lint: rep.Lint,
		SourceRef: src.URL + "@" + rep.Commit, CreatedBy: actor,
	})
	if err != nil {
		return rep, err
	}
	sn := &dom.Snapshot{
		ID: shared.NewID(), SourceID: src.ID, Scope: dom.ScopeTenant, TenantID: &tenantID,
		UpstreamRevision: rep.Commit, Ref: src.Ref, Digest: arc.Digest, ContentPackID: &pack.ID,
		SizeBytes: pack.SizeBytes, FileCount: pack.FileCount, FileIndex: dom.FileIndexOf(arc.Files),
		Rules: rules, RuleCount: len(rules), Tier: rep.Lint.Tier, Lint: rep.Lint, LicenseSPDX: rep.License,
		ServiceUse: src.LicenseServiceUse && !dom.NoServiceLicenses[rep.License],
		Signature:  pack.Signature, State: dom.StateCandidate, SyncedBy: actor, ConfigAuthors: src.ConfigAuthors, ConfigAsOf: claimedAt(src), CreatedAt: s.now().UTC(),
	}
	sn.Diff = dom.ComputeDiff(base, rules, sn.Tier, sn.LicenseSPDX)
	sn.Checks, sn.ReviewRequired = dom.EvaluatePromotion(src.Policy, base, sn, dup)
	if err := s.repo.CreateSnapshot(ctx, sn); err != nil {
		// The pack has no snapshot: delete it so no unapproved content stays
		// stored (and it is never deliverable: only a current snapshot's
		// pack is).
		s.deletePack(ctx, tenantID, pack.ID, "failed sync")
		return rep, err
	}
	if err := s.repo.SupersedeCandidatesUnscoped(ctx, src.ID, sn.ID); err != nil {
		return rep, err
	}
	rep.Snapshot = sn
	s.logAudit(ctx, auditapp.AuditContext{}, &tenantID, sourceEvent(auditdom.ActionContentSourceSynced, src,
		fmt.Sprintf("Rule source '%s' synced: candidate %s (%d rules, +%d -%d ~%d)", src.Slug, shortSHA(sn.UpstreamRevision),
			sn.RuleCount, sn.Diff.AddedCount, sn.Diff.RemovedCount, sn.Diff.ChangedCount)).
		WithMetadata("snapshot_id", sn.ID.String()).
		WithMetadata("digest", sn.Digest).
		WithMetadata("commit", sn.UpstreamRevision).
		WithMetadata("tier", string(sn.Tier)).
		WithMetadata("blocked", sn.Checks.Blocked))
	if sn.Checks.AutoPromote {
		if err := s.repo.PromoteUnscoped(ctx, src.ID, sn.ID, s.now().UTC()); err != nil {
			if errors.Is(err, dom.ErrPolicyChanged) {
				sn.ReviewRequired, sn.Checks.AutoPromote = true, false
				return rep, nil
			}
			return rep, err
		}
		sn.State = dom.StatePromoted
		s.logAudit(ctx, auditapp.AuditContext{}, &tenantID, sourceEvent(auditdom.ActionContentSourcePromoted, src,
			fmt.Sprintf("Snapshot %s of rule source '%s' promoted automatically (every check passed)", shortSHA(sn.UpstreamRevision), src.Slug)).
			WithMetadata("snapshot_id", sn.ID.String()).
			WithMetadata("digest", sn.Digest).
			WithMetadata("automatic", true))
	}
	return rep, nil
}

// RunDue syncs the sources whose schedule is due or whose sync was
// requested (the sync worker's reconcile): up to claimBatch, each claimed
// on its own right before it runs, so the lease of a source never waits
// behind another sync and the claim order stays fair across organizations.
// It returns how many it synced.
func (s *Service) RunDue(ctx context.Context) (int, error) {
	n := 0
	for n < claimBatch {
		if err := ctx.Err(); err != nil {
			return n, err
		}
		// A fetch slot first: without one nothing is claimed, the due
		// sources stay due for the next run.
		release, ok := s.acquireFetch()
		if !ok {
			return n, nil
		}
		claimed, err := s.repo.ClaimDueUnscoped(ctx, s.now().UTC(), claimLease, 1)
		if err != nil || len(claimed) == 0 {
			release()
			return n, err
		}
		src := claimed[0]
		n++
		if s.moduleOff(ctx, src) {
			now := s.now().UTC()
			s.saveOutcome(ctx, src, dom.SyncOutcome{
				Status: src.LastSyncStatus, Error: src.LastSyncError, At: now,
				NextSyncAt: src.NextScheduled(now, s.jitter()), ClearRequest: true, KeepFailures: true,
			})
			release()
			continue
		}
		s.runOne(ctx, src)
		release()
	}
	return n, nil
}

// saveOutcome writes a sync's outcome under the claim the source was
// taken with.
func (s *Service) saveOutcome(ctx context.Context, src *dom.Source, out dom.SyncOutcome) {
	out.LeaseUntil, out.ClaimedAt = src.LeaseUntil, src.ClaimedAt
	if err := s.repo.SaveSyncUnscoped(ctx, src.ID, out); err != nil {
		s.logger.Error("failed to save rule source sync outcome", "source_id", src.ID.String(), "error", err)
	}
}

// moduleOff reports whether the source's organization turned the rule
// sources module off.
func (s *Service) moduleOff(ctx context.Context, src *dom.Source) bool {
	if s.modules == nil || src.TenantID == nil {
		return false
	}
	return s.modules.TenantDisabledModules(ctx, src.TenantID.String())[moduledom.ModuleTemplateSources]
}

func (s *Service) runOne(ctx context.Context, src *dom.Source) {
	rep, err := s.syncSource(ctx, src, nil)
	now := s.now().UTC()
	out := dom.SyncOutcome{At: now, NextSyncAt: src.NextScheduled(now, s.jitter()), ClearRequest: true}
	if rep != nil {
		out.Commit = rep.Commit
	}
	if err == nil {
		out.Status, out.ResetFailures = dom.SyncSuccess, true
		result := "new"
		if rep != nil && rep.Unchanged {
			result = "unchanged"
		}
		metrics.ContentSourceSyncsTotal.WithLabelValues(result).Inc()
	} else {
		metrics.ContentSourceSyncsTotal.WithLabelValues("failed").Inc()
		out.Status, out.Error = dom.SyncFailed, err.Error()
		var se *SyncError
		if errors.As(err, &se) && se.Report != nil {
			if raw, jerr := json.Marshal(se.Report.Lint); jerr == nil && len(raw) <= 190000 {
				out.Report = raw
			}
		}
		if src.LastSyncStatus != dom.SyncFailed || src.ConsecutiveFailures == 0 {
			ev := sourceEvent(auditdom.ActionContentSourceSyncFailed, src,
				fmt.Sprintf("Sync of rule source '%s' failed", src.Slug)).WithMetadata("error", truncate(err.Error(), 500))
			s.logAudit(ctx, auditapp.AuditContext{}, src.TenantID, ev)
		}
		s.logger.Warn("rule source sync failed", "source_id", src.ID.String(), "error", err)
	}
	s.saveOutcome(ctx, src, out)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// deletePack deletes a snapshot pack on a context that survives the sync's
// own cancellation. A failure leaves an orphan that is never delivered and
// that CollectGarbage removes later.
func (s *Service) deletePack(ctx context.Context, tenantID, packID shared.ID, why string) {
	dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
	defer cancel()
	if err := s.packs.DeleteSourcePack(dctx, tenantID, packID); err != nil && !errors.Is(err, cpdom.ErrNotFound) {
		s.logger.Warn("failed to delete a rule source pack", "reason", why, "pack_id", packID.String(), "error", err)
	}
}

// CollectGarbage deletes superseded and rejected snapshots older than a day
// that are neither current nor previous, and their packs (mirror storage),
// and then the orphan packs no snapshot references. Delivery never depends
// on this cleanup: a pack is delivered only while it is its source's
// current snapshot, so a pack whose delete fails stays undeliverable and is
// retried as an orphan.
func (s *Service) CollectGarbage(ctx context.Context) (int, error) {
	cutoff := s.now().UTC().Add(-collectAfter)
	list, err := s.repo.ListCollectableUnscoped(ctx, cutoff, collectBatch)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, sn := range list {
		ok, err := s.repo.DeleteSnapshotUnscoped(ctx, sn.ID)
		if err != nil {
			return n, err
		}
		if !ok {
			continue
		}
		n++
		if sn.TenantID != nil && sn.ContentPackID != nil {
			s.deletePack(ctx, *sn.TenantID, *sn.ContentPackID, "collected snapshot")
		}
	}
	orphans, err := s.repo.ListOrphanPacksUnscoped(ctx, s.now().UTC().Add(-time.Hour), collectBatch)
	if err != nil {
		return n, err
	}
	for _, o := range orphans {
		s.deletePack(ctx, o.TenantID, o.PackID, "orphan")
	}
	return n, nil
}

// claimedAt is the claim time of a claimed source, nil for one that was not
// claimed (a snapshot without it consumes no config authors when promoted).
func claimedAt(src *dom.Source) *time.Time {
	if src.ClaimedAt.IsZero() {
		return nil
	}
	t := src.ClaimedAt.UTC()
	return &t
}
