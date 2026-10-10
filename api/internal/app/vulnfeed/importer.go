// Package vulnfeed imports the signed vulnerability bundles the collector
// publishes (openctemio/vulnfeed) into the CVE corpus. The platform never
// calls a vulnerability source itself.
//
// Design: docs/rfcs/RFC-066-inventory-vulnerability-matching.md §5.5.
package vulnfeed

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/openctemio/sdk-go/pkg/transfer"
	"github.com/openctemio/sdk-go/pkg/transfer/bundle"

	"github.com/openctemio/openctem/api/pkg/domain/cvecorpus"
	"github.com/openctemio/openctem/api/pkg/domain/software"
	"github.com/openctemio/openctem/api/pkg/domain/threatintel"
	"github.com/openctemio/openctem/api/pkg/httpsec"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/vulnbundle"
)

// SourceName is the threat_intel_sync_status row of the importer.
const SourceName = "vulnfeed"

// DefaultBaseURL is where the collector publishes.
const DefaultBaseURL = "https://github.com/openctemio/vulnfeed/releases"

// Import tuning.
const (
	pageSize        = 500
	maxEmptiedShare = 0.02
	minEmptiedLimit = 500
	staleAfter      = 3 * 24 * time.Hour
)

// Config of the importer.
type Config struct {
	// RootKeyID is the pinned offline root (VULNFEED_ROOT_KEY_ID). Empty:
	// the importer does nothing.
	RootKeyID string
	// BaseURL is the release base (VULNFEED_BASE_URL); validated https.
	BaseURL string
	// BundleDir, when set (VULNFEED_BUNDLE_DIR), is read instead of the
	// network: an air-gapped platform drops a release's files there.
	BundleDir string
}

// Corpus is what the importer writes.
type Corpus interface {
	cvecorpus.Store
	CVEIDs(ctx context.Context) ([]string, error)
}

// CuratedWriter writes the curated products before a bundle names
// products, so alternate vendors resolve to them.
type CuratedWriter interface {
	EnsureCurated(ctx context.Context, products []software.Curated) error
}

// Importer verifies and applies bundles.
type Importer struct {
	cfg     Config
	corpus  Corpus
	status  threatintel.SyncStatusRepository
	catalog CuratedWriter
	http    *http.Client
	logger  *logger.Logger
	now     func() time.Time
	tmp     string
	// The removal guard (maxEmptiedShare, minEmptiedLimit; tests lower it).
	emptiedShare float64
	minEmptied   int

	// Chunked (v2) bundles; nil chunks: v1 only.
	chunks             ChunkStore
	transfer           Transfer
	fetchMu            sync.Mutex
	fetcher            *transfer.Fetcher
	consumerRegistered bool
}

// NewImporter creates an importer. It refuses a base URL that is not a
// public https URL.
func NewImporter(cfg Config, corpus Corpus, status threatintel.SyncStatusRepository, catalog CuratedWriter, log *logger.Logger) (*Importer, error) {
	if cfg.BaseURL == "" {
		cfg.BaseURL = DefaultBaseURL
	}
	if cfg.BundleDir == "" {
		u, err := url.Parse(cfg.BaseURL)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
			return nil, errors.New("vulnfeed: VULNFEED_BASE_URL must be an https URL without query or fragment")
		}
		if _, err := httpsec.ValidateURL(cfg.BaseURL); err != nil {
			return nil, fmt.Errorf("vulnfeed: VULNFEED_BASE_URL: %w", err)
		}
		cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	}
	return &Importer{cfg: cfg, corpus: corpus, status: status, catalog: catalog,
		http: httpsec.SafeHTTPClient(10 * time.Minute), logger: log, now: time.Now, tmp: os.TempDir(),
		emptiedShare: maxEmptiedShare, minEmptied: minEmptiedLimit}, nil
}

// Result says what a run did.
type Result struct {
	Ran      bool
	Sequence uint64
	Kind     string
	CVEs     int
	Ranges   int
}

// state is the importer's progress in the status row's metadata.
type state struct {
	Applied       uint64
	KeySetVersion uint64
}

func readState(m map[string]any) state {
	return state{Applied: toUint(m["applied_sequence"]), KeySetVersion: toUint(m["keyset_version"])}
}

func toUint(v any) uint64 {
	switch t := v.(type) {
	case float64:
		if t > 0 {
			return uint64(t)
		}
	case int:
		if t > 0 {
			return uint64(t)
		}
	case uint64:
		return t
	case string:
		n, _ := strconv.ParseUint(t, 10, 64)
		return n
	}
	return 0
}

// Run imports the newest bundle when there is one.
func (im *Importer) Run(ctx context.Context) (Result, error) {
	var res Result
	if im.cfg.RootKeyID == "" {
		return res, nil
	}
	st, err := im.status.GetBySource(ctx, SourceName)
	if err != nil {
		return res, fmt.Errorf("vulnfeed status: %w", err)
	}
	if !st.IsEnabled() {
		return res, nil
	}
	cur := readState(st.Metadata())
	if im.useV2(ctx) {
		return im.runV2(ctx, cur)
	}
	if im.chunks != nil {
		// A v2 bundle may have applied a newer sequence than the status row
		// records; the v1 reader never goes below it.
		cp, err := im.chunks.FeedCheckpoint().Load(ctx)
		if err != nil {
			return res, im.fail(ctx, err)
		}
		cur.Applied = max(cur.Applied, cp.Applied)
	}
	now := im.now()
	opt := vulnbundle.Options{PinnedRoot: im.cfg.RootKeyID, MinKeySetVer: cur.KeySetVersion, AppliedSeq: cur.Applied, Now: now}

	dir, cleanup, err := im.stage(ctx, opt)
	if errors.Is(err, vulnbundle.ErrNotNewer) {
		return res, nil
	}
	if err != nil {
		return res, im.fail(ctx, err)
	}
	defer cleanup()
	v, err := vulnbundle.VerifyDir(dir, opt)
	if err != nil {
		return res, im.fail(ctx, err)
	}
	res.Ran, res.Sequence = true, v.Latest.Sequence
	if err := im.markStarted(ctx); err != nil {
		return res, err
	}
	if err := im.catalog.EnsureCurated(ctx, software.CuratedProducts()); err != nil {
		return res, im.fail(ctx, fmt.Errorf("curated products: %w", err))
	}
	m := v.Snapshot
	res.Kind = vulnbundle.KindSnapshot
	if v.Delta != nil && cur.Applied != 0 && v.Delta.BaseSequence == cur.Applied {
		m, res.Kind = *v.Delta, vulnbundle.KindDelta
	}
	recs, err := v.Read(m)
	if err != nil {
		return res, im.fail(ctx, err)
	}
	if err := im.apply(ctx, recs.CVEs, res.Kind == vulnbundle.KindSnapshot && cur.Applied != 0, &res); err != nil {
		return res, im.fail(ctx, err)
	}
	if im.chunks != nil {
		// The checkpoint follows, so the next v2 bundle continues from here.
		if err := im.chunks.FeedCheckpoint().Save(ctx, bundle.State{Feed: FeedV2, Applied: v.Latest.Sequence, UpdatedAt: im.now()}); err != nil {
			return res, im.fail(ctx, err)
		}
	}
	return res, im.finish(ctx, summary{Sequence: v.Latest.Sequence, KeySetVersion: v.KeySet.Version, CreatedAt: v.Latest.CreatedAt,
		Kind: res.Kind, Sources: m.Sources}, res)
}

// apply writes the records page by page behind the removal guard. A
// snapshot applied over an existing corpus also withdraws the ranges of
// CVEs the snapshot no longer carries.
func (im *Importer) apply(ctx context.Context, cves []cvecorpus.CVE, replaceAll bool, res *Result) error {
	if replaceAll {
		in := make(map[string]bool, len(cves))
		for _, c := range cves {
			in[c.ID] = true
		}
		stored, err := im.corpus.CVEIDs(ctx)
		if err != nil {
			return err
		}
		for _, id := range stored {
			if !in[id] {
				cves = append(cves, cvecorpus.CVE{ID: id, Status: "Withdrawn"})
			}
		}
	}
	_, ranges, err := im.corpus.Counts(ctx)
	if err != nil {
		return err
	}
	limit := max(int(float64(ranges)*im.emptiedShare), im.minEmptied)
	emptied := 0
	for start := 0; start < len(cves); start += pageSize {
		end := start + pageSize
		if end > len(cves) {
			end = len(cves)
		}
		page := cves[start:end]
		e, err := im.corpus.EmptiedRanges(ctx, page)
		if err != nil {
			return err
		}
		if emptied+e > limit {
			return fmt.Errorf("refused: the bundle would remove %d affected ranges, over the limit of %d", emptied+e, limit)
		}
		pr, err := im.corpus.ApplyPage(ctx, page)
		if err != nil {
			return err
		}
		emptied += e
		res.CVEs += pr.Upserted
		res.Ranges += pr.RangesWritten
	}
	return nil
}

// stage puts the bundle in a local directory: the configured bundle
// directory, or a fresh temporary one filled from the release: the record
// files are fetched only after the key set, the pointer and their manifest
// verified, each capped at the size its signed manifest states.
func (im *Importer) stage(ctx context.Context, opt vulnbundle.Options) (string, func(), error) {
	if im.cfg.BundleDir != "" {
		if _, err := vulnbundle.VerifyPointer(im.cfg.BundleDir, opt); err != nil {
			return "", nil, err
		}
		return im.cfg.BundleDir, func() {}, nil
	}
	dir, err := os.MkdirTemp(im.tmp, "vulnfeed-*")
	if err != nil {
		return "", nil, err
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	latestURL := im.cfg.BaseURL + "/latest/download/"
	for _, name := range []string{vulnbundle.KeySetFile, vulnbundle.LatestFile} {
		if err := im.download(ctx, latestURL+name, filepath.Join(dir, name), vulnbundle.MaxManifestBytes); err != nil {
			cleanup()
			return "", nil, err
		}
	}
	v, err := vulnbundle.VerifyPointer(dir, opt)
	if err != nil {
		cleanup()
		return "", nil, err
	}
	tagURL := im.cfg.BaseURL + "/download/" + url.PathEscape(v.Latest.Tag) + "/"
	kinds := []string{vulnbundle.KindSnapshot}
	if v.Latest.Delta != "" {
		kinds = append(kinds, vulnbundle.KindDelta)
	}
	for _, kind := range kinds {
		name := vulnbundle.ManifestName(kind)
		if err := im.download(ctx, tagURL+name, filepath.Join(dir, name), vulnbundle.MaxManifestBytes); err != nil {
			cleanup()
			return "", nil, err
		}
		m, err := v.LoadManifest(kind)
		if err != nil {
			cleanup()
			return "", nil, err
		}
		for _, f := range m.Files {
			if err := im.download(ctx, tagURL+f.Name, filepath.Join(dir, f.Name), f.Size); err != nil {
				cleanup()
				return "", nil, err
			}
		}
	}
	return dir, cleanup, nil
}

func (im *Importer) download(ctx context.Context, rawURL, path string, max int64) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "OpenCTEM/1.0 (+https://github.com/openctemio)")
	resp, err := im.http.Do(req)
	if err != nil {
		return fmt.Errorf("vulnfeed fetch %s: %w", filepath.Base(path), err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("vulnfeed fetch %s: status %d", filepath.Base(path), resp.StatusCode)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	n, err := io.Copy(f, httpsec.NewLimitedReader(resp.Body, max+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("vulnfeed fetch %s: %w", filepath.Base(path), err)
	}
	if n > max {
		return fmt.Errorf("vulnfeed fetch %s: over %d bytes", filepath.Base(path), max)
	}
	return nil
}

func (im *Importer) markStarted(ctx context.Context) error {
	st, err := im.status.GetBySource(ctx, SourceName)
	if err != nil {
		return err
	}
	st.MarkSyncStarted()
	return im.status.Update(ctx, st)
}

func (im *Importer) finish(ctx context.Context, b summary, res Result) error {
	records, ranges, err := im.corpus.Counts(ctx)
	if err != nil {
		return im.fail(ctx, err)
	}
	st, err := im.status.GetBySource(ctx, SourceName)
	if err != nil {
		return err
	}
	meta := st.Metadata()
	meta["applied_sequence"] = max(b.Sequence, toUint(meta["applied_sequence"]))
	meta["keyset_version"] = max(b.KeySetVersion, toUint(meta["keyset_version"]))
	meta["bundle_created_at"] = b.CreatedAt.UTC().Format(time.RFC3339)
	meta["kind"] = b.Kind
	meta["records"], meta["ranges"] = records, ranges
	srcs := make([]map[string]any, 0, len(b.Sources))
	for _, s := range b.Sources {
		srcs = append(srcs, map[string]any{"name": s.Name, "as_of": s.AsOf.UTC().Format(time.RFC3339), "attribution": s.Attribution})
	}
	meta["sources"] = srcs
	meta["stale"] = im.now().Sub(b.CreatedAt) > staleAfter
	st.SetMetadata(meta)
	st.MarkSyncSuccess(res.CVEs, 0)
	if err := im.status.Update(ctx, st); err != nil {
		return err
	}
	im.logger.Info("vulnerability bundle imported", "sequence", b.Sequence, "kind", b.Kind,
		"cves", res.CVEs, "ranges_written", res.Ranges, "corpus_records", records, "corpus_ranges", ranges)
	return nil
}

func (im *Importer) fail(ctx context.Context, cause error) error {
	st, err := im.status.GetBySource(ctx, SourceName)
	if err == nil {
		st.MarkSyncFailed(cause.Error())
		err = im.status.Update(ctx, st)
	}
	if err != nil {
		im.logger.Warn("vulnfeed status not updated", "error", err)
	}
	return cause
}

// CheckStale reports a corpus whose newest bundle is older than three days
// (a freeze: someone may be withholding bundles).
func (im *Importer) CheckStale(ctx context.Context) (bool, error) {
	st, err := im.status.GetBySource(ctx, SourceName)
	if err != nil || !st.IsEnabled() {
		return false, err
	}
	created, _ := time.Parse(time.RFC3339, fmt.Sprint(st.Metadata()["bundle_created_at"]))
	return created.IsZero() || im.now().Sub(created) > staleAfter, nil
}

// SetClockForTest replaces the importer's clock (tests that import a fixed
// bundle need its own time).
func SetClockForTest(im *Importer, now func() time.Time) { im.now = now }

// SetRemovalLimitForTest replaces the removal guard (tests that exercise
// it with a small corpus).
func SetRemovalLimitForTest(im *Importer, share float64, minimum int) {
	im.emptiedShare, im.minEmptied = share, minimum
}
