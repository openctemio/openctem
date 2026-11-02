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

	"github.com/openctemio/ctis/transfer"
	"github.com/openctemio/ctis/transfer/bundle"

	"github.com/openctemio/openctem/api/internal/app/feedstatus"
	"github.com/openctemio/openctem/api/pkg/domain/cvecorpus"
	"github.com/openctemio/openctem/api/pkg/domain/software"
	"github.com/openctemio/openctem/api/pkg/domain/threatintel"
	"github.com/openctemio/openctem/api/pkg/httpsec"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/vulnbundle"
)

// SourceName is the threat_intel_sync_status row of the importer.
const SourceName = "vulnfeed"

// DefaultBaseURL is where the feed is published: the releases of
// openctemio/vulnfeed-bundles (the collector code is openctemio/vulnfeed).
const DefaultBaseURL = "https://github.com/openctemio/vulnfeed-bundles/releases"

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
	dirFetchers        map[string]*transfer.Fetcher
	consumerRegistered bool

	// relayDir returns the relay working directory when the platform receives its feeds
	// through a relay sensor ("": not in relay mode); nil: never.
	relayDir func(ctx context.Context) string

	// aliases applies the release's alias dictionary (nil: not applied).
	aliases software.AliasWriter
	// vulnIDs applies the release's vulnerability id alias map (nil: not
	// applied).
	vulnIDs VulnIDAliasWriter
	// intel applies the release's KEV and EPSS streams (nil: not applied).
	intel IntelApplier
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

// WithRelay makes the importer read the relay working directory dir returns
// (non-empty only while the platform is in relay mode) as its only origin.
func (im *Importer) WithRelay(dir func(ctx context.Context) string) *Importer {
	im.relayDir = dir
	return im
}

func (im *Importer) relaySpool(ctx context.Context) string {
	if im.relayDir == nil || im.cfg.BundleDir != "" {
		return ""
	}
	return im.relayDir(ctx)
}

// Configured reports whether the importer has a pinned root key (without
// one it does nothing).
func (im *Importer) Configured() bool { return im.cfg.RootKeyID != "" }

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
	// One run at a time: the scheduled controller and an operator's request
	// (on this or another replica) never import together.
	if ok, err := im.status.TryStart(ctx, SourceName, feedstatus.RunningTimeout); err != nil {
		return res, fmt.Errorf("vulnfeed status: %w", err)
	} else if !ok {
		return res, nil
	}
	defer im.release(ctx)
	cur := readState(st.Metadata())
	dir := im.cfg.BundleDir
	if relay := im.relaySpool(ctx); relay != "" {
		// Relay mode: the relay working directory is the only origin, never the network, and
		// never the whole-bundle (v1) reader. Until the relay delivered a
		// pointer there is nothing to import.
		if !im.useV2(ctx, relay) {
			return res, nil
		}
		return im.runV2(ctx, cur, relay)
	}
	if im.useV2(ctx, dir) {
		return im.runV2(ctx, cur, dir)
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

	dir, kind, cleanup, err := im.stage(ctx, opt)
	if errors.Is(err, vulnbundle.ErrNotNewer) {
		return res, im.checked(ctx)
	}
	if err != nil {
		return res, im.fail(ctx, err)
	}
	defer cleanup()
	// Only the part that is applied is verified (and was fetched): the
	// delta when it starts at the applied sequence, the snapshot otherwise.
	v, err := vulnbundle.VerifyOne(dir, opt, kind)
	if err != nil {
		return res, im.fail(ctx, feedstatus.TagVerify(err))
	}
	res.Ran, res.Sequence, res.Kind = true, v.Latest.Sequence, kind
	if err := im.markStarted(ctx); err != nil {
		return res, err
	}
	if err := im.catalog.EnsureCurated(ctx, software.CuratedProducts()); err != nil {
		return res, im.fail(ctx, fmt.Errorf("curated products: %w", err))
	}
	m := v.Snapshot
	if kind == vulnbundle.KindDelta {
		m = *v.Delta
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
			return &feedstatus.GuardError{Base: feedstatus.ErrFeedShrunk, Kind: feedstatus.GuardRemoval, N: int64(emptied + e), Limit: int64(limit),
				Msg: fmt.Sprintf("refused: the bundle would remove %d affected ranges, over the limit of %d", emptied+e, limit)}
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

// stage puts the bundle in a local directory and says which part to apply:
// the delta when the verified pointer says it starts at the applied
// sequence, the snapshot otherwise (first import, or a platform that fell
// behind, however far). From the network only that part is fetched: the
// key set and the pointer first, then that part's manifest, verified, then
// its record files, each capped at the size its signed manifest states. A
// configured bundle directory (air-gapped) is read as it is.
func (im *Importer) stage(ctx context.Context, opt vulnbundle.Options) (string, string, func(), error) {
	if im.cfg.BundleDir != "" {
		v, err := vulnbundle.VerifyPointer(im.cfg.BundleDir, opt)
		if err != nil {
			return "", "", nil, tagPointer(err)
		}
		return im.cfg.BundleDir, partOf(v, opt), func() {}, nil
	}
	dir, err := os.MkdirTemp(im.tmp, "vulnfeed-*")
	if err != nil {
		return "", "", nil, err
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	fail := func(err error) (string, string, func(), error) {
		cleanup()
		return "", "", nil, err
	}
	latestURL := im.cfg.BaseURL + "/latest/download/"
	for _, name := range []string{vulnbundle.KeySetFile, vulnbundle.LatestFile} {
		if err := im.download(ctx, latestURL+name, filepath.Join(dir, name), vulnbundle.MaxManifestBytes); err != nil {
			return fail(publisherEmpty(err))
		}
	}
	v, err := vulnbundle.VerifyPointer(dir, opt)
	if err != nil {
		return fail(tagPointer(err))
	}
	kind := partOf(v, opt)
	tagURL := im.cfg.BaseURL + "/download/" + url.PathEscape(v.Latest.Tag) + "/"
	name := vulnbundle.ManifestName(kind)
	if err := im.download(ctx, tagURL+name, filepath.Join(dir, name), vulnbundle.MaxManifestBytes); err != nil {
		return fail(err)
	}
	m, err := v.LoadManifest(kind)
	if err != nil {
		return fail(err)
	}
	for _, f := range m.Files {
		if err := im.download(ctx, tagURL+f.Name, filepath.Join(dir, f.Name), f.Size); err != nil {
			return fail(err)
		}
	}
	return dir, kind, cleanup, nil
}

// partOf is the bundle part a platform at opt.AppliedSeq applies.
func partOf(v *vulnbundle.Verified, opt vulnbundle.Options) string {
	if v.DeltaApplies(opt.AppliedSeq) {
		return vulnbundle.KindDelta
	}
	return vulnbundle.KindSnapshot
}

// publisherEmpty: a 404 on the key set or the pointer means the collector has
// published nothing yet.
func publisherEmpty(err error) error {
	var he *feedstatus.HTTPError
	if errors.As(err, &he) && he.Status == http.StatusNotFound {
		return feedstatus.Tag(feedstatus.CodePublisherEmpty, map[string]string{"host": he.Host}, err)
	}
	return err
}

// tagPointer classifies a pointer verification failure ("nothing newer" is
// not a failure).
func tagPointer(err error) error {
	if errors.Is(err, vulnbundle.ErrNotNewer) {
		return err
	}
	return feedstatus.TagVerify(err)
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
		return &feedstatus.HTTPError{Op: "vulnfeed fetch", File: filepath.Base(path), Host: req.URL.Host, Status: resp.StatusCode}
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
	meta["root_key_id"] = im.cfg.RootKeyID
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
		c := feedstatus.Classify(cause)
		st.MarkSyncFailedWith(cause.Error(), c.Code, c.Params)
		err = im.status.Update(ctx, st)
	}
	if err != nil {
		im.logger.Warn("vulnfeed status not updated", "error", err)
	}
	return cause
}

// release ends a run that left the row running (a run that found nothing
// newer, or an early return): the platform is current as of now.
func (im *Importer) release(ctx context.Context) {
	// The caller's context may be the one that ended the run.
	ctx = context.WithoutCancel(ctx)
	st, err := im.status.GetBySource(ctx, SourceName)
	if err != nil || st.LastSyncStatus() != threatintel.SyncStateRunning {
		return
	}
	st.MarkSyncUnchanged(0, 0)
	if err := im.status.Update(ctx, st); err != nil {
		im.logger.Warn("vulnfeed status not updated", "error", err)
	}
}

// checked records a run that found nothing newer: the platform is current as
// of now, and an earlier failure no longer stands.
func (im *Importer) checked(ctx context.Context) error {
	st, err := im.status.GetBySource(ctx, SourceName)
	if err != nil {
		return err
	}
	st.MarkSyncUnchanged(0, 0)
	return im.status.Update(ctx, st)
}

// Freshness returns the applied release sequence and the applied bundle's
// creation time (zero when none was applied).
func (im *Importer) Freshness(ctx context.Context) (uint64, time.Time, error) {
	st, err := im.status.GetBySource(ctx, SourceName)
	if err != nil {
		return 0, time.Time{}, err
	}
	meta := st.Metadata()
	created, _ := time.Parse(time.RFC3339, fmt.Sprint(meta["bundle_created_at"]))
	return toUint(meta["applied_sequence"]), created, nil
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
