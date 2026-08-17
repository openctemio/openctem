// Package ctemid provides the application service that mirrors the CTEM-ID
// catalog from an external JSON feed (default https://ctem.org/source.json) into
// local reference storage, mirroring the KEV/EPSS threat-intel refresh pattern.
// The refresh is fail-open: a feed outage returns an error the caller logs and
// tolerates; it never panics and never blocks ingest.
package ctemid

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/openctemio/api/pkg/domain/ctemid"
	"github.com/openctemio/api/pkg/httpsec"
	"github.com/openctemio/api/pkg/logger"
)

const (
	// DefaultFeedURL is the CTEM-ID catalog feed, CVE-like, published as JSON.
	DefaultFeedURL = "https://ctem.org/source.json"

	// httpTimeout bounds the feed fetch.
	httpTimeout = 2 * time.Minute

	// maxFeedBytes bounds the response body to guard against an oversized /
	// malicious upstream.
	maxFeedBytes = 64 << 20 // 64 MiB

	// userAgent identifies OpenCTEM to the feed host.
	userAgent = "OpenCTEM/1.0 (https://github.com/openctemio)"
)

// Service refreshes and reads the CTEM-ID catalog.
type Service struct {
	repo       ctemid.Repository
	httpClient *http.Client
	feedURL    string
	logger     *logger.Logger
}

// NewService creates a Service. An empty feedURL defaults to DefaultFeedURL.
func NewService(repo ctemid.Repository, feedURL string, log *logger.Logger) *Service {
	if strings.TrimSpace(feedURL) == "" {
		feedURL = DefaultFeedURL
	}
	return &Service{
		repo: repo,
		// SafeHTTPClient refuses to connect to RFC1918 / link-local addresses
		// even though the feed URL is a public endpoint — defense against DNS
		// rebinding of a configurable URL.
		httpClient: httpsec.SafeHTTPClient(httpTimeout),
		feedURL:    feedURL,
		logger:     log.With("service", "ctem_id"),
	}
}

// SyncCatalog fetches the CTEM-ID feed and upserts it. Fail-open: any error is
// returned for the caller to log; nothing panics. Returns the number of entries
// upserted.
func (s *Service) SyncCatalog(ctx context.Context) (int, error) {
	if s == nil || s.repo == nil {
		return 0, nil
	}

	body, err := s.fetch(ctx)
	if err != nil {
		return 0, err
	}

	entries, err := parseCatalog(body)
	if err != nil {
		return 0, fmt.Errorf("failed to parse ctem-id feed: %w", err)
	}
	if len(entries) == 0 {
		s.logger.Warn("ctem-id feed returned no usable entries", "feed_url", s.feedURL)
		return 0, nil
	}

	if err := s.repo.UpsertBatch(ctx, entries); err != nil {
		return 0, fmt.Errorf("failed to persist ctem-id catalog: %w", err)
	}

	s.logger.Info("ctem-id catalog synced", "records", len(entries), "feed_url", s.feedURL)
	return len(entries), nil
}

// List proxies the repository list.
func (s *Service) List(ctx context.Context, category *string, limit, offset int) ([]*ctemid.CTEMID, int, error) {
	return s.repo.List(ctx, category, limit, offset)
}

// Count proxies the repository count.
func (s *Service) Count(ctx context.Context) (int, error) {
	return s.repo.Count(ctx)
}

// FeedURL returns the configured feed URL (for diagnostics).
func (s *Service) FeedURL() string { return s.feedURL }

func (s *Service) fetch(ctx context.Context) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.feedURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create ctem-id request: %w", err)
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch ctem-id feed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ctem-id feed returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxFeedBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to read ctem-id feed: %w", err)
	}
	return body, nil
}

// feedEntry tolerates the several field spellings the feed might use. json
// cannot map two keys to one field, so alternates are separate fields and
// coalesced after decode.
type feedEntry struct {
	CTEMID    string `json:"ctem_id"`
	ID        string `json:"id"`
	CTEMIDAlt string `json:"ctemId"`

	Category string `json:"category"`
	Type     string `json:"type"`

	Title string `json:"title"`
	Name  string `json:"name"`

	Description string `json:"description"`
	Summary     string `json:"summary"`

	Severity string `json:"severity"`

	SourceURL string `json:"source_url"`
	URL       string `json:"url"`
	Reference string `json:"reference"`

	PublishedAt string `json:"published_at"`
	Published   string `json:"published"`
	Date        string `json:"date"`
}

// parseCatalog is a pure (no I/O) helper so the tolerant feed shape handling is
// unit-testable without the SSRF-guarded HTTP client. It accepts either a
// top-level JSON array of entries or an object wrapping the array under
// "entries", "source", or "data".
func parseCatalog(body []byte) ([]*ctemid.CTEMID, error) {
	rawEntries, err := extractEntries(body)
	if err != nil {
		return nil, err
	}

	entries := make([]*ctemid.CTEMID, 0, len(rawEntries))
	for _, raw := range rawEntries {
		var fe feedEntry
		if err := json.Unmarshal(raw, &fe); err != nil {
			// Skip malformed entries rather than failing the whole sync.
			continue
		}
		id := coalesce(fe.CTEMID, fe.CTEMIDAlt, fe.ID)
		title := coalesce(fe.Title, fe.Name)
		if id == "" || title == "" {
			continue
		}
		category := ctemid.ParseCategory(coalesce(fe.Category, fe.Type))
		published := parseTime(coalesce(fe.PublishedAt, fe.Published, fe.Date))
		entries = append(entries, ctemid.NewCTEMID(
			id,
			category,
			title,
			coalesce(fe.Description, fe.Summary),
			fe.Severity,
			coalesce(fe.SourceURL, fe.URL, fe.Reference),
			published,
			[]byte(raw),
		))
	}
	return entries, nil
}

// extractEntries returns the array of raw entry objects from either a bare array
// or a wrapper object.
func extractEntries(body []byte) ([]json.RawMessage, error) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return nil, nil
	}
	if trimmed[0] == '[' {
		var arr []json.RawMessage
		if err := json.Unmarshal(trimmed, &arr); err != nil {
			return nil, err
		}
		return arr, nil
	}
	var wrapper struct {
		Entries []json.RawMessage `json:"entries"`
		Source  []json.RawMessage `json:"source"`
		Data    []json.RawMessage `json:"data"`
		Items   []json.RawMessage `json:"items"`
	}
	if err := json.Unmarshal(trimmed, &wrapper); err != nil {
		return nil, err
	}
	switch {
	case len(wrapper.Entries) > 0:
		return wrapper.Entries, nil
	case len(wrapper.Source) > 0:
		return wrapper.Source, nil
	case len(wrapper.Data) > 0:
		return wrapper.Data, nil
	case len(wrapper.Items) > 0:
		return wrapper.Items, nil
	default:
		return nil, nil
	}
}

func coalesce(vals ...string) string {
	for _, v := range vals {
		if s := strings.TrimSpace(v); s != "" {
			return s
		}
	}
	return ""
}

func parseTime(s string) *time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05Z07:00", "2006-01-02", "2006/01/02"} {
		if t, err := time.Parse(layout, s); err == nil {
			u := t.UTC()
			return &u
		}
	}
	return nil
}
