package mcpoauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/openctemio/openctem/api/pkg/domain/mcpoauth"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/httpsec"
)

// Client ID Metadata Document fetch bounds (draft-ietf-oauth-client-id-
// metadata-document-02 §5, §8.6, §8.7).
const (
	cimdMaxBytes     = 5 * 1024
	cimdTimeout      = 5 * time.Second
	cimdDefaultCache = time.Hour
	cimdMinCache     = 5 * time.Minute
	cimdMaxCache     = 24 * time.Hour
	maxClientIDLen   = 2048
	maxClientNameLen = 120
	maxRedirectURIs  = 20
)

// ErrInvalidClientMetadata is a client metadata document that cannot be
// used. The reason is logged, never shown to the client.
var ErrInvalidClientMetadata = fmt.Errorf("%w: client metadata document is not usable", shared.ErrValidation)

// IsMetadataDocumentClientID reports whether a client_id is a URL, i.e. a
// Client ID Metadata Document rather than a registered identifier.
func IsMetadataDocumentClientID(clientID string) bool {
	return strings.HasPrefix(clientID, "https://") || strings.HasPrefix(clientID, "http://")
}

// ValidateMetadataDocumentURL checks a client_id URL before anything is
// fetched: https, a host, a path other than "/", no user info, query,
// fragment or dot segments.
func ValidateMetadataDocumentURL(clientID string) (*url.URL, error) {
	if len(clientID) > maxClientIDLen || strings.ContainsAny(clientID, " \t\r\n#") {
		return nil, ErrInvalidClientMetadata
	}
	u, err := url.Parse(clientID)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery {
		return nil, ErrInvalidClientMetadata
	}
	if u.Path == "" || u.Path == "/" {
		return nil, ErrInvalidClientMetadata
	}
	for _, seg := range strings.Split(u.EscapedPath(), "/") {
		if seg == "." || seg == ".." || strings.EqualFold(seg, "%2e") || strings.EqualFold(seg, "%2e%2e") {
			return nil, ErrInvalidClientMetadata
		}
	}
	return u, nil
}

// MetadataFetcher fetches a Client ID Metadata Document.
type MetadataFetcher interface {
	Fetch(ctx context.Context, clientID string) (*mcpoauth.Client, error)
}

// HTTPMetadataFetcher fetches documents through the platform's SSRF-guarded
// client: public addresses only (checked when the connection is made, so a
// DNS answer cannot be swapped between check and use), no redirects, a
// 5 KB body and a 5 second budget.
type HTTPMetadataFetcher struct {
	client *http.Client
	now    func() time.Time
}

// NewHTTPMetadataFetcher builds the production fetcher.
func NewHTTPMetadataFetcher() *HTTPMetadataFetcher {
	c := httpsec.SafeHTTPClient(cimdTimeout)
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &HTTPMetadataFetcher{client: c, now: time.Now}
}

// newMetadataFetcherWithClient is for tests (a local TLS server).
func newMetadataFetcherWithClient(c *http.Client, now func() time.Time) *HTTPMetadataFetcher {
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &HTTPMetadataFetcher{client: c, now: now}
}

// clientMetadataDocument is the subset of RFC 7591 client metadata read
// from a document.
type clientMetadataDocument struct {
	ClientID                string   `json:"client_id"`
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	ClientSecret            *string  `json:"client_secret"`
	ClientSecretExpiresAt   *int64   `json:"client_secret_expires_at"`
}

// Fetch implements MetadataFetcher.
func (f *HTTPMetadataFetcher) Fetch(ctx context.Context, clientID string) (*mcpoauth.Client, error) {
	u, err := ValidateMetadataDocumentURL(clientID)
	if err != nil {
		return nil, err
	}
	// Refuse a special-use address before any lookup leaves the process; the
	// guarded dialer checks again at connection time.
	if err := httpsec.ValidateHost(ctx, u.Hostname()); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidClientMetadata, err)
	}
	return f.fetchURL(ctx, clientID)
}

// fetchURL fetches and validates a document whose URL was already checked.
func (f *HTTPMetadataFetcher) fetchURL(ctx context.Context, clientID string) (*mcpoauth.Client, error) {
	ctx, cancel := context.WithTimeout(ctx, cimdTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, clientID, nil)
	if err != nil {
		return nil, ErrInvalidClientMetadata
	}
	req.Header.Set("Accept", "application/json")
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: fetch: %v", ErrInvalidClientMetadata, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: status %d", ErrInvalidClientMetadata, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, cimdMaxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%w: read: %v", ErrInvalidClientMetadata, err)
	}
	if len(body) > cimdMaxBytes {
		return nil, fmt.Errorf("%w: larger than %d bytes", ErrInvalidClientMetadata, cimdMaxBytes)
	}
	c, err := parseClientMetadataDocument(clientID, body)
	if err != nil {
		return nil, err
	}
	now := f.now()
	expires := now.Add(cacheLifetime(resp.Header.Get("Cache-Control")))
	c.FetchedAt, c.ExpiresAt = &now, &expires
	return c, nil
}

// parseClientMetadataDocument validates a document fetched from clientID.
func parseClientMetadataDocument(clientID string, body []byte) (*mcpoauth.Client, error) {
	var doc clientMetadataDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("%w: not JSON", ErrInvalidClientMetadata)
	}
	// Simple string comparison, no normalization (CIMD §4).
	if doc.ClientID != clientID {
		return nil, fmt.Errorf("%w: client_id does not match the document URL", ErrInvalidClientMetadata)
	}
	if doc.ClientSecret != nil || doc.ClientSecretExpiresAt != nil {
		return nil, fmt.Errorf("%w: a metadata document must not carry a client secret", ErrInvalidClientMetadata)
	}
	// Public clients only: PKCE is the client's proof.
	if m := doc.TokenEndpointAuthMethod; m != "" && m != "none" {
		return nil, fmt.Errorf("%w: token_endpoint_auth_method %q not supported", ErrInvalidClientMetadata, m)
	}
	if len(doc.GrantTypes) > 0 && !contains(doc.GrantTypes, "authorization_code") {
		return nil, fmt.Errorf("%w: grant_types lacks authorization_code", ErrInvalidClientMetadata)
	}
	if len(doc.ResponseTypes) > 0 && !contains(doc.ResponseTypes, "code") {
		return nil, fmt.Errorf("%w: response_types lacks code", ErrInvalidClientMetadata)
	}
	name := cleanClientName(doc.ClientName)
	if name == "" {
		return nil, fmt.Errorf("%w: client_name missing", ErrInvalidClientMetadata)
	}
	if len(doc.RedirectURIs) == 0 || len(doc.RedirectURIs) > maxRedirectURIs {
		return nil, fmt.Errorf("%w: redirect_uris must list 1 to %d URIs", ErrInvalidClientMetadata, maxRedirectURIs)
	}
	for _, r := range doc.RedirectURIs {
		if err := mcpoauth.ValidateRedirectURI(r); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidClientMetadata, err)
		}
	}
	return &mcpoauth.Client{
		ClientID:     clientID,
		Kind:         mcpoauth.ClientKindMetadataDocument,
		Name:         name,
		RedirectURIs: doc.RedirectURIs,
	}, nil
}

// cleanClientName keeps a display name safe to show: printable characters
// only (no bidi overrides or control characters that could disguise it),
// trimmed and bounded.
func cleanClientName(s string) string {
	var b strings.Builder
	for _, r := range strings.TrimSpace(s) {
		if unicode.IsPrint(r) && !unicode.Is(unicode.Bidi_Control, r) {
			b.WriteRune(r)
		}
	}
	out := strings.TrimSpace(b.String())
	if len([]rune(out)) > maxClientNameLen {
		out = string([]rune(out)[:maxClientNameLen])
	}
	return out
}

// cacheLifetime reads max-age from Cache-Control, bounded to [5 min, 24 h];
// no-store/no-cache keep the minimum, no header the default (1 h).
func cacheLifetime(cc string) time.Duration {
	if cc == "" {
		return cimdDefaultCache
	}
	d := cimdDefaultCache
	for _, part := range strings.Split(cc, ",") {
		p := strings.ToLower(strings.TrimSpace(part))
		switch {
		case p == "no-store" || p == "no-cache":
			return cimdMinCache
		case strings.HasPrefix(p, "max-age="):
			if n, err := strconv.Atoi(strings.TrimPrefix(p, "max-age=")); err == nil {
				d = time.Duration(n) * time.Second
			}
		}
	}
	if d < cimdMinCache {
		return cimdMinCache
	}
	if d > cimdMaxCache {
		return cimdMaxCache
	}
	return d
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

// resolveClient returns the client for clientID: a metadata document is
// served from the stored copy while it is fresh and fetched again when it is
// not; a registered client is read from the store. Unknown, unusable or
// blocked clients are errors.
func (s *Service) resolveClient(ctx context.Context, clientID string) (*mcpoauth.Client, error) {
	if clientID == "" || len(clientID) > maxClientIDLen {
		return nil, ErrInvalidClientMetadata
	}
	stored, err := s.repo.GetClientByClientID(ctx, clientID)
	if err != nil && !errors.Is(err, mcpoauth.ErrNotFound) {
		return nil, err
	}
	now := s.now()
	if stored != nil && stored.BlockedAt != nil {
		return nil, errClientBlocked
	}
	if !IsMetadataDocumentClientID(clientID) {
		if stored == nil {
			return nil, mcpoauth.ErrNotFound
		}
		return stored, nil
	}
	if stored != nil && stored.ExpiresAt != nil && now.Before(*stored.ExpiresAt) {
		return stored, nil
	}
	if s.fetcher == nil {
		return nil, ErrInvalidClientMetadata
	}
	fetched, err := s.fetcher.Fetch(ctx, clientID)
	if err != nil {
		// The client_id is caller input: line breaks are removed before it
		// reaches the log.
		s.log.Info("mcp oauth: client metadata document refused",
			"client_id", oneLine(clientID), "reason", oneLine(err.Error()))
		return nil, ErrInvalidClientMetadata
	}
	return s.repo.UpsertClient(ctx, fetched)
}

var errClientBlocked = errors.New("client blocked")

// oneLine strips line breaks so a value cannot forge log lines.
func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\n", "")
	return strings.ReplaceAll(s, "\r", "")
}
