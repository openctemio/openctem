package defectdojo

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// maxFindingsPerSync bounds a single sync so a huge DefectDojo backlog can't
// pull unbounded memory/time in one pass; the scheduler (Phase 2b) resumes.
const maxFindingsPerSync = 10000

// defaultPageLimit is DefectDojo's typical max page size for /api/v2/findings/.
const defaultPageLimit = 100

// Client is a minimal, read-only DefectDojo REST client (Phase 2a). It pulls
// findings for ingestion; it never writes to DefectDojo (one-way, RFC-013).
type Client struct {
	baseURL string
	token   string
	http    *http.Client
}

// NewClient builds a DefectDojo client. baseURL is the instance root
// (e.g. https://dd.example.com); token is a DefectDojo API v2 token. A nil
// httpClient gets a sane default with a timeout.
func NewClient(baseURL, token string, httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	return &Client{
		baseURL: strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		token:   strings.TrimSpace(token),
		http:    httpClient,
	}
}

// FindingFilter narrows a findings pull. Zero-value fetches all active findings.
type FindingFilter struct {
	Product    string // DefectDojo product id or name
	Test       string // DefectDojo test id
	ActiveOnly bool   // only active=true findings (recommended)
	Limit      int    // page size (default 100)
	MaxTotal   int    // cap total pulled (default maxFindingsPerSync)
}

// findingsResponse is DefectDojo's paginated envelope.
type findingsResponse struct {
	Count   int       `json:"count"`
	Next    string    `json:"next"`
	Results []Finding `json:"results"`
}

// FetchFindings pulls findings across all pages (bounded by MaxTotal), following
// limit/offset pagination.
func (c *Client) FetchFindings(ctx context.Context, filter FindingFilter) ([]Finding, error) {
	limit := filter.Limit
	if limit <= 0 || limit > defaultPageLimit {
		limit = defaultPageLimit
	}
	maxTotal := filter.MaxTotal
	if maxTotal <= 0 || maxTotal > maxFindingsPerSync {
		maxTotal = maxFindingsPerSync
	}

	all := make([]Finding, 0, limit)
	for offset := 0; offset < maxTotal; offset += limit {
		q := url.Values{}
		q.Set("limit", strconv.Itoa(limit))
		q.Set("offset", strconv.Itoa(offset))
		if filter.ActiveOnly {
			q.Set("active", "true")
		}
		if filter.Product != "" {
			q.Set("product", filter.Product)
		}
		if filter.Test != "" {
			q.Set("test", filter.Test)
		}

		var page findingsResponse
		if err := c.getJSON(ctx, "/api/v2/findings/?"+q.Encode(), &page); err != nil {
			return nil, err
		}
		all = append(all, page.Results...)

		// Stop when the page is short (last page) or the API reports no next page.
		if len(page.Results) < limit || page.Next == "" {
			break
		}
		if len(all) >= maxTotal {
			break
		}
	}
	if len(all) > maxTotal {
		all = all[:maxTotal]
	}
	return all, nil
}

// TestConnection verifies the base URL + token by hitting a cheap authenticated
// endpoint. Used by the integration connect flow.
func (c *Client) TestConnection(ctx context.Context) error {
	if c.baseURL == "" {
		return fmt.Errorf("defectdojo: base URL is required")
	}
	if c.token == "" {
		return fmt.Errorf("defectdojo: API token is required")
	}
	var probe struct {
		Count int `json:"count"`
	}
	// product_types is small and always present on a healthy instance.
	return c.getJSON(ctx, "/api/v2/product_types/?limit=1", &probe)
}

// getJSON performs an authenticated GET and decodes the JSON body. It accepts
// either a path or a full URL (DefectDojo's `next` links are absolute).
func (c *Client) getJSON(ctx context.Context, pathOrURL string, out any) error {
	endpoint := pathOrURL
	if strings.HasPrefix(pathOrURL, "/") {
		endpoint = c.baseURL + pathOrURL
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return fmt.Errorf("defectdojo: build request: %w", err)
	}
	req.Header.Set("Authorization", "Token "+c.token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("defectdojo: request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return fmt.Errorf("defectdojo: authentication failed (status %d)", resp.StatusCode)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("defectdojo: unexpected status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("defectdojo: decode response: %w", err)
	}
	return nil
}
