// Package bountysource reads a bug-bounty program's scope from where the
// program publishes it (RFC-065 §14): HackerOne's researcher API
// (structured scopes, with the researcher's own API token) or a scope file
// on the program's own domain. Every request goes through the platform's
// outbound guard (pkg/httpsec: no private, loopback or metadata address),
// with a body limit and a timeout.
package bountysource

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	bp "github.com/openctemio/openctem/api/pkg/domain/bountyprogram"
	"github.com/openctemio/openctem/api/pkg/httpsec"
)

// Limits of one fetch.
const (
	maxBody     = bp.MaxScopeTextBytes
	maxAPIPages = 20 // 2 000 structured scopes at 100 a page
	timeout     = 30 * time.Second
)

// DefaultAPIBase is HackerOne's API.
const DefaultAPIBase = "https://api.hackerone.com/v1"

// ErrGone: the source answered that the program or file does not exist.
var ErrGone = errors.New("the program scope source is gone")

// Fetcher reads program scopes.
type Fetcher struct {
	client  *http.Client
	apiBase string
}

// New returns a fetcher on the outbound guard.
func New() *Fetcher {
	return &Fetcher{client: httpsec.SafeHTTPClient(timeout), apiBase: DefaultAPIBase}
}

// NewWithClient returns a fetcher on the given client and API base (tests).
func NewWithClient(c *http.Client, apiBase string) *Fetcher {
	return &Fetcher{client: c, apiBase: strings.TrimRight(apiBase, "/")}
}

func (f *Fetcher) get(ctx context.Context, rawURL, user, token string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json, text/plain, text/csv")
	req.Header.Set("User-Agent", "openctem-program-sync")
	if user != "" {
		req.SetBasicAuth(user, token)
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	switch {
	case resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone:
		return nil, ErrGone
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return nil, fmt.Errorf("the source refused the credentials (%d)", resp.StatusCode)
	case resp.StatusCode < 200 || resp.StatusCode > 299:
		return nil, fmt.Errorf("the source answered %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	if len(body) > maxBody {
		return nil, bp.ErrScopeTooLarge
	}
	return body, nil
}

// FetchFile reads a scope file (the text or CSV format of ParseScope).
func (f *Fetcher) FetchFile(ctx context.Context, fileURL string) ([]bp.Item, error) {
	body, err := f.get(ctx, fileURL, "", "")
	if err != nil {
		return nil, err
	}
	return bp.ParseScope(string(body))
}

type h1Program struct {
	Data struct {
		Attributes struct {
			SubmissionState string `json:"submission_state"`
		} `json:"attributes"`
	} `json:"data"`
}

type h1Scopes struct {
	Data []struct {
		Attributes struct {
			AssetIdentifier       string `json:"asset_identifier"`
			AssetType             string `json:"asset_type"`
			EligibleForSubmission bool   `json:"eligible_for_submission"`
		} `json:"attributes"`
	} `json:"data"`
	Links struct {
		Next string `json:"next"`
	} `json:"links"`
}

// FetchAPI reads a program's structured scopes with the researcher's API
// credentials: in scope when eligible for submission, out of scope
// otherwise. open is false when the program no longer takes submissions.
func (f *Fetcher) FetchAPI(ctx context.Context, handle, username, token string) (items []bp.Item, open bool, err error) {
	base := f.apiBase + "/hackers/programs/" + url.PathEscape(handle)
	body, err := f.get(ctx, base, username, token)
	if err != nil {
		return nil, false, err
	}
	var prog h1Program
	if err := json.Unmarshal(body, &prog); err != nil {
		return nil, false, fmt.Errorf("decode program: %w", err)
	}
	open = prog.Data.Attributes.SubmissionState == "" || prog.Data.Attributes.SubmissionState == "open"

	next := base + "/structured_scopes?page%5Bsize%5D=100&page%5Bnumber%5D=1"
	for page := 0; next != "" && page < maxAPIPages; page++ {
		// Only follow links on the API host (a response never sends the
		// credentials elsewhere).
		if !strings.HasPrefix(next, f.apiBase+"/") {
			return nil, false, fmt.Errorf("the source linked outside its API")
		}
		body, err := f.get(ctx, next, username, token)
		if err != nil {
			return nil, false, err
		}
		var sc h1Scopes
		if err := json.Unmarshal(body, &sc); err != nil {
			return nil, false, fmt.Errorf("decode scopes: %w", err)
		}
		for _, d := range sc.Data {
			it := bp.ClassifyTyped(d.Attributes.AssetIdentifier, d.Attributes.AssetType)
			it.InScope = d.Attributes.EligibleForSubmission
			items = append(items, it)
			if len(items) > bp.MaxScopeItems {
				return nil, false, bp.ErrScopeTooLarge
			}
		}
		next = sc.Links.Next
	}
	return items, open, nil
}
