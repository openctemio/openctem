package certmonitor

import (
	"context"
	"fmt"
	"io"
	"net/http"
)

// httpFetcher is a test Fetcher that performs the CT requests itself with
// client (a test server's). Production has no such fetcher: the platform
// never connects to a CT source.
type httpFetcher struct{ client *http.Client }

func (f httpFetcher) FetchCT(ctx context.Context, r CTRequest) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.URL, nil)
	if err != nil {
		return nil, err
	}
	req.Header = r.Header.Clone()
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s request failed: %w", r.Source, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		return nil, NewStatusError(r.Source, resp.StatusCode, resp.Header.Get("Retry-After"))
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, r.MaxBytes+1))
	if err != nil {
		return nil, err
	}
	return body, nil
}

// setHTTPClient makes the service fetch through client (a test server's) and
// disables the politeness delay and retry waits.
func (s *Service) setHTTPClient(c *http.Client) {
	s.fetcher = httpFetcher{client: c}
	s.requestDelay = 0
	s.noSleep = true
}
