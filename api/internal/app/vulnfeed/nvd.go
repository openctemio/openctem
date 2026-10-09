// Package vulnfeed syncs the platform-wide CVE corpus used by inventory
// matching from the NVD CVE API 2.0.
//
// Design: docs/rfcs/RFC-066-inventory-vulnerability-matching.md (§5.3, §4).
//
// Everything read from the feed is untrusted input: the response body is
// capped and decoded one CVE at a time, every string is bounded, CPE names
// and versions go through the vulnmatch parsers, and a statement that does
// not parse is dropped rather than widened.
package vulnfeed

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/cvecorpus"
	"github.com/openctemio/openctem/api/pkg/domain/vulnmatch"
	"github.com/openctemio/openctem/api/pkg/httpsec"
)

// nvdBaseURL is fixed: there is no configurable feed URL, so the feed is no
// SSRF surface.
const nvdBaseURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

// NVD API limits and our caps.
const (
	PageSize           = 2000
	MaxWindow          = 120 * 24 * time.Hour
	maxPageBytes       = 256 << 20
	maxRangesPerCVE    = 2000
	maxDescriptionLen  = 4000
	paceWithoutKey     = 6 * time.Second
	paceWithKey        = 700 * time.Millisecond
	rateLimitedBackoff = 30 * time.Second
	maxAttempts        = 4
)

var (
	cveIDPattern = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,19}$`)
	cwePattern   = regexp.MustCompile(`^CWE-[0-9]{1,6}$`)
	cvssVector   = regexp.MustCompile(`^[A-Za-z0-9:/.\-_()]{1,200}$`)
)

// ErrRateLimited is returned when the NVD API keeps refusing requests.
var ErrRateLimited = errors.New("nvd: rate limited")

// Client reads pages of the NVD CVE API.
type Client struct {
	http    *http.Client
	baseURL string
	apiKey  string
	pace    time.Duration
	sleep   func(context.Context, time.Duration) error
	last    time.Time
}

// NewClient returns a client of the public NVD API. apiKey may be empty.
func NewClient(apiKey string) *Client {
	pace := paceWithoutKey
	if apiKey != "" {
		pace = paceWithKey
	}
	return &Client{
		http:    httpsec.SafeHTTPClientWithHeaderTimeout(10*time.Minute, time.Minute),
		baseURL: nvdBaseURL,
		apiKey:  apiKey,
		pace:    pace,
		sleep:   sleepCtx,
	}
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// PageQuery selects one page: the whole corpus (bootstrap) or CVEs modified
// in a window of at most 120 days.
type PageQuery struct {
	StartIndex  int
	ModifiedGTE time.Time
	ModifiedLT  time.Time
}

// Page is one decoded page.
type Page struct {
	TotalResults int
	Count        int // CVE objects on the page, including those dropped
	CVEs         []cvecorpus.CVE
}

// FetchPage reads one page, paced and retried on rate limiting. The body is
// decoded one CVE object at a time; only the converted records are kept.
func (c *Client) FetchPage(ctx context.Context, q PageQuery) (*Page, error) {
	u, err := url.Parse(c.baseURL)
	if err != nil {
		return nil, fmt.Errorf("nvd url: %w", err)
	}
	params := url.Values{}
	params.Set("resultsPerPage", strconv.Itoa(PageSize))
	params.Set("startIndex", strconv.Itoa(q.StartIndex))
	if !q.ModifiedGTE.IsZero() {
		if q.ModifiedLT.Sub(q.ModifiedGTE) > MaxWindow || !q.ModifiedLT.After(q.ModifiedGTE) {
			return nil, fmt.Errorf("nvd: invalid modified window %s - %s", q.ModifiedGTE, q.ModifiedLT)
		}
		params.Set("lastModStartDate", q.ModifiedGTE.UTC().Format("2006-01-02T15:04:05.000Z"))
		params.Set("lastModEndDate", q.ModifiedLT.UTC().Format("2006-01-02T15:04:05.000Z"))
	}
	u.RawQuery = params.Encode()

	for attempt := 1; ; attempt++ {
		if wait := c.pace - time.Since(c.last); wait > 0 && !c.last.IsZero() {
			if err := c.sleep(ctx, wait); err != nil {
				return nil, err
			}
		}
		c.last = time.Now()
		page, retry, err := c.get(ctx, u.String())
		if err == nil {
			return page, nil
		}
		if !retry || attempt >= maxAttempts {
			return nil, err
		}
		if err := c.sleep(ctx, rateLimitedBackoff*time.Duration(attempt)); err != nil {
			return nil, err
		}
	}
}

func (c *Client) get(ctx context.Context, rawURL string) (*Page, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, false, fmt.Errorf("nvd request: %w", err)
	}
	req.Header.Set("User-Agent", "OpenCTEM/1.0 (https://github.com/openctemio)")
	req.Header.Set("Accept", "application/json")
	if c.apiKey != "" {
		req.Header.Set("apiKey", c.apiKey)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, true, fmt.Errorf("nvd fetch: %w", err)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusOK:
	case resp.StatusCode == http.StatusForbidden, resp.StatusCode == http.StatusTooManyRequests,
		resp.StatusCode >= 500:
		_, _ = io.Copy(io.Discard, httpsec.NewLimitedReader(resp.Body, 1<<20))
		return nil, true, fmt.Errorf("%w (status %d)", ErrRateLimited, resp.StatusCode)
	default:
		return nil, false, fmt.Errorf("nvd: unexpected status %d", resp.StatusCode)
	}
	page, err := DecodePage(httpsec.NewLimitedReader(resp.Body, maxPageBytes))
	if err != nil {
		return nil, false, err
	}
	return page, false, nil
}

// DecodePage decodes a CVE API response one vulnerability at a time.
// Fields other than totalResults and vulnerabilities are skipped.
func DecodePage(r io.Reader) (*Page, error) {
	dec := json.NewDecoder(r)
	if err := expectDelim(dec, '{'); err != nil {
		return nil, err
	}
	page := &Page{}
	for dec.More() {
		key, err := stringToken(dec)
		if err != nil {
			return nil, err
		}
		switch key {
		case "totalResults":
			if err := dec.Decode(&page.TotalResults); err != nil {
				return nil, fmt.Errorf("nvd: totalResults: %w", err)
			}
			if page.TotalResults < 0 || page.TotalResults > 10_000_000 {
				return nil, fmt.Errorf("nvd: implausible totalResults %d", page.TotalResults)
			}
		case "vulnerabilities":
			if err := expectDelim(dec, '['); err != nil {
				return nil, err
			}
			for dec.More() {
				var item struct {
					CVE nvdCVE `json:"cve"`
				}
				if err := dec.Decode(&item); err != nil {
					return nil, fmt.Errorf("nvd: vulnerability %d: %w", page.Count, err)
				}
				page.Count++
				if page.Count > PageSize {
					return nil, fmt.Errorf("nvd: more than %d vulnerabilities on a page", PageSize)
				}
				if cve, ok := convertCVE(item.CVE); ok {
					page.CVEs = append(page.CVEs, cve)
				}
			}
			if err := expectDelim(dec, ']'); err != nil {
				return nil, err
			}
		default:
			var skip json.RawMessage
			if err := dec.Decode(&skip); err != nil {
				return nil, fmt.Errorf("nvd: %s: %w", key, err)
			}
		}
	}
	return page, nil
}

func expectDelim(dec *json.Decoder, want json.Delim) error {
	t, err := dec.Token()
	if err != nil {
		return fmt.Errorf("nvd: decode: %w", err)
	}
	if d, ok := t.(json.Delim); !ok || d != want {
		return fmt.Errorf("nvd: expected %q", want)
	}
	return nil
}

func stringToken(dec *json.Decoder) (string, error) {
	t, err := dec.Token()
	if err != nil {
		return "", fmt.Errorf("nvd: decode: %w", err)
	}
	s, ok := t.(string)
	if !ok {
		return "", errors.New("nvd: expected an object key")
	}
	return s, nil
}

// nvdCVE is the subset of the NVD CVE object the corpus uses.
type nvdCVE struct {
	ID           string `json:"id"`
	Published    string `json:"published"`
	LastModified string `json:"lastModified"`
	VulnStatus   string `json:"vulnStatus"`
	Descriptions []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"descriptions"`
	Metrics struct {
		V40 []nvdMetric `json:"cvssMetricV40"`
		V31 []nvdMetric `json:"cvssMetricV31"`
		V30 []nvdMetric `json:"cvssMetricV30"`
		V2  []nvdMetric `json:"cvssMetricV2"`
	} `json:"metrics"`
	Weaknesses []struct {
		Description []struct {
			Value string `json:"value"`
		} `json:"description"`
	} `json:"weaknesses"`
	Configurations []struct {
		Operator string    `json:"operator"`
		Negate   bool      `json:"negate"`
		Nodes    []nvdNode `json:"nodes"`
	} `json:"configurations"`
}

type nvdMetric struct {
	Type     string `json:"type"`
	CVSSData struct {
		Version      string  `json:"version"`
		VectorString string  `json:"vectorString"`
		BaseScore    float64 `json:"baseScore"`
		BaseSeverity string  `json:"baseSeverity"`
	} `json:"cvssData"`
	BaseSeverity string `json:"baseSeverity"` // CVSS v2 keeps it here
}

type nvdNode struct {
	Operator string `json:"operator"`
	Negate   bool   `json:"negate"`
	CPEMatch []struct {
		Vulnerable            bool   `json:"vulnerable"`
		Criteria              string `json:"criteria"`
		VersionStartIncluding string `json:"versionStartIncluding"`
		VersionStartExcluding string `json:"versionStartExcluding"`
		VersionEndIncluding   string `json:"versionEndIncluding"`
		VersionEndExcluding   string `json:"versionEndExcluding"`
	} `json:"cpeMatch"`
}

// convertCVE validates a CVE object. ok is false for an object without a
// valid CVE id.
func convertCVE(n nvdCVE) (cvecorpus.CVE, bool) {
	id := strings.TrimSpace(n.ID)
	if !cveIDPattern.MatchString(id) {
		return cvecorpus.CVE{}, false
	}
	c := cvecorpus.CVE{ID: id, Status: clipText(strings.TrimSpace(n.VulnStatus), 32)}
	c.Rejected = strings.EqualFold(c.Status, "Rejected")
	c.Published = parseNVDTime(n.Published)
	c.LastModified = parseNVDTime(n.LastModified)
	for _, d := range n.Descriptions {
		if d.Lang == "en" {
			c.Description = clipText(sanitizeText(d.Value), maxDescriptionLen)
			break
		}
	}
	c.CVSSScore, c.CVSSVersion, c.CVSSVector, c.Severity = pickCVSS(n)
	seen := map[string]bool{}
	for _, w := range n.Weaknesses {
		for _, d := range w.Description {
			if v := strings.TrimSpace(d.Value); cwePattern.MatchString(v) && !seen[v] && len(c.CWEs) < 16 {
				seen[v] = true
				c.CWEs = append(c.CWEs, v)
			}
		}
	}
	if c.Rejected {
		return c, true
	}
	for _, cfg := range n.Configurations {
		if cfg.Negate {
			continue
		}
		c.Ranges = append(c.Ranges, configRanges(id, cfg.Operator, cfg.Nodes)...)
		if len(c.Ranges) > maxRangesPerCVE {
			c.Ranges = nil
			c.TooManyRanges = true
			break
		}
	}
	return c, true
}

// configRanges reads one configuration: every vulnerable statement is a
// range; in an AND configuration the first non-vulnerable statement of the
// other nodes is the platform the product must run on.
func configRanges(cveID, operator string, nodes []nvdNode) []cvecorpus.Range {
	var condition *vulnmatch.CPE
	if strings.EqualFold(operator, "AND") {
	find:
		for _, n := range nodes {
			if n.Negate {
				continue
			}
			for _, m := range n.CPEMatch {
				if !m.Vulnerable {
					if cpe, err := vulnmatch.ParseCPE(m.Criteria); err == nil {
						condition = &cpe
						break find
					}
				}
			}
		}
	}
	var out []cvecorpus.Range
	for _, n := range nodes {
		if n.Negate {
			continue
		}
		for _, m := range n.CPEMatch {
			if !m.Vulnerable {
				continue
			}
			r, cpe, ok := vulnmatch.RangeFromNVD(cveID, vulnmatch.NVDMatch{
				Criteria:              m.Criteria,
				VersionStartIncluding: m.VersionStartIncluding,
				VersionStartExcluding: m.VersionStartExcluding,
				VersionEndIncluding:   m.VersionEndIncluding,
				VersionEndExcluding:   m.VersionEndExcluding,
			})
			if !ok {
				continue
			}
			rr := cvecorpus.Range{Product: cpe, Range: r}
			if condition != nil && condition.Key() != cpe.Key() {
				rr.Condition = condition
			}
			out = append(out, rr)
		}
	}
	return out
}

// pickCVSS takes the primary metric of the newest CVSS version.
func pickCVSS(n nvdCVE) (*float64, string, string, string) {
	for _, set := range [][]nvdMetric{n.Metrics.V40, n.Metrics.V31, n.Metrics.V30, n.Metrics.V2} {
		if len(set) == 0 {
			continue
		}
		m := set[0]
		for _, x := range set {
			if strings.EqualFold(x.Type, "Primary") {
				m = x
				break
			}
		}
		score := m.CVSSData.BaseScore
		if score < 0 || score > 10 {
			return nil, "", "", ""
		}
		sev := strings.ToLower(firstNonEmpty(m.CVSSData.BaseSeverity, m.BaseSeverity))
		switch sev {
		case "none", "low", "medium", "high", "critical":
		default:
			sev = severityFromScore(score)
		}
		vector := m.CVSSData.VectorString
		if !cvssVector.MatchString(vector) {
			vector = ""
		}
		return &score, clipText(m.CVSSData.Version, 8), vector, sev
	}
	return nil, "", "", ""
}

func severityFromScore(s float64) string {
	switch {
	case s >= 9:
		return "critical"
	case s >= 7:
		return "high"
	case s >= 4:
		return "medium"
	case s > 0:
		return "low"
	}
	return "none"
}

func parseNVDTime(s string) *time.Time {
	s = strings.TrimSpace(s)
	for _, layout := range []string{"2006-01-02T15:04:05.000", "2006-01-02T15:04:05", time.RFC3339Nano} {
		if t, err := time.Parse(layout, s); err == nil {
			t = t.UTC()
			return &t
		}
	}
	return nil
}

func sanitizeText(s string) string {
	s = strings.ToValidUTF8(s, "")
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' {
			return ' '
		}
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
}

func clipText(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "")
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
