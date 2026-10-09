package vulnfeed

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/cvecorpus"
)

func loadPage(t *testing.T) *Page {
	t.Helper()
	f, err := os.Open("testdata/nvd_page.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	p, err := DecodePage(f)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func byID(p *Page) map[string]cvecorpus.CVE {
	m := map[string]cvecorpus.CVE{}
	for _, c := range p.CVEs {
		m[c.ID] = c
	}
	return m
}

func TestDecodePage(t *testing.T) {
	p := loadPage(t)
	if p.TotalResults != 7 || p.Count != 5 || len(p.CVEs) != 4 {
		t.Fatalf("total=%d count=%d cves=%d", p.TotalResults, p.Count, len(p.CVEs))
	}
	cves := byID(p)

	nginx := cves["CVE-2021-23017"]
	if nginx.CVSSScore == nil || *nginx.CVSSScore != 7.7 || nginx.CVSSVersion != "3.1" || nginx.Severity != "high" {
		t.Errorf("cvss: %+v %s %s", nginx.CVSSScore, nginx.CVSSVersion, nginx.Severity)
	}
	if strings.ContainsAny(nginx.Description, "\n\a") || !strings.HasPrefix(nginx.Description, "A security issue") {
		t.Errorf("description %q", nginx.Description)
	}
	if len(nginx.CWEs) != 1 || nginx.CWEs[0] != "CWE-193" {
		t.Errorf("cwes %v", nginx.CWEs)
	}
	if nginx.Published == nil || nginx.Published.Year() != 2021 {
		t.Errorf("published %v", nginx.Published)
	}
	// Two good statements of the first configuration (wildcard criteria and
	// an unparseable bound are dropped), one of the AND configuration with
	// its platform condition; the negated configuration is skipped.
	if len(nginx.Ranges) != 3 {
		t.Fatalf("ranges: %+v", nginx.Ranges)
	}
	r0 := nginx.Ranges[0]
	if r0.Product.Key() != "cpe:a:f5:nginx" || r0.Range.Start != "0.6.18" || !r0.Range.StartIncl || r0.Range.End != "1.20.1" || r0.Range.EndIncl || r0.Condition != nil {
		t.Errorf("range 0: %+v", r0)
	}
	if r1 := nginx.Ranges[1]; r1.Range.Exact != "1.21.0" {
		t.Errorf("range 1: %+v", r1)
	}
	r2 := nginx.Ranges[2]
	if r2.Product.Key() != "cpe:a:f5:nginx_plus" || r2.Range.End != "r24" && r2.Condition == nil {
		t.Errorf("range 2: %+v", r2)
	}
	if r2.Condition == nil || r2.Condition.Key() != "cpe:o:canonical:ubuntu_linux" {
		t.Errorf("condition: %+v", r2.Condition)
	}

	gitlab := cves["CVE-2023-0001"]
	if len(gitlab.Ranges) != 3 || gitlab.Ranges[0].Range.Edition != "community" || gitlab.Ranges[2].Range.Edition != "enterprise" {
		t.Errorf("gitlab: %+v", gitlab.Ranges)
	}
	if gitlab.CVSSVersion != "4.0" || gitlab.Severity != "critical" {
		t.Errorf("gitlab cvss: %s %s", gitlab.CVSSVersion, gitlab.Severity)
	}

	rejected := cves["CVE-2020-9999"]
	if !rejected.Rejected || len(rejected.Ranges) != 0 {
		t.Errorf("rejected: %+v", rejected)
	}
	deferred := cves["CVE-2026-12345"]
	if deferred.Rejected || len(deferred.Ranges) != 0 || deferred.CVSSScore != nil {
		t.Errorf("deferred: %+v", deferred)
	}
}

func TestDecodePage_Refuses(t *testing.T) {
	for name, body := range map[string]string{
		"not json":        `<html>`,
		"array":           `[]`,
		"bad item":        `{"vulnerabilities":[{"cve": 5}]}`,
		"negative total":  `{"totalResults": -1}`,
		"huge total":      `{"totalResults": 99999999}`,
		"truncated":       `{"vulnerabilities":[{"cve":{"id":"CVE-2021-1`,
		"vulns not array": `{"vulnerabilities": {}}`,
	} {
		if _, err := DecodePage(strings.NewReader(body)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	var b strings.Builder
	b.WriteString(`{"vulnerabilities":[`)
	for i := 0; i <= PageSize; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"cve":{"id":"CVE-2020-%05d"}}`, i)
	}
	b.WriteString(`]}`)
	if _, err := DecodePage(strings.NewReader(b.String())); err == nil {
		t.Error("more than a page of vulnerabilities accepted")
	}
}

func TestConvertCVE_TooManyRanges(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"vulnerabilities":[{"cve":{"id":"CVE-2022-0001","configurations":[{"nodes":[{"operator":"OR","cpeMatch":[`)
	for i := 0; i <= maxRangesPerCVE; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"vulnerable":true,"criteria":"cpe:2.3:a:v:p%d:1.0:*:*:*:*:*:*:*"}`, i)
	}
	b.WriteString(`]}]}]}}]}`)
	p, err := DecodePage(strings.NewReader(b.String()))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.CVEs) != 1 || !p.CVEs[0].TooManyRanges || len(p.CVEs[0].Ranges) != 0 {
		t.Fatalf("got %+v", p.CVEs)
	}
}

func testClient(srv *httptest.Server, key string) (*Client, *[]time.Duration) {
	c := NewClient(key)
	c.http = srv.Client()
	c.baseURL = srv.URL
	var slept []time.Duration
	c.sleep = func(_ context.Context, d time.Duration) error {
		slept = append(slept, d)
		return nil
	}
	return c, &slept
}

func TestClient_FetchPage(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if n == 1 {
			w.WriteHeader(http.StatusForbidden) // NVD's rate-limit answer
			return
		}
		q := r.URL.Query()
		if q.Get("resultsPerPage") != "2000" || q.Get("startIndex") != "4000" ||
			q.Get("lastModStartDate") != "2026-01-01T00:00:00.000Z" || q.Get("lastModEndDate") != "2026-02-01T00:00:00.000Z" {
			t.Errorf("query %s", r.URL.RawQuery)
		}
		if r.Header.Get("apiKey") != "k" {
			t.Errorf("api key header missing")
		}
		_, _ = w.Write([]byte(`{"totalResults": 1, "vulnerabilities": []}`))
	}))
	defer srv.Close()
	c, slept := testClient(srv, "k")
	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	p, err := c.FetchPage(context.Background(), PageQuery{StartIndex: 4000, ModifiedGTE: from, ModifiedLT: from.AddDate(0, 1, 0)})
	if err != nil {
		t.Fatal(err)
	}
	if p.TotalResults != 1 || calls.Load() != 2 {
		t.Fatalf("total %d calls %d", p.TotalResults, calls.Load())
	}
	if len(*slept) == 0 || (*slept)[0] != rateLimitedBackoff {
		t.Errorf("no backoff after 403: %v", *slept)
	}
}

func TestClient_GivesUpAndRefusesBadWindows(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	c, _ := testClient(srv, "")
	if _, err := c.FetchPage(context.Background(), PageQuery{}); err == nil {
		t.Fatal("kept retrying")
	}
	from := time.Now()
	for _, q := range []PageQuery{
		{ModifiedGTE: from, ModifiedLT: from.Add(MaxWindow + time.Hour)},
		{ModifiedGTE: from, ModifiedLT: from},
	} {
		if _, err := c.FetchPage(context.Background(), q); err == nil {
			t.Errorf("window %v accepted", q)
		}
	}
	notFound := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer notFound.Close()
	c2, slept := testClient(notFound, "")
	if _, err := c2.FetchPage(context.Background(), PageQuery{}); err == nil || len(*slept) != 0 {
		t.Fatalf("404 retried or accepted: %v %v", err, *slept)
	}
}

// The default client is the SSRF-guarded one with the fixed base URL.
func TestNewClient_Defaults(t *testing.T) {
	c := NewClient("")
	if c.baseURL != nvdBaseURL || !strings.HasPrefix(c.baseURL, "https://services.nvd.nist.gov/") || c.pace != paceWithoutKey {
		t.Fatalf("%+v", c)
	}
	if NewClient("k").pace != paceWithKey {
		t.Fatal("pace with key")
	}
}
