package certmonitor

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/openctemio/contract/ctlookup"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// testBodyCap is the largest answer httpSource reads from one test server.
const testBodyCap = 1 << 20

// httpSource is a test-only CTSource that speaks the crt.sh and Cert Spotter
// wire formats to httptest servers, the way a platform sensor does in
// production: one attempt per source, crt.sh first, then Cert Spotter. The
// platform itself never does this; the production package holds no HTTP
// client.
type httpSource struct {
	client    *http.Client
	crtBase   string
	csBase    string
	bodyLimit int64
}

func (h *httpSource) Available(context.Context) bool { return h.client != nil || h.crtBase != "" }

func (h *httpSource) Lookup(ctx context.Context, _ shared.ID, domain string) (ctlookup.Output, error) {
	var out ctlookup.Output
	recs, st := h.queryCRTSH(ctx, domain)
	out.SourceStatus = append(out.SourceStatus, st)
	out.Records = append(out.Records, recs...)
	if st.State != ctlookup.StateOK && h.csBase != "" {
		recs, st := h.queryCertSpotter(ctx, domain)
		out.SourceStatus = append(out.SourceStatus, st)
		out.Records = append(out.Records, recs...)
	}
	return out, nil
}

func (h *httpSource) httpClient() *http.Client {
	if h.client != nil {
		return h.client
	}
	return http.DefaultClient
}

func (h *httpSource) limit() int64 {
	if h.bodyLimit > 0 {
		return h.bodyLimit
	}
	return testBodyCap
}

// get makes one request and maps its outcome to a source state.
func (h *httpSource) get(ctx context.Context, source, u string) ([]byte, ctlookup.SourceStatus) {
	st := ctlookup.SourceStatus{Source: source, State: ctlookup.StateUnavailable}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, st
	}
	req.Header.Set("Accept", "application/json")
	resp, err := h.httpClient().Do(req)
	if err != nil {
		return nil, st
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusTooManyRequests {
		st.State = ctlookup.StateRateLimited
		if n, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && n > 0 {
			st.RetryAfterS = min(n, ctlookup.MaxRetryAfter)
		}
		return nil, st
	}
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		return nil, st
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, h.limit()+1))
	if err != nil {
		return nil, st
	}
	if int64(len(body)) > h.limit() {
		st.State = ctlookup.StateTooLarge
		return nil, st
	}
	st.State = ctlookup.StateOK
	return body, st
}

func (h *httpSource) queryCRTSH(ctx context.Context, domain string) ([]ctlookup.Record, ctlookup.SourceStatus) {
	q := url.Values{"q": {"%." + domain}, "output": {"json"}, "deduplicate": {"Y"}}
	body, st := h.get(ctx, ctlookup.SourceCRTSH, h.crtBase+"/?"+q.Encode())
	if st.State != ctlookup.StateOK {
		return nil, st
	}
	var rows []struct {
		ID         json.Number `json:"id"`
		NameValue  string      `json:"name_value"`
		NotBefore  string      `json:"not_before"`
		NotAfter   string      `json:"not_after"`
		IssuerName string      `json:"issuer_name"`
		Serial     string      `json:"serial_number"`
	}
	if t := strings.TrimSpace(string(body)); t != "" {
		if err := json.Unmarshal(body, &rows); err != nil {
			st.State = ctlookup.StateUnavailable
			return nil, st
		}
	}
	recs := make([]ctlookup.Record, 0, len(rows))
	for _, r := range rows {
		recs = append(recs, ctlookup.Record{
			Source: ctlookup.SourceCRTSH, EntryID: r.ID.String(),
			DNSNames: strings.Split(r.NameValue, "\n"), Issuer: r.IssuerName, Serial: r.Serial,
			NotBefore: fmtCTTime(r.NotBefore), NotAfter: fmtCTTime(r.NotAfter),
		})
	}
	return recs, st
}

func fmtCTTime(s string) string {
	t := parseCRTTime(s)
	if t.IsZero() {
		return ""
	}
	return ctlookup.FormatTime(t)
}

func (h *httpSource) queryCertSpotter(ctx context.Context, domain string) ([]ctlookup.Record, ctlookup.SourceStatus) {
	st := ctlookup.SourceStatus{Source: ctlookup.SourceCertSpotter, State: ctlookup.StateOK}
	var recs []ctlookup.Record
	after := ""
	for page := 0; page < 10; page++ {
		q := url.Values{"domain": {domain}, "include_subdomains": {"true"}, "expand": {"dns_names", "issuer"}}
		if after != "" {
			q.Set("after", after)
		}
		body, pst := h.get(ctx, ctlookup.SourceCertSpotter, h.csBase+"/v1/issuances?"+q.Encode())
		if pst.State != ctlookup.StateOK {
			return nil, pst
		}
		var rows []struct {
			ID       string   `json:"id"`
			DNSNames []string `json:"dns_names"`
			NotAfter string   `json:"not_after"`
			Before   string   `json:"not_before"`
			Issuer   struct {
				Name string `json:"friendly_name"`
			} `json:"issuer"`
			Cert string `json:"cert_sha256"`
		}
		if err := json.Unmarshal(body, &rows); err != nil {
			st.State = ctlookup.StateUnavailable
			return nil, st
		}
		if len(rows) == 0 {
			break
		}
		for _, r := range rows {
			recs = append(recs, ctlookup.Record{
				Source: ctlookup.SourceCertSpotter, EntryID: r.ID, DNSNames: r.DNSNames,
				Issuer: r.Issuer.Name, Serial: r.Cert, NotBefore: r.Before, NotAfter: r.NotAfter,
			})
		}
		after = rows[len(rows)-1].ID
	}
	return recs, st
}

// newTestService builds a Service whose CT source is an httpSource on the
// crt.sh-format test server at crtBase.
func newTestService(assets AssetLister, exp ExposureUpserter, crtBase string) *Service {
	svc := NewService(assets, exp, testLogger())
	svc.SetSource(&httpSource{crtBase: crtBase})
	return svc
}

// setHTTPClient makes the test source use client (a test server's) and
// disables the politeness delay and waits.
func (s *Service) setHTTPClient(c *http.Client) {
	if h, ok := s.source.(*httpSource); ok {
		h.client = c
	}
	s.requestDelay = 0
	s.noSleep = true
}

// setCertSpotter adds a Cert Spotter test server behind crt.sh.
func setCertSpotter(svc *Service, u string) {
	if h, ok := svc.source.(*httpSource); ok {
		h.csBase = u
	}
}
