// Package recon provides an adapter that turns recon-scanner output
// (subdomain enumeration, DNS, port scans, HTTP probes, URL crawling)
// into a CTIS Report, so recon tools plug into the same ingest path
// as vulnerability scanners.
//
// Unlike the /ingest/recon HTTP endpoint (which accepts the typed
// ReconIngestRequest struct), this adapter accepts the same payload
// as an opaque byte blob and uses the adapter registry's auto-detect
// path. It's the recon equivalent of the sarif/ adapter: tenants POST
// a JSON file to /ingest/auto and the registry picks recon if the
// shape matches.
package recon

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/openctemio/api/internal/infra/adapters/core"
	"github.com/openctemio/ctis"
)

// Adapter converts Recon scanner output to CTIS.
type Adapter struct{}

// NewAdapter constructs the adapter.
func NewAdapter() *Adapter { return &Adapter{} }

// Name returns the adapter name as it appears in the registry.
func (a *Adapter) Name() string { return "recon" }

// InputFormats are the MIME-ish labels the /ingest/auto router
// advertises. JSON is the only on-wire form; "recon" is the
// convenience alias tools use in the format= query param.
func (a *Adapter) InputFormats() []string { return []string{"recon", "json"} }

// OutputFormat is always CTIS — that's the shape the ingest pipeline
// consumes downstream.
func (a *Adapter) OutputFormat() string { return "ctis" }

// reconInput mirrors the handler.ReconIngestRequest shape. Kept
// duplicated in this package so the adapter has zero dependency on
// the HTTP handler layer — one-way data flow, no import cycle risk.
type reconInput struct {
	ScannerName    string               `json:"scanner_name"`
	ScannerVersion string               `json:"scanner_version,omitempty"`
	ReconType      string               `json:"recon_type"`
	Target         string               `json:"target"`
	StartedAt      int64                `json:"started_at,omitempty"`
	FinishedAt     int64                `json:"finished_at,omitempty"`
	DurationMs     int64                `json:"duration_ms,omitempty"`
	Subdomains     []subdomainInput     `json:"subdomains,omitempty"`
	DNSRecords     []dnsRecordInput     `json:"dns_records,omitempty"`
	OpenPorts      []openPortInput      `json:"open_ports,omitempty"`
	LiveHosts      []liveHostInput      `json:"live_hosts,omitempty"`
	URLs           []discoveredURLInput `json:"urls,omitempty"`
}

type subdomainInput struct {
	Host   string   `json:"host"`
	Domain string   `json:"domain,omitempty"`
	Source string   `json:"source,omitempty"`
	IPs    []string `json:"ips,omitempty"`
}

type dnsRecordInput struct {
	Host       string   `json:"host"`
	RecordType string   `json:"record_type"`
	Values     []string `json:"values"`
	TTL        int      `json:"ttl,omitempty"`
	Resolver   string   `json:"resolver,omitempty"`
	StatusCode string   `json:"status_code,omitempty"`
}

type openPortInput struct {
	Host     string `json:"host"`
	IP       string `json:"ip,omitempty"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol,omitempty"`
	Service  string `json:"service,omitempty"`
	Version  string `json:"version,omitempty"`
	Banner   string `json:"banner,omitempty"`
}

type liveHostInput struct {
	URL           string   `json:"url"`
	Host          string   `json:"host"`
	IP            string   `json:"ip,omitempty"`
	Port          int      `json:"port,omitempty"`
	Scheme        string   `json:"scheme"`
	StatusCode    int      `json:"status_code"`
	ContentLength int64    `json:"content_length,omitempty"`
	Title         string   `json:"title,omitempty"`
	WebServer     string   `json:"web_server,omitempty"`
	ContentType   string   `json:"content_type,omitempty"`
	Technologies  []string `json:"technologies,omitempty"`
	CDN           string   `json:"cdn,omitempty"`
	TLSVersion    string   `json:"tls_version,omitempty"`
	Redirect      string   `json:"redirect,omitempty"`
	ResponseTime  int64    `json:"response_time_ms,omitempty"`
}

type discoveredURLInput struct {
	URL        string `json:"url"`
	Method     string `json:"method,omitempty"`
	Source     string `json:"source,omitempty"`
	StatusCode int    `json:"status_code,omitempty"`
	Depth      int    `json:"depth,omitempty"`
	Parent     string `json:"parent,omitempty"`
	Type       string `json:"type,omitempty"`
	Extension  string `json:"extension,omitempty"`
}

// Allowed recon_type values — the adapter uses this whitelist to
// discriminate recon payloads from other tool outputs that happen to
// carry scanner_name + target fields.
var validReconTypes = map[string]bool{
	"subdomain":  true,
	"dns":        true,
	"port":       true,
	"http_probe": true,
	"url_crawl":  true,
}

// CanConvert reports whether the blob is a recon payload. The test is
// "parses as JSON AND has a known recon_type AND carries at least one
// result array". Stricter than "has a target field" to avoid matching
// generic scan blobs that happen to have overlapping keys.
func (a *Adapter) CanConvert(input []byte) bool {
	var probe reconInput
	if err := json.Unmarshal(input, &probe); err != nil {
		return false
	}
	if !validReconTypes[probe.ReconType] {
		return false
	}
	// Must have at least one populated result bucket — otherwise this
	// is an empty stub that the adapter has nothing to produce from.
	return len(probe.Subdomains) > 0 ||
		len(probe.DNSRecords) > 0 ||
		len(probe.OpenPorts) > 0 ||
		len(probe.LiveHosts) > 0 ||
		len(probe.URLs) > 0
}

// Convert parses the blob, hands it to the CTIS SDK converter, and
// applies the caller's AdapterOptions on top (scope, repository etc.).
func (a *Adapter) Convert(ctx context.Context, input []byte, opts *core.AdapterOptions) (*ctis.Report, error) {
	var in reconInput
	if err := json.Unmarshal(input, &in); err != nil {
		return nil, fmt.Errorf("parse recon input: %w", err)
	}
	if in.ScannerName == "" {
		return nil, fmt.Errorf("recon: scanner_name is required")
	}
	if !validReconTypes[in.ReconType] {
		return nil, fmt.Errorf("recon: unknown recon_type %q", in.ReconType)
	}

	ctisInput := toCTISInput(&in)

	converterOpts := ctis.DefaultReconConverterOptions()
	if opts != nil {
		// SourceName on AdapterOptions names the data source (e.g.
		// "subfinder-scan-2026-04-20"). Recon converter's own
		// DiscoverySource field is what shows up on the asset;
		// default to "agent" but allow the caller to override via
		// opts.SourceType so manual uploads can say "manual".
		if opts.SourceType != "" {
			converterOpts.DiscoverySource = opts.SourceType
		}
	}

	report, err := ctis.ConvertReconToCTIS(ctisInput, converterOpts)
	if err != nil {
		return nil, fmt.Errorf("convert recon to CTIS: %w", err)
	}

	// Scope from AdapterOptions flows through to the report so asset
	// linking works consistently with other adapters.
	if opts != nil && opts.Repository != "" {
		report.Metadata.Scope = &ctis.Scope{Name: opts.Repository}
	}
	return report, nil
}

// toCTISInput copies the local reconInput into the SDK-side struct.
// One-way flat copy, no clever transforms.
func toCTISInput(in *reconInput) *ctis.ReconToCTISInput {
	out := &ctis.ReconToCTISInput{
		ScannerName:    in.ScannerName,
		ScannerVersion: in.ScannerVersion,
		ReconType:      in.ReconType,
		Target:         in.Target,
		StartedAt:      in.StartedAt,
		FinishedAt:     in.FinishedAt,
		DurationMs:     in.DurationMs,
	}
	for _, s := range in.Subdomains {
		out.Subdomains = append(out.Subdomains, ctis.SubdomainInput{
			Host:   s.Host,
			Domain: s.Domain,
			Source: s.Source,
			IPs:    s.IPs,
		})
	}
	for _, r := range in.DNSRecords {
		out.DNSRecords = append(out.DNSRecords, ctis.DNSRecordInput{
			Host:       r.Host,
			RecordType: r.RecordType,
			Values:     r.Values,
			TTL:        r.TTL,
			Resolver:   r.Resolver,
			StatusCode: r.StatusCode,
		})
	}
	for _, p := range in.OpenPorts {
		out.OpenPorts = append(out.OpenPorts, ctis.OpenPortInput{
			Host:     p.Host,
			IP:       p.IP,
			Port:     p.Port,
			Protocol: p.Protocol,
			Service:  p.Service,
			Version:  p.Version,
			Banner:   p.Banner,
		})
	}
	for _, h := range in.LiveHosts {
		out.LiveHosts = append(out.LiveHosts, ctis.LiveHostInput{
			URL:           h.URL,
			Host:          h.Host,
			IP:            h.IP,
			Port:          h.Port,
			Scheme:        h.Scheme,
			StatusCode:    h.StatusCode,
			ContentLength: h.ContentLength,
			Title:         h.Title,
			WebServer:     h.WebServer,
			ContentType:   h.ContentType,
			Technologies:  h.Technologies,
			CDN:           h.CDN,
			TLSVersion:    h.TLSVersion,
			Redirect:      h.Redirect,
			ResponseTime:  h.ResponseTime,
		})
	}
	for _, u := range in.URLs {
		out.URLs = append(out.URLs, ctis.DiscoveredURLInput{
			URL:        u.URL,
			Method:     u.Method,
			Source:     u.Source,
			StatusCode: u.StatusCode,
			Depth:      u.Depth,
			Parent:     u.Parent,
			Type:       u.Type,
			Extension:  u.Extension,
		})
	}
	return out
}
