// Package nessus parses Tenable Nessus / Tenable.sc ".nessus" exports
// (NessusClientData_v2). It is the one parser of that format: the findings
// converter (internal/infra/scanner/nessus) and the host-only asset import
// (internal/app/asset) both read the file through it, so the two can never
// disagree about what a file contains (RFC-043 §12, one parser per tool).
// https://github.com/openctemio/openctem/blob/develop/api/docs/rfcs/RFC-043-deduplication-and-identity.md
package nessus

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
)

// ErrInvalid is returned for input that is not a Nessus v2 export.
var ErrInvalid = errors.New("invalid Nessus XML")

// ErrTooLarge is returned when the input is larger than the caller's limit.
var ErrTooLarge = errors.New("nessus export too large")

// Document is a parsed .nessus export.
type Document struct {
	XMLName xml.Name `xml:"NessusClientData_v2"`
	Hosts   []Host   `xml:"Report>ReportHost"`
}

// Host is one ReportHost.
type Host struct {
	Name       string    `xml:"name,attr"`
	Properties []HostTag `xml:"HostProperties>tag"`
	Items      []Item    `xml:"ReportItem"`
}

// HostTag is one HostProperties tag (host-ip, host-fqdn, operating-system, …).
type HostTag struct {
	Name  string `xml:"name,attr"`
	Value string `xml:",chardata"`
}

// Item is one ReportItem: a plugin result on a port.
type Item struct {
	Port         int      `xml:"port,attr"`
	Protocol     string   `xml:"protocol,attr"`
	ServiceName  string   `xml:"svc_name,attr"`
	PluginID     string   `xml:"pluginID,attr"`
	PluginName   string   `xml:"pluginName,attr"`
	PluginFamily string   `xml:"pluginFamily,attr"`
	Severity     int      `xml:"severity,attr"`
	Synopsis     string   `xml:"synopsis"`
	Description  string   `xml:"description"`
	Solution     string   `xml:"solution"`
	RiskFactor   string   `xml:"risk_factor"`
	CVSSScore    string   `xml:"cvss_base_score"`
	CVSSVector   string   `xml:"cvss_vector"`
	CVSS3Score   string   `xml:"cvss3_base_score"`
	CVSS3Vector  string   `xml:"cvss3_vector"`
	CVEs         []string `xml:"cve"`
	SeeAlso      string   `xml:"see_also"`
	PluginOutput string   `xml:"plugin_output"`
	VPRScore     string   `xml:"vpr_score"`
	ExploitAvail string   `xml:"exploit_available"`
	CPE          string   `xml:"cpe"`
	PatchPubDate string   `xml:"patch_publication_date"`
}

// Props flattens the host's HostProperties into a map (a repeated tag keeps
// its last value).
func (h *Host) Props() map[string]string {
	m := make(map[string]string, len(h.Properties))
	for _, p := range h.Properties {
		m[p.Name] = p.Value
	}
	return m
}

// Parse reads at most maxBytes of a .nessus export. More input than that is
// ErrTooLarge (never a silently truncated parse), and anything that is not a
// NessusClientData_v2 document is ErrInvalid. encoding/xml does not resolve
// external entities, so a hostile file cannot read local files (XXE).
func Parse(r io.Reader, maxBytes int64) (*Document, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read Nessus export: %w", err)
	}
	if int64(len(data)) > maxBytes {
		return nil, ErrTooLarge
	}
	var doc Document
	if err := xml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	return &doc, nil
}
