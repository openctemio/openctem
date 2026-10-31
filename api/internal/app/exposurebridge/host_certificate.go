package exposurebridge

// Certificate exposures per host (docs/architecture/easm.md, "Certificate
// exposures per host").
//
// A probe of an https service records the certificate the host served
// (service.tls_fingerprint, a serves_certificate edge to the certificate
// asset). The host, not the certificate, is what a visitor reaches and
// what the tenant fixes, so the problems a browser refuses are judged per
// service and certificate pair:
//
//   - certificate_expired (high): past not_after.
//   - certificate_expiring: within 30 days (high within 7).
//   - ssl_issue not_yet_valid (medium): before not_before.
//   - ssl_issue name_mismatch (medium): no name of the certificate covers
//     the host.
//   - ssl_issue foreign_certificate (high, a takeover candidate): no name of
//     the certificate shares the host's registrable domain. The host serves
//     another party's certificate, typically a hosting platform's default
//     one: the name still points at a platform where nothing (or someone
//     else) claims it.
//
// The facts come from the TLS handshake, so they hold when the host resets
// every HTTP request (a service with status 0). One exposure per service
// and problem: the title names the host, the details carry the certificate
// served (fingerprint, names, issuer, not_after). A later scan that sees
// the service serve a certificate without the problem resolves it
// automatically (resolved_by empty, AutoResolveCertNote); a scan that sees
// the problem again reopens it through the shared upsert. No probe result,
// no change: a host that was not reached keeps its exposures.
//
// Tenant isolation: every asset is the ingest tenant's (ProjectAssets
// checks), certificates are matched only within the same batch, and the
// automatic resolution is scoped to the tenant, this source and the exact
// fingerprints computed here.

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/exposure"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Certificate problems judged per host (details.issue of ssl_issue, and the
// kinds this file resolves).
const (
	CertIssueNotYetValid        = "not_yet_valid"
	CertIssueNameMismatch       = "name_mismatch"
	CertIssueForeignCertificate = "foreign_certificate"
)

// AutoResolveCertNote marks host certificate exposures resolved because a
// later scan saw the host serve a certificate without the problem.
const AutoResolveCertNote = "Resolved automatically: the host now serves a certificate without this problem."

// AutoResolveSupersededNote marks a certificate-level expiry exposure that
// the per-host certificate exposures replace.
const AutoResolveSupersededNote = "Resolved automatically: replaced by the certificate exposure on each host that serves it."

// certificateExpiringHigh is how close to not_after an expiring
// certificate is high.
const certificateExpiringHigh = 7 * 24 * time.Hour

// maxDetailSANs bounds the names copied into an exposure's details.
const maxDetailSANs = 20

// ExposureAutoResolver resolves the tenant's open exposures of one source by
// fingerprint, leaving accepted, false-positive and resolved ones alone
// (*postgres.EASMDNSRepository).
type ExposureAutoResolver interface {
	ResolveAuto(ctx context.Context, tenantID shared.ID, source string, fingerprints []string, note string) (int, error)
}

// SetAutoResolver enables the automatic resolution of host certificate
// exposures (nil: none is resolved, new ones are still raised).
func (b *AssetBridge) SetAutoResolver(r ExposureAutoResolver) { b.resolver = r }

// hostCert is one https service and the certificate it served.
type hostCert struct {
	svc  *asset.Asset
	cert *asset.Asset
	host string
}

// certificateProps are a certificate asset's certificate facts: the nested
// "certificate" map of the ingest mapper, or the flat properties a stored
// asset carries (the registry's attribute names: is_expired,
// is_self_signed, fingerprint_sha256). The flags are read under both names
// (certFlag).
func certificateProps(a *asset.Asset) map[string]any {
	if c := propMap(a.Properties(), "certificate"); c != nil {
		return c
	}
	p := a.Properties()
	if propString(p, "fingerprint") == "" && propString(p, "fingerprint_sha256") == "" && propString(p, "not_after") == "" {
		return nil
	}
	return p
}

// certFlag reads a certificate flag stored as name or is_<name>.
func certFlag(cert map[string]any, name string) bool {
	return propBool(cert, name) || propBool(cert, "is_"+name)
}

// certificateFingerprintOf is the certificate asset's SHA-256 fingerprint.
func certificateFingerprintOf(a *asset.Asset) string {
	c := certificateProps(a)
	for _, k := range []string{"fingerprint", "fingerprint_sha256"} {
		if fp := strings.ToLower(propString(c, k)); fp != "" {
			return fp
		}
	}
	return strings.ToLower(a.Name())
}

// pairHostCertificates pairs each https service of the batch with the
// certificate of the same batch it served (service.tls_fingerprint).
func pairHostCertificates(tenantID shared.ID, assets []*asset.Asset) ([]hostCert, map[string]bool) {
	certs := map[string]*asset.Asset{}
	for _, a := range assets {
		if a == nil || a.TenantID() != tenantID || a.Type() != asset.AssetTypeCertificate {
			continue
		}
		if fp := certificateFingerprintOf(a); fp != "" {
			certs[fp] = a
		}
	}
	pairs := make([]hostCert, 0, len(assets))
	served := map[string]bool{}
	for _, a := range assets {
		if a == nil || a.TenantID() != tenantID || a.Type() != asset.AssetTypeService || a.SubType() == "open_port" {
			continue
		}
		fp := strings.ToLower(propString(a.Properties(), "tls_fingerprint"))
		cert := certs[fp]
		host := hostOf(a)
		if fp == "" || cert == nil || host == "" {
			continue
		}
		served[fp] = true
		pairs = append(pairs, hostCert{svc: a, cert: cert, host: host})
	}
	return pairs, served
}

// hostOf is the name the service was probed by (the host of its URL,
// which was also the TLS server name), lower case without a trailing dot
// or port; "" when none can be read.
func hostOf(a *asset.Asset) string {
	for _, v := range []string{propString(a.Properties(), "url"), a.Name(), propString(a.Properties(), "host")} {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if strings.Contains(v, "://") {
			u, err := url.Parse(v)
			if err != nil {
				continue
			}
			v = u.Hostname()
		} else if h, _, err := net.SplitHostPort(v); err == nil {
			v = h
		}
		v = strings.TrimSuffix(strings.ToLower(strings.Trim(v, "[]")), ".")
		if v != "" && !strings.ContainsAny(v, "/ ") {
			return v
		}
	}
	return ""
}

// hostCertificateKind is one problem a host's certificate can have.
type hostCertificateKind struct {
	eventType exposure.EventType
	issue     string // details.issue of an ssl_issue
	title     func(host string) string
}

var hostCertificateKinds = []hostCertificateKind{
	{exposure.EventTypeCertificateExpired, "", func(h string) string { return "Expired TLS certificate on " + h }},
	{exposure.EventTypeCertificateExpiring, "", func(h string) string { return "TLS certificate expiring soon on " + h }},
	{exposure.EventTypeSSLIssue, CertIssueNotYetValid, func(h string) string { return "TLS certificate not yet valid on " + h }},
	{exposure.EventTypeSSLIssue, CertIssueNameMismatch, func(h string) string { return "TLS certificate does not cover " + h }},
	{exposure.EventTypeSSLIssue, CertIssueForeignCertificate, func(h string) string { return h + " serves another site's TLS certificate" }},
}

// hostCertificateFinding is a problem found, with its severity.
type hostCertificateFinding struct {
	kind     hostCertificateKind
	severity exposure.Severity
}

// judgeHostCertificate returns the problems of the certificate cert served
// for host at now.
func judgeHostCertificate(host string, cert map[string]any, now time.Time) []hostCertificateFinding {
	var out []hostCertificateFinding
	notAfter, hasNotAfter := parseTime(propString(cert, "not_after"))
	notBefore, hasNotBefore := parseTime(propString(cert, "not_before"))
	switch {
	case certFlag(cert, "expired") || (hasNotAfter && notAfter.Before(now)):
		out = append(out, hostCertificateFinding{hostCertificateKinds[0], exposure.SeverityHigh})
	case hasNotAfter && notAfter.Before(now.Add(certificateExpiryWindow)):
		sev := exposure.SeverityMedium
		if notAfter.Before(now.Add(certificateExpiringHigh)) {
			sev = exposure.SeverityHigh
		}
		out = append(out, hostCertificateFinding{hostCertificateKinds[1], sev})
	}
	if hasNotBefore && now.Before(notBefore) {
		out = append(out, hostCertificateFinding{hostCertificateKinds[2], exposure.SeverityMedium})
	}
	names := certificateNames(cert)
	// A service probed by address is judged on validity only: its
	// certificate names a site, never the address.
	if len(names) > 0 && net.ParseIP(host) == nil && !namesCover(names, host) {
		if foreignCertificate(names, host) {
			out = append(out, hostCertificateFinding{hostCertificateKinds[4], exposure.SeverityHigh})
		} else {
			out = append(out, hostCertificateFinding{hostCertificateKinds[3], exposure.SeverityMedium})
		}
	}
	return out
}

// certificateNames are the certificate's DNS names (SANs) and, without
// any, its subject CN (the browser rule: SANs win), lower case.
func certificateNames(cert map[string]any) []string {
	var names []string
	switch v := cert["sans"].(type) {
	case []any:
		for _, n := range v {
			if s, ok := n.(string); ok && strings.TrimSpace(s) != "" {
				names = append(names, strings.ToLower(strings.TrimSpace(s)))
			}
		}
	case []string:
		for _, s := range v {
			if strings.TrimSpace(s) != "" {
				names = append(names, strings.ToLower(strings.TrimSpace(s)))
			}
		}
	}
	if len(names) == 0 {
		if cn := strings.ToLower(propString(cert, "subject_cn")); cn != "" {
			names = append(names, cn)
		}
	}
	return names
}

// namesCover reports whether one of names covers host: the same name, or a
// wildcard "*.parent" for a host exactly one label under parent.
func namesCover(names []string, host string) bool {
	host = strings.TrimSuffix(host, ".")
	for _, n := range names {
		n = strings.TrimSuffix(n, ".")
		if n == host {
			return true
		}
		if rest, ok := strings.CutPrefix(n, "*."); ok {
			if i := strings.IndexByte(host, '.'); i > 0 && host[i+1:] == rest {
				return true
			}
		}
	}
	return false
}

// foreignCertificate reports whether no name of the certificate shares the
// host's registrable domain (an address host is never judged foreign).
func foreignCertificate(names []string, host string) bool {
	root, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil || root == "" {
		return false
	}
	for _, n := range names {
		n = strings.TrimPrefix(n, "*.")
		if r, err := publicsuffix.EffectiveTLDPlusOne(n); err == nil && r == root {
			return false
		}
	}
	return true
}

// hostCertificateEvents builds the exposures of one service and certificate
// pair and the fingerprints of the kinds it does not have (to resolve).
func (b *AssetBridge) hostCertificateEvents(p hostCert, now time.Time) ([]*exposure.ExposureEvent, []string) {
	cert := certificateProps(p.cert)
	if cert == nil {
		return nil, nil
	}
	found := map[int]exposure.Severity{}
	for _, f := range judgeHostCertificate(p.host, cert, now) {
		for i, k := range hostCertificateKinds {
			if k.eventType == f.kind.eventType && k.issue == f.kind.issue {
				found[i] = f.severity
			}
		}
	}
	var events []*exposure.ExposureEvent
	var clear []string
	for i, k := range hostCertificateKinds {
		sev, ok := found[i]
		if !ok {
			sev = exposure.SeverityMedium
		}
		ev := b.newEvent(p.svc, k.eventType, sev, k.title(p.host), b.hostCertificateDetails(p, cert, k), hostCertificateDescription(k))
		if ev == nil {
			continue
		}
		if ok {
			events = append(events, ev)
		} else {
			clear = append(clear, ev.Fingerprint())
		}
	}
	return events, clear
}

// hostCertificateDetails are the exposure's details: the host (the
// identifying "domain"), the certificate served and whether HTTP answered.
func (b *AssetBridge) hostCertificateDetails(p hostCert, cert map[string]any, k hostCertificateKind) map[string]any {
	d := map[string]any{
		discoverySourceKey: SourceReconScan,
		"domain":           p.host, // whitelisted: part of the dedupe key with the service asset
		"cert_fingerprint": certificateFingerprintOf(p.cert),
		"certificate_id":   p.cert.ID().String(),
	}
	if k.issue != "" {
		d["issue"] = k.issue
	}
	for _, key := range []string{"subject_cn", "issuer_cn", "issuer_org", "not_before", "not_after"} {
		if v := propString(cert, key); v != "" {
			d[key] = v
		}
	}
	if names := certificateNames(cert); len(names) > 0 {
		d["certificate_names"] = names[:min(len(names), maxDetailSANs)]
	}
	if certFlag(cert, "self_signed") {
		d["self_signed"] = true
	}
	status := propInt(p.svc.Properties(), "status_code")
	d["http_answered"] = status > 0
	if k.issue == CertIssueForeignCertificate {
		d["takeover_candidate"] = true
		if cn, ok := p.svc.Properties()["cnames"].([]any); ok && len(cn) > 0 {
			d["cnames"] = cn[:min(len(cn), 5)]
		}
	}
	return d
}

func hostCertificateDescription(k hostCertificateKind) string {
	switch k.issue {
	case CertIssueForeignCertificate:
		return "The host serves a certificate whose names belong to another domain, typically a hosting platform's default certificate: " +
			"the name may point at a platform where the site is no longer claimed (a subdomain takeover candidate). " +
			"Browsers refuse the site. Remove the DNS record or claim the site on the platform. (Discovered by recon scan.)"
	case CertIssueNameMismatch:
		return "No name of the certificate the host serves covers the host: browsers refuse the site. (Discovered by recon scan.)"
	case CertIssueNotYetValid:
		return "The certificate the host serves is not valid yet: browsers refuse the site. (Discovered by recon scan.)"
	}
	switch k.eventType {
	case exposure.EventTypeCertificateExpired:
		return "The certificate the host serves has expired: browsers refuse the site, and a host with HSTS cannot be opened at all. (Discovered by recon scan.)"
	case exposure.EventTypeCertificateExpiring:
		return "The certificate the host serves expires within 30 days. (Discovered by recon scan.)"
	}
	return ""
}

// legacyCertificateExpiryFingerprints are the fingerprints of the
// certificate-level expiry exposures this bridge raised on cert before the
// per-host ones replaced them.
func (b *AssetBridge) legacyCertificateExpiryFingerprints(cert *asset.Asset) []string {
	c := certificateProps(cert)
	if c == nil {
		return nil
	}
	label := propString(c, "subject_cn")
	if label == "" {
		label = cert.Name()
	}
	var fps []string
	for _, t := range []struct {
		typ   exposure.EventType
		title string
	}{
		{exposure.EventTypeCertificateExpired, fmt.Sprintf("Certificate expired: %s", label)},
		{exposure.EventTypeCertificateExpiring, fmt.Sprintf("Certificate expiring soon: %s", label)},
	} {
		if ev := b.newEvent(cert, t.typ, exposure.SeverityMedium, t.title, map[string]any{discoverySourceKey: SourceReconScan}, ""); ev != nil {
			fps = append(fps, ev.Fingerprint())
		}
	}
	return fps
}
