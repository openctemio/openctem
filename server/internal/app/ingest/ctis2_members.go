package ingest

// CTIS 2.0 members at the receiver (docs/architecture/ctis-receiver.md).
// A CTIS 2.0 document gives `properties` no meaning: receivers MUST NOT read
// behavior from it. A producer's properties are
// therefore stripped of every key this receiver used to interpret, before
// anything reads them, and the keys the stored model still keeps are derived
// here from the typed members and from extensions["io.openctem"]:
//
//   - root_domain of a subdomain: the domain_name a subdomain_of
//     relationship of the document names (never derived from the public
//     suffix list: a root is created only when the producer states it, and
//     ingest still checks it is a registrable parent);
//   - ip_addresses of a name: its A/AAAA DNS records and the ip_address
//     assets it resolves_to (DNS only);
//   - ip_addresses of a machine (network device, host, endpoint device, any
//     asset that is not a name, an address or a range): the ip_address
//     assets a has_address relationship names (its interface or management
//     addresses). A range is never given addresses, so a segment is never
//     matched by address;
//   - host, port and transport of a service, from its value;
//   - tls_fingerprint of a web origin or service: the certificate a
//     serves_certificate relationship names;
//   - import_scope, candidate_exposure, candidate_unverified and
//     web_content: from the asset's io.openctem extension.
//
// What a producer leaves in properties under any other key is kept as an
// opaque, display-only attribute bag (bounded in buildPropertiesFromCTIS).

import (
	"net"
	"strings"

	"github.com/openctemio/ctis/v2"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
)

// interpretedPropertyKeys are the asset property keys the receiver reads
// meaning from. A producer's value under one of them is dropped; the
// receiver sets the ones it needs from typed members (adoptCTIS2Members).
//
//nolint:goconst // a list of wire property names, each read where it is used
var interpretedPropertyKeys = []string{
	"sub_type", "kind", "root_domain", "parent_domain", "exposure", "aliases",
	"technologies", "technology", "zone_visibility", "last_seen",
	asset.PropKeyDiscoverySource, asset.PropKeyDiscoveryTool, asset.PropKeyWebContent,
	PropImportScope, extCandidateExposure, extCandidateUnverified,
	"sans", "subject_cn", "issuer_cn", "issuer_org", "not_before", "not_after",
	"owner", "contact", "responsible", "http_posture",
	"method", "status_code", "content_type", "title", "web_server", propServer,
	"redirect_url", "final_url", "url", "favicon_mmh3", propHypervisorHost, propTLSFingerprint,
	"host", "port", "transport",
}

// propServer is the stored attribute of an http service naming its HTTP
// Server header (the registry's canonical key; web_server is its synonym).
const propServer = "server"

// propTLSFingerprint is the stored attribute of an http service naming the
// certificate it served (read by the exposure bridge's certificate checks).
const propTLSFingerprint = "tls_fingerprint"

// io.openctem extension keys on assets (CTIS module,
// schemas/extensions/io.openctem/2.json).
const (
	extCandidateExposure   = "candidate_exposure"
	extCandidateUnverified = "candidate_unverified"
)

// adoptCTIS2Members prepares the receiver's copy of a validated CTIS 2.0
// document for the stored model: producer properties lose every
// interpreted key, then the stored keys are derived from typed members.
// serverSide is a report the platform built itself (a certificate
// promotion, a program's targets, an import converted on the server): its
// properties are the platform's own and are kept; only missing keys are
// derived.
func adoptCTIS2Members(report *ctis.Report, serverSide bool) {
	if report == nil {
		return
	}
	fillFromRules(report)
	resolved := resolvedAddressesByRef(report)
	addressed := hasAddressesByRef(report)
	roots := statedRoots(report)
	served := servedCertificates(report)
	for i := range report.Assets {
		a := &report.Assets[i]
		if !serverSide {
			for _, k := range interpretedPropertyKeys {
				delete(a.Properties, k)
			}
			for _, k := range asset.AddressPropertyKeys() {
				delete(a.Properties, k)
			}
		}
		set := func(k string, v any) {
			if a.Properties == nil {
				a.Properties = ctis.Properties{}
			}
			if _, has := a.Properties[k]; !has {
				a.Properties[k] = v
			}
		}
		if root := roots[a.ID]; root != "" && isSubdomainAsset(a) {
			set("root_domain", root)
		}
		if a.Type == ctis.AssetTypeService {
			// The address, port and transport of an open port, from its
			// canonical value: the port set reconciliation finds the open
			// ports of an address by host.
			if host, port, transport, ok := splitServiceValue(a.Value); ok {
				set("host", host)
				set("port", port)
				set("transport", transport)
			}
		}
		if fp := served[a.ID]; fp != "" {
			set(propTLSFingerprint, fp)
		}
		if ips := resolved[a.ID]; len(ips) > 0 && a.Type == ctis.AssetTypeDomainName {
			set(asset.PropKeyIPAddresses, ips)
		}
		if ips := addressed[a.ID]; len(ips) > 0 && takesHasAddress(a.Type) {
			set(asset.PropKeyIPAddresses, ips)
		}
		for _, k := range []string{PropImportScope, extCandidateExposure, extCandidateUnverified, asset.PropKeyWebContent} {
			if v, ok := a.Extensions.Get(ctis.OpenCTEMNamespace, k); ok {
				set(k, v)
			}
		}
	}
}

// keepsOwnProperties reports whether a report's properties are the
// platform's own: a document the platform built (ServerBuilt) and ingests
// under no sensor, CI run or uploader. A zero sensor alone is not enough: a
// person's upload and a connector's conversion run server-side too, and
// their properties come from a file or another system.
func keepsOwnProperties(agt *sensor.Sensor, opts Options) bool {
	return opts.ServerBuilt && agt != nil && agt.ID.IsZero() && opts.Binding.Kind != BindingCIRun && opts.Actor == nil
}

// isSubdomainAsset reports whether a CTIS asset is stored as a subdomain: a
// domain_name below its registrable apex.
func isSubdomainAsset(a *ctis.Asset) bool {
	return a != nil && a.Type == ctis.AssetTypeDomainName && domainNameStoredType(a.Value) == asset.AssetTypeSubdomain
}

// maxResolvedAddresses bounds the addresses one name records.
const maxResolvedAddresses = 64

// resolvedAddressesByRef is, per document asset id of a domain name, the
// addresses it resolves to: its A and AAAA DNS records and the ip_address
// assets a resolves_to relationship names. Canonical, deduplicated, bounded.
func resolvedAddressesByRef(report *ctis.Report) map[string][]string {
	out := map[string][]string{}
	seen := map[string]map[string]bool{}
	add := func(ref, ip string) {
		parsed := net.ParseIP(strings.TrimSpace(ip))
		if ref == "" || parsed == nil {
			return
		}
		canon := parsed.String()
		if v4 := parsed.To4(); v4 != nil {
			canon = v4.String()
		}
		if seen[ref] == nil {
			seen[ref] = map[string]bool{}
		}
		if seen[ref][canon] || len(out[ref]) >= maxResolvedAddresses {
			return
		}
		seen[ref][canon] = true
		out[ref] = append(out[ref], canon)
	}
	ipByRef := map[string]string{}
	for i := range report.Assets {
		a := &report.Assets[i]
		switch {
		case a.Type == ctis.AssetTypeIPAddress:
			ipByRef[a.ID] = a.Value
		case a.Type == ctis.AssetTypeDomainName && a.Technical != nil && a.Technical.Domain != nil:
			for _, r := range a.Technical.Domain.DNSRecords {
				if t := strings.ToUpper(strings.TrimSpace(r.Type)); t == "A" || t == "AAAA" {
					add(a.ID, r.Value)
				}
			}
		}
	}
	for _, rel := range report.Relationships {
		if rel.Type != ctis.RelResolvesTo {
			continue
		}
		if ip, ok := ipByRef[rel.ToRef]; ok {
			add(rel.FromRef, ip)
		}
	}
	return out
}

// takesHasAddress reports whether an asset of this wire type records the
// addresses its has_address relationships name: a machine. A name resolves
// (resolves_to), an address is itself, and a range is a segment, which is
// never matched by address.
func takesHasAddress(t ctis.AssetType) bool {
	switch t {
	case ctis.AssetTypeDomainName, ctis.AssetTypeIPAddress, ctis.AssetTypeIPRange, "":
		return false
	}
	return true
}

// hasAddressesByRef is, per document asset id, the ip_address assets its
// has_address relationships name. Canonical, deduplicated, bounded.
func hasAddressesByRef(report *ctis.Report) map[string][]string {
	ipByRef := map[string]string{}
	for i := range report.Assets {
		if report.Assets[i].Type == ctis.AssetTypeIPAddress {
			ipByRef[report.Assets[i].ID] = report.Assets[i].Value
		}
	}
	out := map[string][]string{}
	seen := map[string]map[string]bool{}
	for _, rel := range report.Relationships {
		if rel.Type != ctis.RelHasAddress {
			continue
		}
		ip, ok := ipByRef[rel.ToRef]
		parsed := net.ParseIP(strings.TrimSpace(ip))
		if !ok || rel.FromRef == "" || parsed == nil {
			continue
		}
		canon := parsed.String()
		if v4 := parsed.To4(); v4 != nil {
			canon = v4.String()
		}
		if seen[rel.FromRef] == nil {
			seen[rel.FromRef] = map[string]bool{}
		}
		if seen[rel.FromRef][canon] || len(out[rel.FromRef]) >= maxResolvedAddresses {
			continue
		}
		seen[rel.FromRef][canon] = true
		out[rel.FromRef] = append(out[rel.FromRef], canon)
	}
	return out
}

// statedRoots is, per document asset id of a domain name, the domain name a
// subdomain_of relationship says it sits under (the first one).
func statedRoots(report *ctis.Report) map[string]string {
	names := map[string]string{}
	for i := range report.Assets {
		if report.Assets[i].Type == ctis.AssetTypeDomainName {
			names[report.Assets[i].ID] = report.Assets[i].Value
		}
	}
	out := map[string]string{}
	for _, rel := range report.Relationships {
		if rel.Type != ctis.RelSubdomainOf {
			continue
		}
		root, ok := names[rel.ToRef]
		child := names[rel.FromRef]
		// Only a strict parent of the name; whether it is registrable is
		// checked where the root would be created (isRegistrableParent).
		if ok && child != "" && out[rel.FromRef] == "" && strings.HasSuffix(child, "."+root) {
			out[rel.FromRef] = root
		}
	}
	return out
}

// fillFromRules completes a finding that names a rule of the document's rule
// catalog (rule_ref) and omits its rule name or description: the rule's
// name, short description. Display only; never part of an identity (the
// finding keeps its own rule_id, equal to the rule's).
func fillFromRules(report *ctis.Report) {
	if len(report.Rules) == 0 {
		return
	}
	byID := make(map[string]*ctis.Rule, len(report.Rules))
	for i := range report.Rules {
		byID[report.Rules[i].ID] = &report.Rules[i]
	}
	for i := range report.Findings {
		f := &report.Findings[i]
		r := byID[f.RuleRef]
		if r == nil {
			continue
		}
		if f.RuleName == "" {
			f.RuleName = r.Name
		}
		if f.Description == "" {
			f.Description = firstNonEmptyStr(r.FullDescription, r.ShortDescription)
		}
	}
}

// servedCertificates is, per document asset id of a web origin or service,
// the SHA-256 fingerprint (the canonical value) of the certificate a
// serves_certificate relationship says it served (the first one).
func servedCertificates(report *ctis.Report) map[string]string {
	certs := map[string]string{}
	for i := range report.Assets {
		if report.Assets[i].Type == ctis.AssetTypeCertificate {
			certs[report.Assets[i].ID] = report.Assets[i].Value
		}
	}
	out := map[string]string{}
	for _, rel := range report.Relationships {
		if rel.Type != ctis.RelServesCertificate {
			continue
		}
		if fp, ok := certs[rel.ToRef]; ok && out[rel.FromRef] == "" {
			out[rel.FromRef] = fp
		}
	}
	return out
}
