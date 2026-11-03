package ingest

// Identity recipes v2 at ingest (RFC-043 §4.2, decisions D1–D4).
// https://github.com/openctemio/openctem/blob/develop/api/docs/rfcs/RFC-043-deduplication-and-identity.md
//
// The server decides identity. A sensor's opaque Finding.Fingerprint is a hint
// (RFC-040): it is kept as a sighting key in partial_fingerprints and never
// becomes the identity. Tool-native ids count only where a recipe names them
// (SARIF primaryLocationLineHash, Semgrep matchBasedId/v1).

import (
	"net/url"
	"sort"
	"strings"

	"github.com/openctemio/ctis/v2"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// Partial fingerprint keys ingest reads or writes.
const (
	// partialSnippetHash carries the producer's hash of the flagged code
	// (the CTIS key snippetHash/v1, ctis fingerprint.PartialSnippetHash).
	partialSnippetHash = "snippetHash/v1"
	// partialSecretHMAC carries a producer's keyed hash of a raw secret
	// (HMAC-SHA256 under the tenant and asset's producer key).
	partialSecretHMAC = "secretHMAC/v1"
	// partialSensorFingerprint keeps the sensor's own fingerprint as a
	// sighting key (D1).
	partialSensorFingerprint = "sensor/fingerprint"
	// partialServerSecretHMAC carries the server's keyed hash of a raw
	// secret a report carried unmasked, taken before the value is masked
	// (keyRawSecrets). Server-only: refused from reports, never stored.
	partialServerSecretHMAC = "server/secretHMAC/v1"
)

// identityKind tells which recipe applies to a CTIS finding, or "" when none
// of the specific ones does: the finding is then keyed by the generic recipe
// (genericIdentity), or keeps its version-1 key when it has no rule either.
func identityKind(f *ctis.Finding) string {
	switch {
	case f.Type == ctis.FindingTypeSecret || f.Secret != nil:
		return vulnerability.IdentityKindSecret
	case f.Type == ctis.FindingTypeCompliance:
		if c := f.Compliance; c != nil && (strings.TrimSpace(string(c.Framework)) != "" || strings.TrimSpace(c.ControlID) != "") {
			return vulnerability.IdentityKindCompliance
		}
		return ""
	case f.Web3 != nil:
		// CTIS 2.0 has no web3 finding type: the web3 profile marks one.
		if strings.TrimSpace(f.Web3.ContractAddress) != "" {
			return vulnerability.IdentityKindWeb3
		}
		return ""
	case f.Type == ctis.FindingTypeMisconfiguration || f.Misconfiguration != nil:
		return vulnerability.IdentityKindMisconfig
	case f.Vulnerability != nil && (strings.TrimSpace(f.Vulnerability.PackageName) != "" || strings.TrimSpace(f.Vulnerability.PURL) != ""):
		return vulnerability.IdentityKindSCA
	}
	if _, _, ok := networkVACVEKey(f); ok {
		return vulnerability.IdentityKindNetwork
	}
	if p := locationPath(f); p != "" {
		if u, _ := vulnerability.URLTemplate(p); u != "" {
			return vulnerability.IdentityKindDAST
		}
		if strings.TrimSpace(f.RuleID) != "" {
			return vulnerability.IdentityKindSAST
		}
		return ""
	}
	if f.Network != nil && strings.TrimSpace(f.RuleID) != "" {
		return vulnerability.IdentityKindNetwork
	}
	return ""
}

func locationPath(f *ctis.Finding) string {
	if f.Location == nil {
		return ""
	}
	return strings.TrimSpace(f.Location.Path)
}

// identityV2 computes the version-2 identity of f on asset. ok is false when
// no recipe applies or the recipe lacks its inputs (a SAST result with
// neither code nor a line, a secret without a keyed HMAC); the
// caller then keeps the version-1 key. secretHMAC is the server-keyed
// per-tenant HMAC of the reported secret; it is never logged.
func identityV2(assetID shared.ID, f *ctis.Finding, secretHMAC string, occurrence int) (vulnerability.IdentityKey, bool) {
	asset := assetID.String()
	switch identityKind(f) {
	case vulnerability.IdentityKindSecret:
		return vulnerability.SecretIdentity(asset, secretHMAC, locationPath(f))
	case vulnerability.IdentityKindMisconfig:
		policy, rtype, rname := f.RuleID, "", ""
		if m := f.Misconfiguration; m != nil {
			if strings.TrimSpace(m.PolicyID) != "" {
				policy = m.PolicyID
			}
			rtype, rname = m.ResourceType, m.ResourceName
		}
		return vulnerability.MisconfigIdentity(asset, policy, rtype, rname, locationPath(f))
	case vulnerability.IdentityKindSCA:
		v := f.Vulnerability
		return vulnerability.SCAIdentity(asset, v.PURL, purlEcosystem(v.PURL), v.PackageName, primaryCVE(v), f.RuleID)
	case vulnerability.IdentityKindNetwork:
		cve := ""
		if c, _, ok := networkVACVEKey(f); ok {
			cve = c
		}
		port, proto := 0, ""
		if f.Network != nil {
			port, proto = f.Network.Port, string(f.Network.Transport)
		}
		return vulnerability.NetworkIdentity(asset, cve, f.RuleID, port, proto)
	case vulnerability.IdentityKindDAST:
		return vulnerability.DASTIdentity(asset, dastRule(f), dastMethod(f), dastKeyURL(f), dastParams(f))
	case vulnerability.IdentityKindSAST:
		return vulnerability.SASTIdentity(sastInput(asset, f, occurrence))
	case vulnerability.IdentityKindCompliance:
		return vulnerability.ComplianceIdentity(asset, string(f.Compliance.Framework), f.Compliance.ControlID, locationPath(f))
	case vulnerability.IdentityKindWeb3:
		w := f.Web3
		rule := w.SWCID
		if strings.TrimSpace(rule) == "" {
			rule = f.RuleID
		}
		return vulnerability.Web3Identity(asset, w.ChainID, w.ContractAddress, rule, w.FunctionSignature)
	}
	return vulnerability.IdentityKey{}, false
}

// genericIdentity is the CTIS generic recipe (rule, path, lines) for a
// finding no specific recipe keys; false without a rule id, and the finding
// then keeps its version-1 key.
func genericIdentity(assetID shared.ID, f *ctis.Finding) (vulnerability.IdentityKey, bool) {
	start, end := 0, 0
	if f.Location != nil {
		start, end = f.Location.StartLine, f.Location.EndLine
	}
	return vulnerability.GenericIdentity(assetID.String(), f.RuleID, locationPath(f), start, end)
}

func sastInput(asset string, f *ctis.Finding, occurrence int) vulnerability.SASTIdentityInput {
	in := vulnerability.SASTIdentityInput{
		Asset:      asset,
		Rule:       f.RuleID,
		Path:       locationPath(f),
		Occurrence: occurrence,
	}
	if f.PartialFingerprints != nil {
		in.SnippetHash = f.PartialFingerprints[partialSnippetHash]
	}
	if f.Location != nil {
		in.StartLine = f.Location.StartLine
		in.Snippet = f.Location.Snippet
		if in.Snippet == vulnerability.SemgrepRequiresLogin {
			in.Snippet = ""
		}
		if ll := f.Location.LogicalLocation; ll != nil {
			in.LogicalLocation = ll.FullyQualifiedName
			if in.LogicalLocation == "" {
				in.LogicalLocation = ll.Name
			}
		}
	}
	return in
}

// formerKeys are the keys a finding may still be stored under from an
// earlier form of its recipe, in both their current and version-2 forms;
// nil when none.
func formerKeys(assetID shared.ID, f *ctis.Finding, identity vulnerability.IdentityKey) []string {
	switch identityKind(f) {
	case vulnerability.IdentityKindSAST:
		return sastFormerLineKey(assetID, f, identity)
	case vulnerability.IdentityKindDAST:
		return dastFormerURLKey(assetID, f)
	}
	return nil
}

// sastFormerLineKey is the line-anchored key of a SAST finding whose key is
// anchored on its code: the key it was stored under while its reports
// carried no code. "" when the finding is not SAST or has no such key.
func sastFormerLineKey(assetID shared.ID, f *ctis.Finding, identity vulnerability.IdentityKey) []string {
	if identityKind(f) != vulnerability.IdentityKindSAST || identity.Field("snippet") == "" {
		return nil
	}
	k, ok := vulnerability.SASTLineIdentity(sastInput(assetID.String(), f, 0))
	if !ok {
		return nil
	}
	return k.KeyForms()
}

// sastSnippetGroup is the key under which identical SAST snippets of one file
// are counted to give each its occurrence index.
func sastSnippetGroup(assetID shared.ID, f *ctis.Finding) (string, bool) {
	if identityKind(f) != vulnerability.IdentityKindSAST {
		return "", false
	}
	in := sastInput(assetID.String(), f, 0)
	sh := vulnerability.SASTSnippetHash(in)
	if sh == "" {
		return "", false
	}
	return strings.Join([]string{in.Asset, in.Rule, vulnerability.NormalizeRepoPath(in.Path), sh, in.LogicalLocation}, "\x1f"), true
}

// sastOccurrences returns, per finding index, the 0-based occurrence of its
// (rule, path, snippet) in the report, in line order, so twin snippets keep
// their index when unrelated code moves.
func sastOccurrences(findings []ctis.Finding, assetOf func(i int) shared.ID) map[int]int {
	groups := map[string][]int{}
	for i := range findings {
		a := assetOf(i)
		if a.IsZero() {
			continue
		}
		if g, ok := sastSnippetGroup(a, &findings[i]); ok {
			groups[g] = append(groups[g], i)
		}
	}
	out := make(map[int]int, len(findings))
	for _, idx := range groups {
		sort.SliceStable(idx, func(a, b int) bool {
			return startLine(&findings[idx[a]]) < startLine(&findings[idx[b]])
		})
		for n, i := range idx {
			out[i] = n
		}
	}
	return out
}

func startLine(f *ctis.Finding) int {
	if f.Location == nil {
		return 0
	}
	return f.Location.StartLine
}

// dastRule is the rule a DAST key names: the CVE of a CVE template, else the
// rule id.
func dastRule(f *ctis.Finding) string {
	if c := primaryCVE(f.Vulnerability); c != "" {
		return vulnerability.CanonicalVulnID(c) // a CVE template is the CVE
	}
	return f.RuleID
}

// dastMethod is the HTTP method of a DAST result: the CTIS web location's
// method. "" when it names none; DASTIdentity reads that as GET, so a
// producer that stops reporting the method never forks a finding.
func dastMethod(f *ctis.Finding) string {
	if f.Web != nil && strings.TrimSpace(f.Web.Method) != "" {
		return f.Web.Method
	}
	return ""
}

// dastParams are the parameter names a DAST result names besides the query
// string (a fuzzed body or header parameter): the CTIS web location's
// parameter.
func dastParams(f *ctis.Finding) []string {
	var out []string
	if f.Web != nil && f.Web.Parameter != nil && strings.TrimSpace(f.Web.Parameter.Name) != "" {
		out = append(out, f.Web.Parameter.Name)
	}
	return out
}

// sourceExtraTarget is the producer's scan input (CTIS source_extra.target).
const sourceExtraTarget = "target"

// dastKeyURL is the URL a DAST key is built on. A result whose path the
// template requested itself (a fixed-path detection: the matched URL is not
// the target it was run against, and no parameter was fuzzed) is one issue on
// that target, however many of its paths matched: it is keyed on the target.
// Any other result (an endpoint the scan was given, a fuzzed parameter) is
// keyed on the matched URL.
func dastKeyURL(f *ctis.Finding) string {
	matched := locationPath(f)
	if base, ok := dastTemplateBase(f, matched); ok {
		return base
	}
	return matched
}

// dastTemplateBase returns the target URL when the matched path came from the
// template, not from the target.
func dastTemplateBase(f *ctis.Finding, matched string) (string, bool) {
	if len(dastParams(f)) > 0 {
		return "", false
	}
	target := strings.TrimSpace(f.SourceExtra[sourceExtraTarget])
	if target == "" || matched == "" {
		return "", false
	}
	mu, err := url.Parse(matched)
	if err != nil || mu.Host == "" {
		return "", false
	}
	if !strings.Contains(target, "://") {
		target = mu.Scheme + "://" + target
	}
	tu, err := url.Parse(target)
	if err != nil || tu.Host == "" || !strings.EqualFold(tu.Hostname(), mu.Hostname()) {
		return "", false
	}
	if tu.Port() == "" && mu.Port() != "" {
		tu.Host = tu.Host + ":" + mu.Port()
	}
	tu.Scheme = mu.Scheme
	tp, mp := strings.TrimSuffix(tu.EscapedPath(), "/"), strings.TrimSuffix(mu.EscapedPath(), "/")
	if tp == mp && mu.RawQuery == "" {
		return "", false // the matched URL is the target: an endpoint, keyed as it is
	}
	tu.RawQuery, tu.Fragment, tu.User = "", "", nil
	return tu.String(), true
}

// dastFormerURLKey is the key a template-path DAST result had when it was
// keyed on its matched URL, "" when it is keyed so now.
func dastFormerURLKey(assetID shared.ID, f *ctis.Finding) []string {
	matched := locationPath(f)
	if _, ok := dastTemplateBase(f, matched); !ok {
		return nil
	}
	k, ok := vulnerability.DASTIdentity(assetID.String(), dastRule(f), dastMethod(f), matched, dastParams(f))
	if !ok {
		return nil
	}
	return k.KeyForms()
}

// splitMultiCVEFinding returns one finding per CVE for a network VA or SCA
// finding that names several (decision D3, extended to SCA by D20: a
// multi-CVE advisory such as a vendor id listing two CVEs), each with that
// single CVE, in CVE order; or f alone. Two tools then agree on the CVE they
// share, and the copy whose CVE is the one the finding was keyed on keeps
// its key.
func splitMultiCVEFinding(f ctis.Finding) []ctis.Finding {
	if f.Vulnerability == nil {
		return []ctis.Finding{f}
	}
	if _, _, ok := networkVACVEKey(&f); !ok && identityKind(&f) != vulnerability.IdentityKindSCA {
		return []ctis.Finding{f}
	}
	seen := map[string]bool{}
	var cves []string
	for _, c := range findingCVEs(f.Vulnerability) {
		c = vulnerability.CanonicalVulnID(c)
		if c != "" && !seen[c] {
			seen[c] = true
			cves = append(cves, c)
		}
	}
	if len(cves) < 2 {
		return []ctis.Finding{f}
	}
	sort.Strings(cves)
	out := make([]ctis.Finding, 0, len(cves))
	for _, c := range cves {
		cp := f
		v := *f.Vulnerability
		v.IDs = withOnlyCVE(v.IDs, c)
		cp.Vulnerability = &v
		out = append(out, cp)
	}
	return out
}

// purlEcosystem is the ecosystem of a package URL: its type ("npm" of
// "pkg:npm/lodash@4"), lower case, or "" without a purl. CTIS 2.0 carries the
// ecosystem only as the purl type.
func purlEcosystem(purl string) string {
	rest, ok := strings.CutPrefix(strings.TrimSpace(purl), "pkg:")
	if !ok {
		return ""
	}
	t, _, _ := strings.Cut(rest, "/")
	return strings.ToLower(t)
}
