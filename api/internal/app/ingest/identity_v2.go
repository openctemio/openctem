package ingest

// Identity recipes v2 at ingest (RFC-043 §4.2, decisions D1–D4).
// https://github.com/openctemio/openctem/blob/develop/api/docs/rfcs/RFC-043-deduplication-and-identity.md
//
// The server decides identity. A sensor's opaque Finding.Fingerprint is a hint
// (RFC-040): it is kept as a sighting key in partial_fingerprints and never
// becomes the identity. Tool-native ids count only where a recipe names them
// (SARIF primaryLocationLineHash, Semgrep matchBasedId/v1).

import (
	"sort"
	"strings"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// Partial fingerprint keys the SAST recipe reads.
const (
	partialPrimaryLocationLineHash = "primaryLocationLineHash"
	partialMatchBasedID            = "matchBasedId/v1"
	// partialSensorFingerprint keeps the sensor's own fingerprint as a
	// sighting key (D1).
	partialSensorFingerprint = "sensor/fingerprint"
)

// identityKind tells which v2 recipe applies to a CTIS finding, or "" when
// none does (compliance, web3, a generic finding without a location): such a
// finding keeps its version-1 key.
func identityKind(f *ctis.Finding) string {
	switch {
	case f.Type == ctis.FindingTypeSecret || f.Secret != nil:
		return vulnerability.IdentityKindSecret
	case f.Type == ctis.FindingTypeCompliance || f.Type == ctis.FindingTypeWeb3:
		return ""
	case f.Type == ctis.FindingTypeMisconfiguration || f.Misconfiguration != nil:
		return vulnerability.IdentityKindMisconfig
	case f.Vulnerability != nil && (strings.TrimSpace(f.Vulnerability.Package) != "" || strings.TrimSpace(f.Vulnerability.PURL) != ""):
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
// neither a tool anchor nor a snippet, a secret without a keyed HMAC); the
// caller then keeps the version-1 key. secretHMAC is the server-keyed
// per-tenant HMAC of the reported secret; it is never logged.
func identityV2(assetID shared.ID, f *ctis.Finding, tool *ctis.Tool, secretHMAC string, occurrence int) (vulnerability.IdentityKey, bool) {
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
		return vulnerability.SCAIdentity(asset, v.PURL, v.Ecosystem, v.Package, v.CVEID, f.RuleID)
	case vulnerability.IdentityKindNetwork:
		cve := ""
		if c, _, ok := networkVACVEKey(f); ok {
			cve = c
		}
		port, proto := 0, ""
		if f.Network != nil {
			port, proto = f.Network.Port, f.Network.Protocol
		}
		return vulnerability.NetworkIdentity(asset, cve, f.RuleID, port, proto)
	case vulnerability.IdentityKindDAST:
		rule := f.RuleID
		if f.Vulnerability != nil && strings.TrimSpace(f.Vulnerability.CVEID) != "" {
			rule = vulnerability.CanonicalVulnID(f.Vulnerability.CVEID) // a CVE template is the CVE
		}
		return vulnerability.DASTIdentity(asset, rule, dastMethod(f), locationPath(f), dastParams(f))
	case vulnerability.IdentityKindSAST:
		return vulnerability.SASTIdentity(sastInput(asset, f, tool, occurrence))
	}
	return vulnerability.IdentityKey{}, false
}

func sastInput(asset string, f *ctis.Finding, tool *ctis.Tool, occurrence int) vulnerability.SASTIdentityInput {
	in := vulnerability.SASTIdentityInput{
		Asset:      asset,
		Rule:       f.RuleID,
		Path:       locationPath(f),
		Occurrence: occurrence,
	}
	if tool != nil {
		in.Tool = tool.Name
	}
	if f.PartialFingerprints != nil {
		in.PrimaryLocationLineHash = f.PartialFingerprints[partialPrimaryLocationLineHash]
		if v := f.PartialFingerprints[partialMatchBasedID]; v != vulnerability.SemgrepRequiresLogin {
			in.MatchBasedID = v
		}
	}
	if f.Location != nil {
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

// sastSnippetGroup is the key under which identical SAST snippets of one file
// are counted to give each its occurrence index.
func sastSnippetGroup(assetID shared.ID, f *ctis.Finding, tool *ctis.Tool) (string, bool) {
	if identityKind(f) != vulnerability.IdentityKindSAST {
		return "", false
	}
	in := sastInput(assetID.String(), f, tool, 0)
	if in.PrimaryLocationLineHash != "" || in.MatchBasedID != "" {
		return "", false
	}
	sh := vulnerability.SnippetHash(in.Snippet)
	if sh == "" {
		return "", false
	}
	return strings.Join([]string{in.Asset, strings.ToLower(in.Tool), in.Rule, vulnerability.NormalizeRepoPath(in.Path), sh, in.LogicalLocation}, "\x1f"), true
}

// sastOccurrences returns, per finding index, the 0-based occurrence of its
// (rule, path, snippet) in the report, in line order, so twin snippets keep
// their index when unrelated code moves.
func sastOccurrences(findings []ctis.Finding, assetOf func(i int) shared.ID, tool *ctis.Tool) map[int]int {
	groups := map[string][]int{}
	for i := range findings {
		a := assetOf(i)
		if a.IsZero() {
			continue
		}
		if g, ok := sastSnippetGroup(a, &findings[i], tool); ok {
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

// dastMethod is the HTTP method of a DAST result: a "method" property, else
// the first word of the recorded request.
func dastMethod(f *ctis.Finding) string {
	if m, ok := f.Properties["method"].(string); ok && strings.TrimSpace(m) != "" {
		return m
	}
	if req, ok := f.Properties["request"].(string); ok {
		if i := strings.IndexAny(req, " \t"); i > 0 && i <= 10 {
			m := req[:i]
			if strings.ToUpper(m) == m && strings.Trim(m, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") == "" {
				return m
			}
		}
	}
	return ""
}

// dastParams are the parameter names a DAST result names besides the query
// string (a fuzzed body or header parameter).
func dastParams(f *ctis.Finding) []string {
	var out []string
	for _, key := range []string{"parameter", "param"} {
		if p, ok := f.Properties[key].(string); ok && strings.TrimSpace(p) != "" {
			out = append(out, p)
		}
	}
	return out
}

// splitMultiCVENetworkFinding returns one finding per CVE for a network VA
// finding that names several (decision D3), each with that single CVE, in
// CVE order; or f alone. Two scanners then agree on the CVE they share, and
// the lowest-CVE copy keeps the version-1 key the grouped finding had.
func splitMultiCVENetworkFinding(f ctis.Finding) []ctis.Finding {
	if _, _, ok := networkVACVEKey(&f); !ok || f.Vulnerability == nil {
		return []ctis.Finding{f}
	}
	seen := map[string]bool{}
	var cves []string
	for _, c := range append([]string{f.Vulnerability.CVEID}, f.Vulnerability.CVEIDs...) {
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
		v.CVEID = c
		v.CVEIDs = []string{c}
		cp.Vulnerability = &v
		out = append(out, cp)
	}
	return out
}
