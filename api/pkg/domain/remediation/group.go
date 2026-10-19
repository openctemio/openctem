package remediation

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// KeyInput carries the finding signals used to derive a remediation group key.
// Primitives only, so the derivation stays trivially unit-testable.
type KeyInput struct {
	// Source is the finding source (sca, secret, dast, ...). It namespaces the
	// solution-text fallback and keeps pentest findings out of groups.
	Source string
	// FindingType is the finding type (vulnerability, secret, ...).
	FindingType string

	// Package identity of an SCA finding: ecosystem (npm, pypi, ...), name
	// and the installed version. Empty for non-package findings.
	Ecosystem        string
	PackageName      string
	InstalledVersion string
	// FixedVersions are the versions that fix the finding's vulnerability
	// (the scanner's list on the finding, then the CVE catalog's).
	FixedVersions []string

	// SecretFingerprint is the keyed fingerprint of a leaked secret's value;
	// SecretType names its kind for the title.
	SecretFingerprint string
	SecretType        string

	// SolutionText is the scanner's remediation recommendation, the fallback
	// grouping signal for host/infra findings.
	SolutionText string
	// RuleID is the scanner rule that raised the finding. Code and
	// configuration findings group by solution text only within one rule.
	RuleID string
}

// KeyAlgorithmVersion is the version of DeriveKey's rules. A stored key with
// an older version is derived again (KeyApplier.Backfill) before the
// suggestion generator trusts it: version 1 grouped any solution text, so
// unrelated findings with the same boilerplate advice shared one key.
const KeyAlgorithmVersion = 3

// Key kinds: the part of a key before the first colon.
const (
	KindRotate  = "rotate"
	KindUpgrade = "upgrade"
	KindSol     = "sol"
)

// KeyKind returns the kind of a key ("upgrade" for "upgrade:pypi:django:4.2.30").
// No key contains "/": it is one URL path segment.
func KeyKind(key string) string {
	if i := strings.IndexByte(key, ':'); i > 0 {
		return key[:i]
	}
	return key
}

// DeriveKey computes the remediation-group key and a readable title for a
// finding. ok is false when the finding is not groupable (no shared fix).
//
// Precedence, strongest identity first:
//  1. A leaked secret: "rotate:secret:<fingerprint>". Only the same secret
//     value groups; a secret without a fingerprint gets no key (secrets are
//     never grouped by their advice text, which is the same for every secret).
//  2. A package with a known fix: "upgrade:<ecosystem>:<name>:<target>",
//     where target is the nearest fixed version for the installed version.
//     Two installed versions that the same upgrade fixes share one key.
//  3. A specific solution text: "sol:<source>:<sha256>". Only the sentences
//     that name something concrete (a version or an advisory id) count;
//     boilerplate ("Apply the suggested fix code.") never forms a group. For
//     code and configuration sources the rule id is part of the hash, so two
//     different rules with the same advice never share a fix.
func DeriveKey(in KeyInput) (key, title string, ok bool) {
	source := strings.ToLower(strings.TrimSpace(in.Source))
	if source == string(vulnerability.FindingSourcePentest) {
		// Pentest findings own their lifecycle and are never grouped.
		return "", "", false
	}
	if source == string(vulnerability.FindingSourceSecret) || strings.EqualFold(in.FindingType, "secret") ||
		in.SecretFingerprint != "" {
		fp := strings.ToLower(strings.TrimSpace(in.SecretFingerprint))
		if fp == "" || !isHex(fp) {
			return "", "", false
		}
		return KindRotate + ":secret:" + fp, secretTitle(in.SecretType, fp), true
	}
	if name := strings.TrimSpace(in.PackageName); name != "" && len(in.FixedVersions) > 0 {
		if target := vulnerability.RecommendedFixVersion(in.InstalledVersion, in.FixedVersions); target != "" {
			eco := strings.ToLower(strings.TrimSpace(in.Ecosystem))
			if eco == "" {
				eco = "other"
			}
			return KindUpgrade + ":" + keyPart(eco) + ":" + keyPart(name) + ":" + keyPart(target),
				clip("Upgrade "+name+" to "+target, maxTitle), true
		}
	}
	if spec, title := SpecificSolution(in.SolutionText); spec != "" {
		if source == "" {
			source = "unknown"
		}
		if ruleScopedSources[source] {
			rule := strings.ToLower(strings.TrimSpace(in.RuleID))
			if rule == "" {
				return "", "", false
			}
			spec = rule + "\x1f" + spec
		}
		sum := sha256.Sum256([]byte(spec))
		return KindSol + ":" + source + ":" + hex.EncodeToString(sum[:]), clip(title, maxTitle), true
	}
	return "", "", false
}

// ruleScopedSources are sources whose solution text is advice for one rule
// at one code or configuration location: the same advice under two rules is
// two different fixes.
var ruleScopedSources = map[string]bool{
	string(vulnerability.FindingSourceSAST):  true,
	string(vulnerability.FindingSourceIaC):   true,
	string(vulnerability.FindingSourceSARIF): true,
	string(vulnerability.FindingSourceCSPM):  true,
}

const maxTitle = 200

// keyPart lowercases one part of a key and keeps "/" out of it: a key travels
// as one URL path segment (/remediation-groups/{key}/resolve), so a package
// name with a slash (an npm scope, a Go module path) uses "~" instead.
func keyPart(s string) string {
	return strings.ReplaceAll(strings.ToLower(strings.TrimSpace(s)), "/", "~")
}

func secretTitle(secretType, fp string) string {
	short := fp
	if len(short) > 8 {
		short = short[:8]
	}
	kind := strings.TrimSpace(secretType)
	if kind == "" {
		return "Rotate the leaked secret " + short
	}
	return clip("Rotate the leaked "+kind+" secret "+short, maxTitle)
}

// minSolutionLen is the shortest normalized specific text that may form a
// group: shorter advice ("Upgrade", "Apply patch 1") says nothing specific.
const minSolutionLen = 16

var (
	urlPattern = regexp.MustCompile(`https?://\S+`)
	// A version ("2.17.1", "5.15"), a "to/version/v" followed by a number
	// ("to PHP 8" is not; "version 8" is), or an advisory or patch id.
	specificToken = regexp.MustCompile(`\d+\.\d+|\b(?:version|v)\s?\d+\b|` +
		`\b(?:cve-\d{4}-\d{4,}|ghsa(?:-[0-9a-z]{4}){3}|ms\d{2}-\d{3}|kb\d{6,}|rhsa-\d{4}:\d+|usn-\d+-\d+|dsa-\d+(?:-\d+)?|apsb\d{2}-\d{2})\b`)
	sentenceEnd = regexp.MustCompile(`[.;!?](?:\s+|$)|\n+`)
)

// SpecificSolution returns the concrete part of a solution text, normalized
// (the sentences that name a version or an advisory id, in order), and the
// first such sentence as written, for a title. Both are empty when the text
// is boilerplate that fits any finding: "Apply the suggested fix code.",
// "Follow the remediation steps", "Upgrade to the latest version".
func SpecificSolution(text string) (spec, title string) {
	sentences := splitSentences(text)
	parts := make([]string, 0, len(sentences))
	for _, raw := range sentences {
		n := normalize(raw)
		if n == "" || !specificToken.MatchString(urlPattern.ReplaceAllString(n, "")) {
			continue
		}
		if title == "" {
			title = strings.TrimSpace(raw)
		}
		parts = append(parts, n)
	}
	spec = strings.Join(parts, " ")
	if len(spec) < minSolutionLen {
		return "", ""
	}
	return spec, title
}

// splitSentences cuts a text at sentence ends and line breaks. A dot inside a
// version ("2.17.1") is not a sentence end: it is not followed by a space.
func splitSentences(text string) []string {
	var out []string
	last := 0
	for _, m := range sentenceEnd.FindAllStringIndex(text, -1) {
		// Keep the terminating punctuation with its sentence.
		end := m[0]
		if end < len(text) && text[end] != '\n' {
			end++
		}
		if s := strings.TrimSpace(text[last:end]); s != "" {
			out = append(out, s)
		}
		last = m[1]
	}
	if s := strings.TrimSpace(text[last:]); s != "" {
		out = append(out, s)
	}
	return out
}

func isHex(s string) bool {
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return s != ""
}

// normalize lowercases, trims, and collapses internal whitespace so trivially
// different renderings of the same fix map to one key.
func normalize(s string) string {
	return strings.ToLower(strings.Join(strings.Fields(s), " "))
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	// Cut on a rune boundary.
	for n > 0 && !utf8RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

func utf8RuneStart(b byte) bool { return b&0xC0 != 0x80 }
