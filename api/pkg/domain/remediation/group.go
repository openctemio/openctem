package remediation

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"unicode"

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
}

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
//  3. A specific solution text: "sol:<source>:<sha256>", only when the text
//     names something concrete (a version or an id) and is not generic advice.
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
	if s := normalize(in.SolutionText); specificSolution(s) {
		if source == "" {
			source = "unknown"
		}
		sum := sha256.Sum256([]byte(s))
		return KindSol + ":" + source + ":" + hex.EncodeToString(sum[:]), firstLine(in.SolutionText), true
	}
	return "", "", false
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

// minSolutionLen is the shortest normalized solution text that may form a
// group: shorter advice ("Upgrade", "Apply patch") says nothing specific.
const minSolutionLen = 16

// genericSolutions are advice texts that fit any finding; grouping by them
// would put unrelated findings under one fix.
var genericSolutions = map[string]bool{
	"upgrade to the latest version":                 true,
	"update to the latest version":                  true,
	"upgrade to the latest version of the package":  true,
	"apply the latest security patches":             true,
	"apply the vendor patch":                        true,
	"apply vendor patches":                          true,
	"rotate the secret":                             true,
	"rotate the secret and remove it from the code": true,
	"remove the secret from the code":               true,
	"no solution available":                         true,
	"n/a":                                           true,
}

// specificSolution reports whether a normalized solution text is concrete
// enough to group by: long enough, not generic advice, and naming a version
// or an identifier (it contains a digit).
func specificSolution(s string) bool {
	if len(s) < minSolutionLen || genericSolutions[strings.TrimRight(s, ".")] {
		return false
	}
	return strings.IndexFunc(s, unicode.IsDigit) >= 0
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

// firstLine returns a compact, single-line title from possibly multi-line text.
func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	return clip(s, maxTitle)
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
