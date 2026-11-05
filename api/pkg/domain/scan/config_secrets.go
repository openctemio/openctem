package scan

// Secrets in scanner_config (RFC-032 Phase 0, G7).
//
// A scan's scanner_config is passed to the sensor inside the command, and it
// is stored in the scans and commands tables. A token, password or
// Authorization header typed into it would therefore travel and rest in
// clear. Secrets reach a sensor's tools only as task secrets
// (docs/architecture/task-secrets.md), so a value that is certainly a
// credential is refused (RefusedConfigSecrets): on scan create and update,
// and at trigger, before it is copied into a command. Values that only
// look random (high entropy) are warned about, never refused: identifiers
// and names reach that bar too. Neither path echoes the value.

import (
	"math"
	"net"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ConfigSecretWarning is one scanner_config value that looks like a secret.
type ConfigSecretWarning struct {
	// Path locates the value: dotted keys, [n] for list items
	// ("headers.Authorization", "args[2]").
	Path string `json:"path"`
	// Reason is why it was flagged.
	Reason ConfigSecretReason `json:"reason"`
}

// ConfigSecretReason says why a value was flagged.
type ConfigSecretReason string

// Reasons.
const (
	// SecretReasonKeyName: the key is named like a credential (password,
	// token, secret, api_key, authorization, ...).
	SecretReasonKeyName ConfigSecretReason = "key_name"
	// SecretReasonKnownFormat: the value has the shape of a known credential
	// (a bearer header, a private key block, a GitHub / GitLab / AWS / Slack
	// token, an OpenCTEM key).
	SecretReasonKnownFormat ConfigSecretReason = "known_format"
	// SecretReasonHighEntropy: a long random-looking string.
	SecretReasonHighEntropy ConfigSecretReason = "high_entropy"
)

// Detection limits.
const (
	maxSecretScanDepth    = 8
	maxSecretWarnings     = 20
	minEntropyValueLength = 24
	minEntropyBitsPerChar = 3.5
)

// secretKeyWords are key-name fragments that mean "this is a credential",
// matched on the key lowercased with '-', '_', '.' and spaces removed.
var secretKeyWords = []string{
	"password", "passwd", "passphrase", "pwd",
	"secret", "token", "apikey", "accesskey", "privatekey", "clientsecret",
	"authorization", "bearer", "cookie", "session", "credential", "signature",
}

// secretKeyExact are short names that only count when they are the whole key.
var secretKeyExact = []string{"pass", "pw", "key", "auth", "sig"}

// notSecretKeys are credential-looking names that are not credentials.
var notSecretKeys = []string{
	"maxtokens", "tokenlimit", "tokencount", "authtype", "authmethod", "authmode",
	"sessiontimeout", "sessionname", "cookiename", "keyfile", "tokenfile", "passwordfile",
	"secretfile", "credentialfile", "credentialsfile", "keyid", "secretname", "credentialid",
	"credentialname", "signaturetype", "signaturealgorithm", "keytype", "keysize", "keylength",
}

var (
	knownSecretFormats = []*regexp.Regexp{
		regexp.MustCompile(`(?i)\bbearer\s+[a-z0-9._~+/=-]{8,}`),
		regexp.MustCompile(`(?i)\bbasic\s+[a-z0-9+/=]{8,}`),
		regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`),
		regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}`),
		regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{30,}`),
		regexp.MustCompile(`\bglpat-[A-Za-z0-9_-]{20,}`),
		regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`),
		regexp.MustCompile(`\bxox[abprs]-[A-Za-z0-9-]{10,}`),
		regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{20,}`),
		regexp.MustCompile(`\b(?:rda|oct|ocse)_[A-Za-z0-9_]{20,}`),
		regexp.MustCompile(`://[^/\s:@]+:[^/\s@]+@`), // credentials in a URL
	}
	uuidPattern   = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	digestPattern = regexp.MustCompile(`^(?:sha256|sha512|sha1|md5):`)
)

// DetectConfigSecrets returns the scanner_config values that look like
// secrets, in a stable order. The values themselves are never returned.
func DetectConfigSecrets(cfg map[string]any) []ConfigSecretWarning {
	if len(cfg) == 0 {
		return nil
	}
	d := &secretDetector{}
	d.walkMap("", cfg, 0)
	slices.SortFunc(d.out, func(a, b ConfigSecretWarning) int { return strings.Compare(a.Path, b.Path) })
	if len(d.out) > maxSecretWarnings {
		d.out = d.out[:maxSecretWarnings]
	}
	return d.out
}

type secretDetector struct {
	out []ConfigSecretWarning
	// refuse keeps only the values RefusedConfigSecrets refuses.
	refuse bool
}

// RefusedConfigSecrets returns the scanner_config values that are
// credentials beyond doubt, in a stable order, without the values: a known
// credential format (a bearer or basic header, a private key block, a
// provider token, credentials in a URL), or a value under a credential key
// name ("password", "api_key", "authorization", ...) unless the value is a
// plain setting word ("basic", "bearer", "none"), which such keys also hold
// to name a mode. High-entropy values are not refused.
func RefusedConfigSecrets(cfg map[string]any) []ConfigSecretWarning {
	if len(cfg) == 0 {
		return nil
	}
	d := &secretDetector{refuse: true}
	d.walkMap("", cfg, 0)
	slices.SortFunc(d.out, func(a, b ConfigSecretWarning) int { return strings.Compare(a.Path, b.Path) })
	if len(d.out) > maxSecretWarnings {
		d.out = d.out[:maxSecretWarnings]
	}
	return d.out
}

// settingWord is a value a credential-named key holds to name a mode
// ("auth": "basic"), not a credential: one lower-case word of letters.
var settingWord = regexp.MustCompile(`^[a-z][a-z_-]{0,15}$`)

// refused reports whether a flagged value is refused, not only warned
// about.
func refused(reason ConfigSecretReason, value string) bool {
	switch reason {
	case SecretReasonKnownFormat:
		return true
	case SecretReasonKeyName:
		return !settingWord.MatchString(strings.TrimSpace(value))
	}
	return false
}

func (d *secretDetector) walkMap(prefix string, m map[string]any, depth int) {
	if depth > maxSecretScanDepth {
		return
	}
	for k, v := range m {
		path := k
		if prefix != "" {
			path = prefix + "." + k
		}
		d.walk(path, k, v, depth+1)
	}
}

func (d *secretDetector) walk(path, key string, v any, depth int) {
	switch val := v.(type) {
	case map[string]any:
		d.walkMap(path, val, depth)
	case []any:
		if depth > maxSecretScanDepth {
			return
		}
		for i, item := range val {
			d.walk(path+"["+strconv.Itoa(i)+"]", key, item, depth+1)
		}
	case []string:
		for i, item := range val {
			d.walk(path+"["+strconv.Itoa(i)+"]", key, item, depth+1)
		}
	case string:
		if reason, ok := secretReason(key, val); ok && (!d.refuse || refused(reason, val)) {
			d.out = append(d.out, ConfigSecretWarning{Path: path, Reason: reason})
		}
	}
}

// secretReason classifies one string value under its key.
func secretReason(key, value string) (ConfigSecretReason, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", false
	}
	for _, re := range knownSecretFormats {
		if re.MatchString(value) {
			return SecretReasonKnownFormat, true
		}
	}
	if isTargetKey(key) {
		// A target list holds host names, addresses and URLs, which the
		// scope gate checks; only a credential format (a URL with a user
		// and password in it) counts as a secret there.
		return "", false
	}
	if isSecretKeyName(key) && !isPlaceholder(value) {
		return SecretReasonKeyName, true
	}
	if looksHighEntropy(value) {
		return SecretReasonHighEntropy, true
	}
	return "", false
}

// isSecretKeyName reports whether a key is named like a credential.
func isSecretKeyName(key string) bool {
	norm := strings.Map(func(r rune) rune {
		switch r {
		case '-', '_', '.', ' ':
			return -1
		}
		return r
	}, strings.ToLower(key))
	if norm == "" || slices.Contains(notSecretKeys, norm) {
		return false
	}
	if slices.Contains(secretKeyExact, norm) {
		return true
	}
	for _, w := range secretKeyWords {
		if strings.Contains(norm, w) {
			return true
		}
	}
	return false
}

// isPlaceholder reports values that are clearly not a secret: references to
// one stored elsewhere (${VAR}, {{ .x }}, env:NAME, file paths) and booleans.
func isPlaceholder(v string) bool {
	lv := strings.ToLower(v)
	switch lv {
	case "true", "false", "none", "null", "yes", "no", "on", "off":
		return true
	}
	return strings.HasPrefix(v, "${") || strings.HasPrefix(v, "{{") ||
		strings.HasPrefix(lv, "env:") || strings.HasPrefix(lv, "file:") ||
		strings.HasPrefix(v, "/") || strings.HasPrefix(v, "./")
}

// looksHighEntropy reports long, random-looking strings: no spaces, at least
// two character classes and a Shannon entropy that ordinary words, paths and
// URLs do not reach. UUIDs and content digests are identifiers, not secrets.
func looksHighEntropy(v string) bool {
	if len(v) < minEntropyValueLength || strings.ContainsAny(v, " \t\n") {
		return false
	}
	if uuidPattern.MatchString(v) || digestPattern.MatchString(v) ||
		strings.Contains(v, "://") || strings.Count(v, "/") > 2 || isHostOrAddress(v) {
		return false
	}
	var lower, upper, digit bool
	for _, r := range v {
		switch {
		case r >= 'a' && r <= 'z':
			lower = true
		case r >= 'A' && r <= 'Z':
			upper = true
		case r >= '0' && r <= '9':
			digit = true
		}
	}
	classes := 0
	for _, c := range []bool{lower, upper, digit} {
		if c {
			classes++
		}
	}
	if classes < 2 {
		return false
	}
	return shannonBitsPerChar(v) >= minEntropyBitsPerChar
}

// targetKeys name the keys that carry a job's targets.
var targetKeys = []string{"target", "targets"}

// isTargetKey reports whether key carries a job's targets.
func isTargetKey(key string) bool {
	return slices.Contains(targetKeys, strings.ToLower(strings.TrimSpace(key)))
}

// isHostOrAddress reports whether v is an IP address, a CIDR range or a DNS
// host name: at least two labels of letters, digits and hyphens (63 at
// most, no hyphen at either end), an optional leading "*." and a last label
// of letters only. A long host name ("static-01.example-group.com.vn") has
// the entropy of a token but is not one; a token has no letters-only last
// label after a dot.
func isHostOrAddress(v string) bool {
	if net.ParseIP(v) != nil {
		return true
	}
	if _, _, err := net.ParseCIDR(v); err == nil {
		return true
	}
	name := strings.TrimSuffix(strings.TrimPrefix(strings.ToLower(v), "*."), ".")
	labels := strings.Split(name, ".")
	if len(name) > 253 || len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for _, r := range l {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return false
			}
		}
	}
	tld := labels[len(labels)-1]
	if len(tld) < 2 {
		return false
	}
	for _, r := range tld {
		if r < 'a' || r > 'z' {
			return false
		}
	}
	return true
}

func shannonBitsPerChar(s string) float64 {
	counts := map[rune]int{}
	n := 0
	for _, r := range s {
		counts[r]++
		n++
	}
	var h float64
	for _, c := range counts {
		p := float64(c) / float64(n)
		h -= p * math.Log2(p)
	}
	return h
}

// CodeScannerConfigSecret refuses a scanner_config that holds a credential
// (on save), and blocks a run of a scan whose stored scanner_config still
// holds one (at trigger): the value is never copied into a command.
const CodeScannerConfigSecret = "SCANNER_CONFIG_SECRET"

// RefuseConfigSecrets is the validation error for a scanner_config that
// RefusedConfigSecrets flags, naming the keys only; nil when none.
func RefuseConfigSecrets(cfg map[string]any) error {
	found := RefusedConfigSecrets(cfg)
	if len(found) == 0 {
		return nil
	}
	paths := make([]string, 0, len(found))
	for _, f := range found {
		paths = append(paths, f.Path)
	}
	return shared.NewDomainError(CodeScannerConfigSecret,
		"the scan settings hold a credential at "+strings.Join(paths, ", ")+
			": remove it; credentials reach scan tools only as organization keys or sensor-local values, never in scan settings",
		shared.ErrValidation)
}
