package scan

// Secrets in scanner_config (RFC-032 Phase 0, G7).
//
// A scan's scanner_config is passed to the sensor verbatim inside the
// command, and it is stored in the scans and commands tables. A token,
// password or Authorization header typed into it therefore travels and rests
// in clear. Until sealed credentials (RFC-032 Phase 3) give such values a
// proper home, the platform warns when a value looks like a secret. It never
// blocks the save and never echoes the value.

import (
	"math"
	"regexp"
	"slices"
	"strconv"
	"strings"
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
		if reason, ok := secretReason(key, val); ok {
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
		strings.Contains(v, "://") || strings.Count(v, "/") > 2 {
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
