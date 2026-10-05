package sensor

// The sensor config report: the results of the preflight checks a sensor
// runs on itself (settings, state volume, tools, TLS trust, local policy),
// sent with PUT /api/v2/sensor/config-report and summarized on every
// heartbeat. Design: research/26 (sensor config doctor), linked from
// docs/rfcs/RFC-033-sensor-manifest.md "Config report".
//
// Everything in a report is an untrusted claim. SanitizeConfigReport reduces
// it to closed sets, typed and re-validated parameters, and bounded plain
// text before anything is stored; unknown members are dropped and listed,
// never an error. A settings entry keeps only name/set/source/secret/valid:
// a value the sensor sends anyway is dropped and never stored. The platform
// recomputes the health from the checks and never trusts the sensor's own
// config_health. Fix instructions come only from the platform catalog
// (internal/app/sensor/config_check_catalog.go), never from the report.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// ConfigReportSchema is the report schema this platform reads.
const ConfigReportSchema = 1

// Limits on a config report.
const (
	// MaxConfigReportBytes caps the request body (protov2.MaxConfigReportBytes).
	MaxConfigReportBytes = 64 << 10
	// MaxConfigReportDepth is the deepest nesting a report may have
	// (document > checks > check > params > param > names).
	MaxConfigReportDepth = 6
	MaxConfigChecks      = 200
	MaxConfigSettings    = 300
	MaxConfigParams      = 16
	MaxConfigKeys        = 8
	MaxConfigBlocks      = 8
	MaxConfigParamNames  = 8
	// MaxConfigSummaryRunes caps a check's summary after stripping.
	MaxConfigSummaryRunes = 300
	// MaxConfigExcerptBytes caps a check's excerpt after stripping.
	MaxConfigExcerptBytes = 512
	// MaxConfigReportIgnored bounds the ignored items returned.
	MaxConfigReportIgnored = 100

	maxConfigCheckIDLen   = 96
	maxConfigParamPathLen = 256
	maxConfigParamHostLen = 253
	maxConfigParamInt     = 1_000_000_000_000
	maxConfigIgnoredValue = 64
)

// Errors of SanitizeConfigReport.
var (
	// ErrConfigReportTooLarge: the body is above MaxConfigReportBytes (413).
	ErrConfigReportTooLarge = errors.New("config report too large")
	// ErrConfigReportMalformed: not JSON, or nested deeper than
	// MaxConfigReportDepth (400 invalid-request).
	ErrConfigReportMalformed = errors.New("config report malformed")
	// ErrConfigReportInvalid: not an object with schema 1 and a checks
	// array (422 config-report-invalid).
	ErrConfigReportInvalid = errors.New("config report invalid")
)

// Check statuses.
const (
	CheckPass  = "pass"
	CheckWarn  = "warn"
	CheckFail  = "fail"
	CheckSkip  = "skip"
	CheckError = "error"
)

// Check severities.
const (
	CheckSeverityInfo     = "info"
	CheckSeverityWarning  = "warning"
	CheckSeverityCritical = "critical"
)

// Config health values (the platform's rollup, ConfigHealthOf).
const (
	ConfigHealthOK        = "ok"
	ConfigHealthAttention = "attention"
	ConfigHealthImpaired  = "impaired"
	ConfigHealthBlocked   = "blocked"
	// ConfigHealthUnknown: no report, or a stale one.
	ConfigHealthUnknown = "unknown"
)

// Ignored reasons of a config report.
const (
	ConfigIgnoredUnknownMember = "unknown-member"
	ConfigIgnoredInvalidValue  = "invalid-value"
	ConfigIgnoredLimit         = "limit"
	ConfigIgnoredDuplicate     = "duplicate"
)

var (
	configStatuses   = []string{CheckPass, CheckWarn, CheckFail, CheckSkip, CheckError}
	configSeverities = []string{CheckSeverityInfo, CheckSeverityWarning, CheckSeverityCritical}
	configHealths    = []string{ConfigHealthOK, ConfigHealthAttention, ConfigHealthImpaired, ConfigHealthBlocked}
	configTriggers   = []string{"start", "change", "requested"}
	configRuntimes   = []string{"docker", "kubernetes", "systemd", "binary", "unknown"}
	configSources    = []string{"env", "option", "default", "unset"}
	configFixedBlock = []string{"role:*", "role:scan", "target:private", "feature:custom_templates"}

	configCheckIDRE  = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z0-9_-]+){1,3}$`)
	configCodeRE     = regexp.MustCompile(`^[a-z][a-z0-9_]{0,47}$`)
	configParamKeyRE = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	configEnumRE     = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,31}$`)
	configVersionRE  = regexp.MustCompile(`^v?[0-9A-Za-z.+-]{1,64}$`)
	configNameRE     = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,64}$`)
	configHostRE     = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,62})(\.[A-Za-z0-9]([A-Za-z0-9-]{0,62}))*\.?$`)
	configDigestRE   = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// ConfigReport is a sanitized config report (schema 1).
type ConfigReport struct {
	Schema int `json:"schema"`
	// ObservedAt is when the sensor ran the checks (RFC 3339, UTC); "" when
	// it sent none or an invalid one.
	ObservedAt string        `json:"observed_at"`
	Trigger    string        `json:"trigger"`
	Runtime    ConfigRuntime `json:"runtime"`
	// SensorHealth is the sensor's own rollup ("config_health"). Kept for
	// display only: the platform recomputes Health.
	SensorHealth string          `json:"config_health"`
	Checks       []ConfigCheck   `json:"checks"`
	Settings     []ConfigSetting `json:"settings"`
	Truncated    bool            `json:"truncated"`
}

// ConfigRuntime is how the sensor runs.
type ConfigRuntime struct {
	Kind string `json:"kind"`
}

// ConfigCheck is one check result.
type ConfigCheck struct {
	ID       string                 `json:"id"`
	Status   string                 `json:"status"`
	Severity string                 `json:"severity"`
	Code     string                 `json:"code"`
	Params   map[string]ConfigParam `json:"params"`
	Keys     []string               `json:"keys"`
	// Summary and Excerpt are sensor text: data, rendered only as text.
	Summary string   `json:"summary"`
	Excerpt string   `json:"excerpt"`
	Blocks  []string `json:"blocks"`
}

// ConfigParam is one typed parameter: exactly one member is set.
type ConfigParam struct {
	Int     *int64   `json:"int,omitempty"`
	Bool    *bool    `json:"bool,omitempty"`
	Enum    string   `json:"enum,omitempty"`
	Path    string   `json:"path,omitempty"`
	Host    string   `json:"host,omitempty"`
	Version string   `json:"version,omitempty"`
	Name    string   `json:"name,omitempty"`
	Names   []string `json:"names,omitempty"`
}

// Text is the parameter as plain text (names joined with ", ").
func (p ConfigParam) Text() string {
	switch {
	case p.Int != nil:
		return strconv.FormatInt(*p.Int, 10)
	case p.Bool != nil:
		return strconv.FormatBool(*p.Bool)
	case p.Names != nil:
		return strings.Join(p.Names, ", ")
	}
	for _, v := range []string{p.Enum, p.Path, p.Host, p.Version, p.Name} {
		if v != "" {
			return v
		}
	}
	return ""
}

// ConfigSetting is one declared setting: whether it is set and where from.
// It never carries a value.
type ConfigSetting struct {
	Name   string `json:"name"`
	Set    bool   `json:"set"`
	Source string `json:"source"`
	Secret bool   `json:"secret"`
	Valid  bool   `json:"valid"`
}

// ConfigIgnored is one report item the platform dropped.
type ConfigIgnored struct {
	Path   string `json:"path"`
	Value  string `json:"value,omitempty"`
	Reason string `json:"reason"`
}

type configSanitizer struct {
	ignored []ConfigIgnored
}

func (s *configSanitizer) ignore(path, value, reason string) {
	if len(s.ignored) < MaxConfigReportIgnored {
		s.ignored = append(s.ignored, ConfigIgnored{Path: path, Value: ignoredValue(value), Reason: reason})
	}
}

// ignoredValue bounds a value echoed in an ignored item: plain text only,
// at most maxConfigIgnoredValue runes.
func ignoredValue(v string) string {
	return stripText(v, maxConfigIgnoredValue, false)
}

// SanitizeConfigReport parses a raw config report and returns it reduced to
// safe, bounded values, with what was dropped. ErrConfigReportTooLarge,
// ErrConfigReportMalformed and ErrConfigReportInvalid refuse the whole
// document; everything else drops the offending item only.
func SanitizeConfigReport(raw []byte) (*ConfigReport, []ConfigIgnored, error) {
	if len(raw) > MaxConfigReportBytes {
		return nil, nil, ErrConfigReportTooLarge
	}
	if err := checkJSONDepth(raw, MaxConfigReportDepth); err != nil {
		return nil, nil, err
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil || members == nil {
		return nil, nil, fmt.Errorf("%w: not a JSON object", ErrConfigReportInvalid)
	}
	var schema int
	if err := json.Unmarshal(members["schema"], &schema); err != nil || schema != ConfigReportSchema {
		return nil, nil, fmt.Errorf("%w: schema must be %d", ErrConfigReportInvalid, ConfigReportSchema)
	}
	var checks []json.RawMessage
	if err := json.Unmarshal(members["checks"], &checks); err != nil || checks == nil {
		return nil, nil, fmt.Errorf("%w: checks must be an array", ErrConfigReportInvalid)
	}

	s := &configSanitizer{}
	out := &ConfigReport{Schema: ConfigReportSchema, Runtime: ConfigRuntime{Kind: "unknown"},
		Checks: []ConfigCheck{}, Settings: []ConfigSetting{}}
	for _, k := range sortedMemberNames(members) {
		v := members[k]
		switch k {
		case "schema", "checks":
		case "observed_at":
			out.ObservedAt = s.timestamp(k, v)
		case "trigger":
			out.Trigger = s.closed(k, v, configTriggers)
		case "config_health":
			out.SensorHealth = s.closed(k, v, configHealths)
		case "truncated":
			if json.Unmarshal(v, &out.Truncated) != nil {
				s.ignore(k, "", ConfigIgnoredInvalidValue)
			}
		case "runtime":
			out.Runtime = s.runtime(v)
		case "settings":
			out.Settings = s.settings(v)
		default:
			s.ignore(stripText(k, maxConfigIgnoredValue, false), "", ConfigIgnoredUnknownMember)
		}
	}
	out.Checks = s.checks(checks)
	return out, s.ignored, nil
}

// checkJSONDepth refuses a document that is not one JSON value or that
// nests arrays and objects deeper than limit.
func checkJSONDepth(raw []byte, limit int) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	depth := 0
	seen := false
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("%w: %w", ErrConfigReportMalformed, err)
		}
		if depth == 0 && seen {
			return fmt.Errorf("%w: trailing data", ErrConfigReportMalformed)
		}
		seen = true
		if d, ok := tok.(json.Delim); ok {
			switch d {
			case '{', '[':
				depth++
				if depth > limit {
					return fmt.Errorf("%w: nested deeper than %d", ErrConfigReportMalformed, limit)
				}
			default:
				depth--
			}
		}
	}
	if !seen {
		return fmt.Errorf("%w: empty", ErrConfigReportMalformed)
	}
	return nil
}

func (s *configSanitizer) str(path string, v json.RawMessage) (string, bool) {
	var out string
	if err := json.Unmarshal(v, &out); err != nil {
		s.ignore(path, "", ConfigIgnoredInvalidValue)
		return "", false
	}
	return out, true
}

func (s *configSanitizer) closed(path string, v json.RawMessage, set []string) string {
	val, ok := s.str(path, v)
	if !ok {
		return ""
	}
	if !slices.Contains(set, val) {
		s.ignore(path, val, ConfigIgnoredInvalidValue)
		return ""
	}
	return val
}

func (s *configSanitizer) timestamp(path string, v json.RawMessage) string {
	val, ok := s.str(path, v)
	if !ok || val == "" {
		return ""
	}
	t, err := time.Parse(time.RFC3339, val)
	if err != nil {
		s.ignore(path, val, ConfigIgnoredInvalidValue)
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func (s *configSanitizer) runtime(v json.RawMessage) ConfigRuntime {
	out := ConfigRuntime{Kind: "unknown"}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(v, &m); err != nil {
		s.ignore("runtime", "", ConfigIgnoredInvalidValue)
		return out
	}
	for _, k := range sortedMemberNames(m) {
		if k != "kind" {
			s.ignore("runtime."+stripText(k, maxConfigIgnoredValue, false), "", ConfigIgnoredUnknownMember)
			continue
		}
		if kind := s.closed("runtime.kind", m[k], configRuntimes); kind != "" {
			out.Kind = kind
		}
	}
	return out
}

func (s *configSanitizer) settings(v json.RawMessage) []ConfigSetting {
	out := []ConfigSetting{}
	var items []json.RawMessage
	if err := json.Unmarshal(v, &items); err != nil {
		s.ignore("settings", "", ConfigIgnoredInvalidValue)
		return out
	}
	seen := map[string]bool{}
	for i, item := range items {
		path := fmt.Sprintf("settings[%d]", i)
		if len(out) == MaxConfigSettings {
			s.ignore(fmt.Sprintf("settings[%d:]", i), strconv.Itoa(len(items)-i), ConfigIgnoredLimit)
			break
		}
		var m map[string]json.RawMessage
		if err := json.Unmarshal(item, &m); err != nil {
			s.ignore(path, "", ConfigIgnoredInvalidValue)
			continue
		}
		var st ConfigSetting
		valid := true
		for _, k := range sortedMemberNames(m) {
			kp := path + "." + stripText(k, maxConfigIgnoredValue, false)
			switch k {
			case "name":
				// The name is shown back only when it is a well-formed name.
				name, _ := s.str(kp, m[k])
				if !configNameRE.MatchString(name) {
					s.ignore(kp, "", ConfigIgnoredInvalidValue)
					valid = false
				}
				st.Name = name
			case "source":
				st.Source = s.closed(kp, m[k], configSources)
			case "set", "secret", "valid":
				var b bool
				if json.Unmarshal(m[k], &b) != nil {
					s.ignore(kp, "", ConfigIgnoredInvalidValue)
					continue
				}
				switch k {
				case "set":
					st.Set = b
				case "secret":
					st.Secret = b
				default:
					st.Valid = b
				}
			default:
				// Any other member (a "value" above all) is dropped
				// unread: no value of a setting is ever stored or echoed.
				s.ignore(kp, "", ConfigIgnoredUnknownMember)
			}
		}
		if !valid || st.Name == "" {
			continue
		}
		if st.Source == "" {
			st.Source = "unset"
			if st.Set {
				st.Source = "env"
			}
		}
		if seen[st.Name] {
			s.ignore(path, st.Name, ConfigIgnoredDuplicate)
			continue
		}
		seen[st.Name] = true
		out = append(out, st)
	}
	return out
}

func (s *configSanitizer) checks(items []json.RawMessage) []ConfigCheck {
	out := []ConfigCheck{}
	seen := map[string]bool{}
	for i, item := range items {
		if len(out) == MaxConfigChecks {
			s.ignore(fmt.Sprintf("checks[%d:]", i), strconv.Itoa(len(items)-i), ConfigIgnoredLimit)
			break
		}
		c, ok := s.check(fmt.Sprintf("checks[%d]", i), item)
		if !ok {
			continue
		}
		key := c.uniqueKey()
		if seen[key] {
			s.ignore(fmt.Sprintf("checks[%d]", i), c.ID, ConfigIgnoredDuplicate)
			continue
		}
		seen[key] = true
		out = append(out, c)
	}
	return out
}

// uniqueKey is (id, canonical params): several results may share an id.
func (c ConfigCheck) uniqueKey() string {
	p, _ := json.Marshal(c.Params) // map keys are sorted
	return c.ID + "\x00" + string(p)
}

func (s *configSanitizer) check(path string, raw json.RawMessage) (ConfigCheck, bool) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		s.ignore(path, "", ConfigIgnoredInvalidValue)
		return ConfigCheck{}, false
	}
	c := ConfigCheck{Params: map[string]ConfigParam{}, Keys: []string{}, Blocks: []string{}}
	id, _ := s.str(path+".id", m["id"])
	if len(id) > maxConfigCheckIDLen || !configCheckIDRE.MatchString(id) {
		s.ignore(path+".id", id, ConfigIgnoredInvalidValue)
		return ConfigCheck{}, false
	}
	c.ID = id
	status, _ := s.str(path+".status", m["status"])
	if !slices.Contains(configStatuses, status) {
		s.ignore(path+".status", status, ConfigIgnoredInvalidValue)
		return ConfigCheck{}, false
	}
	c.Status = status
	for _, k := range sortedMemberNames(m) {
		kp := path + "." + stripText(k, maxConfigIgnoredValue, false)
		v := m[k]
		switch k {
		case "id", "status":
		case "severity":
			c.Severity = s.closed(kp, v, configSeverities)
		case "code":
			if code, ok := s.str(kp, v); ok {
				if configCodeRE.MatchString(code) {
					c.Code = code
				} else if code != "" {
					s.ignore(kp, code, ConfigIgnoredInvalidValue)
				}
			}
		case "params":
			c.Params = s.params(kp, v)
		case "keys":
			c.Keys = s.names(kp, v, MaxConfigKeys)
		case "summary":
			if t, ok := s.str(kp, v); ok {
				c.Summary = stripText(t, MaxConfigSummaryRunes, false)
			}
		case "excerpt":
			if t, ok := s.str(kp, v); ok {
				c.Excerpt = capBytes(stripText(t, MaxConfigExcerptBytes, true), MaxConfigExcerptBytes)
			}
		case "blocks":
			c.Blocks = s.blocks(kp, v)
		default:
			s.ignore(kp, "", ConfigIgnoredUnknownMember)
		}
	}
	if c.Severity == "" {
		c.Severity = defaultSeverity(c.Status)
	}
	return c, true
}

func defaultSeverity(status string) string {
	switch status {
	case CheckFail, CheckError:
		return CheckSeverityCritical
	case CheckWarn:
		return CheckSeverityWarning
	}
	return CheckSeverityInfo
}

func (s *configSanitizer) names(path string, v json.RawMessage, limit int) []string {
	out := []string{}
	var items []json.RawMessage
	if err := json.Unmarshal(v, &items); err != nil {
		s.ignore(path, "", ConfigIgnoredInvalidValue)
		return out
	}
	for i, item := range items {
		if len(out) == limit {
			s.ignore(fmt.Sprintf("%s[%d:]", path, i), strconv.Itoa(len(items)-i), ConfigIgnoredLimit)
			break
		}
		var n string
		if json.Unmarshal(item, &n) != nil || !configNameRE.MatchString(n) {
			s.ignore(fmt.Sprintf("%s[%d]", path, i), "", ConfigIgnoredInvalidValue)
			continue
		}
		if !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	return out
}

func (s *configSanitizer) blocks(path string, v json.RawMessage) []string {
	out := []string{}
	var items []json.RawMessage
	if err := json.Unmarshal(v, &items); err != nil {
		s.ignore(path, "", ConfigIgnoredInvalidValue)
		return out
	}
	for i, item := range items {
		if len(out) == MaxConfigBlocks {
			s.ignore(fmt.Sprintf("%s[%d:]", path, i), strconv.Itoa(len(items)-i), ConfigIgnoredLimit)
			break
		}
		var b string
		_ = json.Unmarshal(item, &b)
		if !validBlock(b) {
			s.ignore(fmt.Sprintf("%s[%d]", path, i), b, ConfigIgnoredInvalidValue)
			continue
		}
		if !slices.Contains(out, b) {
			out = append(out, b)
		}
	}
	return out
}

func validBlock(b string) bool {
	if slices.Contains(configFixedBlock, b) {
		return true
	}
	name, ok := strings.CutPrefix(b, "tool:")
	return ok && configNameRE.MatchString(name)
}

func (s *configSanitizer) params(path string, v json.RawMessage) map[string]ConfigParam {
	out := map[string]ConfigParam{}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(v, &m); err != nil {
		s.ignore(path, "", ConfigIgnoredInvalidValue)
		return out
	}
	for _, k := range sortedMemberNames(m) {
		kp := path + "." + stripText(k, maxConfigIgnoredValue, false)
		if !configParamKeyRE.MatchString(k) {
			s.ignore(kp, "", ConfigIgnoredInvalidValue)
			continue
		}
		if len(out) == MaxConfigParams {
			s.ignore(kp, "", ConfigIgnoredLimit)
			continue
		}
		p, ok := parseConfigParam(m[k])
		if !ok {
			// The value is not echoed: it failed validation, so it may be
			// anything (a secret pasted into the wrong place included).
			s.ignore(kp, "", ConfigIgnoredInvalidValue)
			continue
		}
		out[k] = p
	}
	return out
}

// parseConfigParam reads a typed parameter: an object with exactly one
// known member whose value passes its type's rule.
func parseConfigParam(raw json.RawMessage) (ConfigParam, bool) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil || len(m) != 1 {
		return ConfigParam{}, false
	}
	var p ConfigParam
	for k, v := range m {
		switch k {
		case "int":
			var n int64
			if json.Unmarshal(v, &n) != nil || n > maxConfigParamInt || n < -maxConfigParamInt {
				return p, false
			}
			p.Int = &n
		case "bool":
			var b bool
			if json.Unmarshal(v, &b) != nil {
				return p, false
			}
			p.Bool = &b
		case "names":
			var names []string
			if json.Unmarshal(v, &names) != nil || len(names) == 0 || len(names) > MaxConfigParamNames {
				return p, false
			}
			for _, n := range names {
				if !configNameRE.MatchString(n) {
					return p, false
				}
			}
			p.Names = names
		default:
			var str string
			if json.Unmarshal(v, &str) != nil {
				return p, false
			}
			switch {
			case k == "enum" && configEnumRE.MatchString(str):
				p.Enum = str
			case k == "path" && validParamPath(str):
				p.Path = str
			case k == "host" && validParamHost(str):
				p.Host = str
			case k == "version" && configVersionRE.MatchString(str):
				p.Version = str
			case k == "name" && configNameRE.MatchString(str):
				p.Name = str
			default:
				return p, false
			}
		}
	}
	return p, true
}

// validParamPath: absolute, at most 256 bytes, no control or bidi
// characters, no ".." segment.
func validParamPath(p string) bool {
	if p == "" || len(p) > maxConfigParamPathLen || !strings.HasPrefix(p, "/") || !utf8.ValidString(p) {
		return false
	}
	for _, r := range p {
		if unsafeRune(r) {
			return false
		}
	}
	return !slices.Contains(strings.Split(p, "/"), "..")
}

// validParamHost: a host name or an IP address; no scheme, user info or
// port.
func validParamHost(h string) bool {
	if h == "" || len(h) > maxConfigParamHostLen {
		return false
	}
	if net.ParseIP(h) != nil {
		return true
	}
	return configHostRE.MatchString(h)
}

// unsafeRune reports control characters (C0, DEL, C1) and bidi controls.
func unsafeRune(r rune) bool {
	return r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) || (r >= 0x200e && r <= 0x200f) ||
		(r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) || r == 0x061c || r == utf8.RuneError
}

// stripText replaces control and bidi characters with a space (keeping
// newlines and tabs when multiline) and keeps at most limit runes.
func stripText(v string, limit int, multiline bool) string {
	var b strings.Builder
	n := 0
	for _, r := range v {
		if n == limit {
			break
		}
		if unsafeRune(r) && !(multiline && (r == '\n' || r == '\t')) {
			r = ' '
		}
		b.WriteRune(r)
		n++
	}
	if multiline {
		return strings.TrimRight(b.String(), " \n\t")
	}
	return strings.TrimSpace(b.String())
}

// capBytes cuts s to at most n bytes on a rune boundary.
func capBytes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

// Digest is the report's digest: ManifestDigest's canonical form of the
// report with observed_at emptied, so running the same checks again does
// not change it.
func (r *ConfigReport) Digest() (string, error) {
	c := *r
	c.ObservedAt = ""
	raw, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("encode config report: %w", err)
	}
	return ManifestDigest(raw)
}

// ConfigCounts counts checks by status.
type ConfigCounts struct {
	Pass  int `json:"pass"`
	Warn  int `json:"warn"`
	Fail  int `json:"fail"`
	Skip  int `json:"skip"`
	Error int `json:"error"`
}

// CountChecks counts checks by status.
func CountChecks(checks []ConfigCheck) ConfigCounts {
	var c ConfigCounts
	for _, ch := range checks {
		switch ch.Status {
		case CheckPass:
			c.Pass++
		case CheckWarn:
			c.Warn++
		case CheckFail:
			c.Fail++
		case CheckSkip:
			c.Skip++
		case CheckError:
			c.Error++
		}
	}
	return c
}

// ConfigHealthOf is the platform's rollup of checks: blocked when a fail
// blocks every role, impaired on any other fail or error, attention on a
// warn of severity warning or critical, ok otherwise.
func ConfigHealthOf(checks []ConfigCheck) string {
	health := ConfigHealthOK
	for _, c := range checks {
		switch {
		case c.Status == CheckFail && slices.Contains(c.Blocks, "role:*"):
			return ConfigHealthBlocked
		case c.Status == CheckFail || c.Status == CheckError:
			health = ConfigHealthImpaired
		case c.Status == CheckWarn && c.Severity != CheckSeverityInfo && health == ConfigHealthOK:
			health = ConfigHealthAttention
		}
	}
	return health
}

// ConfigReportSummary is the heartbeat's "config_report" member.
type ConfigReportSummary struct {
	Digest     string `json:"digest"`
	Health     string `json:"health,omitempty"`
	Fail       int    `json:"fail,omitempty"`
	Warn       int    `json:"warn,omitempty"`
	ObservedAt string `json:"observed_at,omitempty"`
}

// ParseConfigReportSummary reads a heartbeat's config_report member
// leniently: nil when absent or not an object; a member of the wrong type
// is left at its zero value.
func ParseConfigReportSummary(raw json.RawMessage) *ConfigReportSummary {
	var m map[string]json.RawMessage
	if len(raw) == 0 || json.Unmarshal(raw, &m) != nil || m == nil {
		return nil
	}
	var s ConfigReportSummary
	_ = json.Unmarshal(m["digest"], &s.Digest)
	_ = json.Unmarshal(m["health"], &s.Health)
	_ = json.Unmarshal(m["fail"], &s.Fail)
	_ = json.Unmarshal(m["warn"], &s.Warn)
	_ = json.Unmarshal(m["observed_at"], &s.ObservedAt)
	if !slices.Contains(configHealths, s.Health) {
		s.Health = ""
	}
	s.Fail, s.Warn = max(0, min(s.Fail, MaxConfigChecks)), max(0, min(s.Warn, MaxConfigChecks))
	s.ObservedAt = stripText(s.ObservedAt, 40, false)
	return &s
}

// HeartbeatConfigDigest is the digest a heartbeat's config_report echoes,
// "" when it carried none or a malformed one.
func HeartbeatConfigDigest(s *ConfigReportSummary) string {
	if s == nil {
		return ""
	}
	if d := strings.TrimSpace(s.Digest); configDigestRE.MatchString(d) {
		return d
	}
	return ""
}

// StoredConfigReport is the latest report of a sensor as stored.
type StoredConfigReport struct {
	Report     ConfigReport
	Digest     string
	Health     string
	ReceivedAt time.Time
}

// ConfigReportStale reports whether the stored report no longer describes
// the sensor: its latest heartbeat echoed another digest, or none.
func (a *Sensor) ConfigReportStale() bool {
	return a.ConfigReportDigest != "" && a.ConfigHeartbeatDigest != a.ConfigReportDigest
}

// configReasons are the health reasons of a fresh report.
func (a *Sensor) configReasons() []HealthReason {
	if a.ConfigReportDigest == "" || a.ConfigReportStale() {
		return nil
	}
	switch a.ConfigHealth {
	case ConfigHealthBlocked, ConfigHealthImpaired:
		return []HealthReason{{Code: ReasonConfigCheckFailed, Severity: SeverityCritical,
			Message: "A setup check failed on the sensor. Open its setup checklist to see what to fix."}}
	case ConfigHealthAttention:
		return []HealthReason{{Code: ReasonConfigCheckWarning, Severity: SeverityWarning,
			Message: "A setup check on the sensor needs attention. Open its setup checklist to see what to fix."}}
	}
	return nil
}

// configStaleReason is the reason of a heartbeating sensor whose stored
// report is stale.
func (a *Sensor) configStaleReason() (HealthReason, bool) {
	if !a.ConfigReportStale() {
		return HealthReason{}, false
	}
	return HealthReason{Code: ReasonConfigReportStale, Severity: SeverityWarning,
		Message: "The sensor's setup checklist is out of date: its heartbeat no longer matches the last report it sent."}, true
}

// DerivedConfigNote labels a checklist derived from the heartbeat.
const DerivedConfigNote = "Derived from the heartbeat. Upgrade the sensor (>= v0.10.0) for the full check list."

// DerivedConfigChecks is the checklist the platform derives for a sensor
// that sends no config report, from what its heartbeat and manifest say:
// each reported tool's install state, whether any scanner is available,
// and the local policy.
func (a *Sensor) DerivedConfigChecks() []ConfigCheck {
	var out []ConfigCheck
	add := func(id, status, code string, params map[string]ConfigParam, blocks []string, summary string) {
		if params == nil {
			params = map[string]ConfigParam{}
		}
		if blocks == nil {
			blocks = []string{}
		}
		out = append(out, ConfigCheck{ID: id, Status: status, Severity: defaultSeverity(status), Code: code,
			Params: params, Keys: []string{}, Blocks: blocks, Summary: summary})
	}
	installed := 0
	tools := slices.Clone(a.Reported.Tools)
	sort.SliceStable(tools, func(i, j int) bool { return tools[i].Name < tools[j].Name })
	for _, t := range tools {
		if !configNameRE.MatchString(t.Name) || len(t.Name) > 64 || !configCheckIDRE.MatchString("tool."+t.Name+".binary") {
			continue
		}
		p := map[string]ConfigParam{"tool": {Name: t.Name}}
		if t.Installed {
			installed++
			add("tool."+t.Name+".binary", CheckPass, "ok", p, nil, "The sensor reports this tool as installed.")
		} else {
			add("tool."+t.Name+".binary", CheckFail, "not_installed", p, []string{"tool:" + t.Name},
				"The sensor reports this tool as not installed (the reason is unknown to this sensor version).")
		}
	}
	if !a.Type.IsCollector() && a.IsDaemon() {
		n := int64(installed)
		if installed == 0 {
			add("tools.available", CheckFail, "none", map[string]ConfigParam{"count": {Int: &n}}, []string{"role:scan"},
				"No scanner is installed on the sensor.")
		} else {
			add("tools.available", CheckPass, "ok", map[string]ConfigParam{"count": {Int: &n}}, nil, "")
		}
	}
	if a.LocalPolicy.Enforced() {
		add("policy.local", CheckPass, "enforced", nil, nil, "")
	} else {
		add("policy.local", CheckWarn, "absent", nil, nil, "The sensor reports no local policy (or a version that ignores it).")
	}
	return out
}
