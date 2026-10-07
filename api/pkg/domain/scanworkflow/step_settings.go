package scanworkflow

// A workflow step's settings and how they reach the sensor.
//
// The sensor SDK (sdk-go ScanCommandPayload) reads a scan command's settings
// from the payload key `config`. Steps sent them as `step_config`, which no
// sensor reads, so every step ran with its tool's defaults (a naabu step with
// ports "80" scanned the top 100 ports). PayloadKeyConfig is the one key.
//
// On the sensor, the SDK resolves `config` against the tool's own settings
// schema (api RFC-038) and fails the command on any value the schema does not
// allow. Until the platform stores the schemas sensors report (RFC-038 P2),
// stepToolSettings mirrors the keys the sensor's naabu and nuclei declare, so
// a bad value is refused when the step is saved rather than when it runs.
// Keep it in step with sensor internal/recon/naabu/settings.go and
// internal/scanners/nuclei/settings.go; the sensor is the authority, this is
// the early check.

import (
	"errors"
	"fmt"
	"maps"
	"math"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"
)

// PayloadKeyConfig is the command payload key the sensor reads a scan's
// settings from.
const PayloadKeyConfig = "config"

// ErrInvalidStepSetting is wrapped by every NormalizeStepConfig error.
var ErrInvalidStepSetting = errors.New("invalid step setting")

// Keys the sensor's command executor reads itself, whatever the tool.
const (
	stepKeyAllowInteractsh = "allow_interactsh"
	stepKeyExclude         = "exclude"
)

var (
	// portListRE is a list of ports and port ranges: no sign, space or
	// letter, so a value can never be read as a flag.
	portListRE = regexp.MustCompile(`^[0-9]{1,5}(?:-[0-9]{1,5})?(?:,[0-9]{1,5}(?:-[0-9]{1,5})?)*$`)
	// templateTagRE is one nuclei template tag (no comma, space or leading
	// '-').
	templateTagRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
)

const (
	maxPortListLen = 2048
	maxTemplateTag = 64
)

// refusedTemplateTags select templates that can take a target down or flood
// it; the sensor refuses them per scan.
var refusedTemplateTags = []string{"dos", "fuzz", "fuzzing", "intrusive"}

var nucleiSeverities = []string{"info", "low", "medium", "high", "critical", "unknown"}

// stepSetting checks and normalizes one setting's value.
type stepSetting func(v any) (any, error)

// stepToolSettings are the settings each tool's sensor schema declares.
var stepToolSettings = map[string]map[string]stepSetting{
	"naabu": {
		"ports":         portsSetting(true),
		"exclude_ports": portsSetting(false),
		"top_ports":     topPortsSetting,
		"rate":          intSetting(1, 100000),
		"retries":       intSetting(0, 10),
	},
	"nuclei": {
		"tags":         tagsSetting(true),
		"exclude_tags": tagsSetting(false),
		"severity":     severitySetting,
	},
}

// NormalizeStepConfig checks a step's config for its tool and returns it in
// the form the sensor's schema takes: comma-separated lists become arrays,
// numbers written as strings become numbers, tags are lowercased. Keys the
// tool's sensor schema does not declare are kept as they are (the sensor
// reports them as ignored). The config itself is not modified.
//
// Refused: a value of a declared key the sensor would refuse, an exclude
// pattern that looks like a flag, and allow_interactsh (out-of-band
// callbacks are an approved-scan decision, not a workflow step setting).
func NormalizeStepConfig(tool string, config map[string]any) (map[string]any, error) {
	if config == nil {
		return nil, nil
	}
	out := maps.Clone(config)
	if _, ok := out[stepKeyAllowInteractsh]; ok {
		return nil, fmt.Errorf("%w: %s cannot be set on a pipeline step", ErrInvalidStepSetting, stepKeyAllowInteractsh)
	}
	if v, ok := out[stepKeyExclude]; ok {
		list, err := stringList(v)
		if err != nil {
			return nil, fmt.Errorf("%w: %s: %w", ErrInvalidStepSetting, stepKeyExclude, err)
		}
		for _, s := range list {
			if err := plainArgValue(s); err != nil {
				return nil, fmt.Errorf("%w: %s: %w", ErrInvalidStepSetting, stepKeyExclude, err)
			}
		}
		out[stepKeyExclude] = list
	}
	settings := stepToolSettings[strings.ToLower(strings.TrimSpace(tool))]
	for _, key := range slices.Sorted(maps.Keys(settings)) {
		v, ok := out[key]
		if !ok {
			continue
		}
		nv, err := settings[key](v)
		if err != nil {
			return nil, fmt.Errorf("%w: %s %s: %w", ErrInvalidStepSetting, tool, key, err)
		}
		out[key] = nv
	}
	if _, hasPorts := out["ports"]; hasPorts && settings != nil {
		if _, hasTop := out["top_ports"]; hasTop {
			return nil, fmt.Errorf("%w: %s: set ports or top_ports, not both", ErrInvalidStepSetting, tool)
		}
	}
	return out, nil
}

func portsSetting(keywords bool) stepSetting {
	return func(v any) (any, error) {
		var s string
		switch x := v.(type) {
		case string:
			s = strings.ReplaceAll(strings.TrimSpace(x), " ", "")
		case float64, int, int64:
			n, err := wholeNumber(x)
			if err != nil {
				return nil, err
			}
			s = strconv.FormatInt(n, 10)
		default:
			return nil, fmt.Errorf("must be a port list such as 80,443,8000-8100")
		}
		if keywords && (s == "top-100" || s == "top-1000" || s == "full") {
			return s, nil
		}
		if s == "" || len(s) > maxPortListLen || !portListRE.MatchString(s) {
			return nil, fmt.Errorf("%q is not a port list such as 80,443,8000-8100", s)
		}
		for _, part := range strings.Split(s, ",") {
			lo, hi, isRange := strings.Cut(part, "-")
			a, _ := strconv.Atoi(lo)
			b := a
			if isRange {
				b, _ = strconv.Atoi(hi)
			}
			if a < 1 || a > 65535 || b < 1 || b > 65535 {
				return nil, fmt.Errorf("port %s is not from 1 to 65535", part)
			}
			if b < a {
				return nil, fmt.Errorf("range %s is reversed", part)
			}
		}
		return s, nil
	}
}

func topPortsSetting(v any) (any, error) {
	n, err := wholeNumber(v)
	if err != nil || (n != 100 && n != 1000) {
		return nil, fmt.Errorf("must be 100 or 1000")
	}
	return n, nil
}

func intSetting(lo, hi int64) stepSetting {
	return func(v any) (any, error) {
		n, err := wholeNumber(v)
		if err != nil {
			return nil, err
		}
		if n < lo || n > hi {
			return nil, fmt.Errorf("must be from %d to %d", lo, hi)
		}
		return n, nil
	}
}

func tagsSetting(selecting bool) stepSetting {
	return func(v any) (any, error) {
		list, err := stringList(v)
		if err != nil {
			return nil, err
		}
		if len(list) > maxTemplateTag {
			return nil, fmt.Errorf("at most %d tags", maxTemplateTag)
		}
		out := make([]string, 0, len(list))
		for _, t := range list {
			t = strings.ToLower(t)
			if !templateTagRE.MatchString(t) {
				return nil, fmt.Errorf("%q is not a template tag (lowercase letters, digits, '-' and '_')", t)
			}
			if selecting && slices.Contains(refusedTemplateTags, t) {
				return nil, fmt.Errorf("tag %q selects intrusive templates", t)
			}
			if !slices.Contains(out, t) {
				out = append(out, t)
			}
		}
		return out, nil
	}
}

func severitySetting(v any) (any, error) {
	list, err := stringList(v)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(list))
	for _, s := range list {
		s = strings.ToLower(s)
		if !slices.Contains(nucleiSeverities, s) {
			return nil, fmt.Errorf("%q is not one of %s", s, strings.Join(nucleiSeverities, ", "))
		}
		if !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("must name at least one severity")
	}
	return out, nil
}

// stringList reads a list written as an array of strings or as one
// comma-separated string; items are trimmed and empty items dropped.
func stringList(v any) ([]string, error) {
	var raw []string
	switch x := v.(type) {
	case string:
		raw = strings.Split(x, ",")
	case []string:
		raw = x
	case []any:
		for _, e := range x {
			s, ok := e.(string)
			if !ok {
				return nil, fmt.Errorf("must be a list of strings")
			}
			raw = append(raw, s)
		}
	default:
		return nil, fmt.Errorf("must be a list of strings")
	}
	out := make([]string, 0, len(raw))
	for _, s := range raw {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out, nil
}

// wholeNumber reads an integer written as a JSON number or a numeric string.
func wholeNumber(v any) (int64, error) {
	var f float64
	switch x := v.(type) {
	case float64:
		f = x
	case int:
		return int64(x), nil
	case int64:
		return x, nil
	case string:
		n, err := strconv.ParseInt(strings.TrimSpace(x), 10, 64)
		if err != nil {
			return 0, fmt.Errorf("%q is not a whole number", x)
		}
		return n, nil
	default:
		return 0, fmt.Errorf("must be a whole number")
	}
	if math.IsNaN(f) || math.IsInf(f, 0) || f != math.Trunc(f) || math.Abs(f) > 1<<53 {
		return 0, fmt.Errorf("%v is not a whole number", v)
	}
	return int64(f), nil
}

// plainArgValue refuses a value that would read as a flag or carries a
// control character (the sensor refuses the same).
func plainArgValue(s string) error {
	if strings.HasPrefix(s, "-") {
		return fmt.Errorf("%q looks like a command-line flag", s)
	}
	if strings.IndexFunc(s, unicode.IsControl) >= 0 {
		return fmt.Errorf("%q contains a control character", s)
	}
	return nil
}
