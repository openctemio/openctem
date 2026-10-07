package stage

import (
	"errors"
	"fmt"
	"math"
	"regexp"
	"slices"
	"sort"
	"strings"
)

// A capability node's settings (pipeline_steps.config):
//
//   - standard params: the capability contract's params, by name, checked
//     against their type, enum and bounds; each tool receives them under
//     its own config key (Implementation.Params);
//   - tool extras: "x": {"<tool>": {...}}, the tool's own settings, allowed
//     only on a step pinned to that tool (the tool's sensor schema checks
//     them);
//   - executor keys the sensor reads whatever the tool ("exclude").
//
// A key outside these on a step that is not pinned is refused: it would
// reach only some of the tools the platform may pick. On a pinned step a
// plain key is the pinned tool's own setting, as before capabilities.

// ParamsKeyExtras holds a pinned tool's own settings.
const ParamsKeyExtras = "x"

// executorKeys are read by the sensor's command executor for every tool.
var executorKeys = map[string]bool{"exclude": true}

// ErrInvalidParams wraps every params refusal.
var ErrInvalidParams = errors.New("invalid step settings")

var portListParamRE = regexp.MustCompile(`^[0-9]{1,5}(?:-[0-9]{1,5})?(?:,[0-9]{1,5}(?:-[0-9]{1,5})?)*$`)

// ParamByName returns the capability's standard param.
func (s Stage) ParamByName(name string) (Param, bool) {
	for _, p := range s.Params {
		if p.Name == name {
			return p, true
		}
	}
	return Param{}, false
}

// ValidateParams checks a capability node's settings. pinned is the pinned
// tool ("" for auto or prefer).
func ValidateParams(s Stage, config map[string]any, pinned string) error {
	pinned = normalizeTool(pinned)
	for _, key := range sortedKeys(config) {
		v := config[key]
		switch {
		case key == ParamsKeyExtras:
			if err := validateExtras(v, pinned); err != nil {
				return err
			}
		case executorKeys[key]:
		default:
			p, ok := s.ParamByName(key)
			if !ok {
				if pinned != "" {
					continue // the pinned tool's own setting
				}
				return fmt.Errorf("%w: %q is not a setting of %s; pin a tool to set its own settings", ErrInvalidParams, key, s.Name)
			}
			if err := checkParam(p, v); err != nil {
				return fmt.Errorf("%w: %s: %w", ErrInvalidParams, key, err)
			}
		}
	}
	return nil
}

func validateExtras(v any, pinned string) error {
	m, ok := v.(map[string]any)
	if !ok {
		return fmt.Errorf("%w: %s must be an object of tool settings", ErrInvalidParams, ParamsKeyExtras)
	}
	for tool, settings := range m {
		if pinned == "" || normalizeTool(tool) != pinned {
			return fmt.Errorf("%w: settings for %q need the step pinned to %q", ErrInvalidParams, tool, tool)
		}
		if _, ok := settings.(map[string]any); !ok {
			return fmt.Errorf("%w: %s.%s must be an object", ErrInvalidParams, ParamsKeyExtras, tool)
		}
	}
	return nil
}

func checkParam(p Param, v any) error {
	switch p.Type {
	case ParamBoolean:
		if _, ok := v.(bool); !ok {
			return errors.New("must be true or false")
		}
	case ParamInteger:
		n, ok := wholeNumber(v)
		if !ok {
			return errors.New("must be a whole number")
		}
		if p.Min != nil && n < *p.Min {
			return fmt.Errorf("must be at least %d", *p.Min)
		}
		if p.Max != nil && n > *p.Max {
			return fmt.Errorf("must be at most %d", *p.Max)
		}
	case ParamString:
		str, ok := v.(string)
		if !ok {
			return errors.New("must be text")
		}
		return checkEnum(p, []string{str})
	case ParamStringList:
		list, ok := stringList(v)
		if !ok {
			return errors.New("must be a list of text values")
		}
		return checkEnum(p, list)
	case ParamPortList:
		str, ok := v.(string)
		if !ok {
			if n, isNum := wholeNumber(v); isNum {
				str = fmt.Sprint(n)
			} else {
				return errors.New("must be ports and ranges such as 80,443,8000-8100")
			}
		}
		if !portListParamRE.MatchString(strings.ReplaceAll(str, " ", "")) {
			return errors.New("must be ports and ranges such as 80,443,8000-8100")
		}
	default:
		return fmt.Errorf("unknown param type %q", p.Type)
	}
	return nil
}

func checkEnum(p Param, values []string) error {
	if len(p.Enum) == 0 {
		return nil
	}
	for _, v := range values {
		if !slices.Contains(p.Enum, strings.ToLower(strings.TrimSpace(v))) {
			return fmt.Errorf("%q is not one of %s", v, strings.Join(p.Enum, ", "))
		}
	}
	return nil
}

func wholeNumber(v any) (int, bool) {
	switch x := v.(type) {
	case int:
		return x, true
	case int64:
		if x > math.MaxInt32 || x < math.MinInt32 {
			return 0, false
		}
		return int(x), true
	case float64:
		if x != math.Trunc(x) || x > math.MaxInt32 || x < math.MinInt32 {
			return 0, false
		}
		return int(x), true
	}
	return 0, false
}

func stringList(v any) ([]string, bool) {
	switch x := v.(type) {
	case []string:
		return x, true
	case []any:
		out := make([]string, 0, len(x))
		for _, e := range x {
			s, ok := e.(string)
			if !ok {
				return nil, false
			}
			out = append(out, s)
		}
		return out, true
	case string:
		parts := strings.Split(x, ",")
		out := make([]string, 0, len(parts))
		for _, p := range parts {
			if p = strings.TrimSpace(p); p != "" {
				out = append(out, p)
			}
		}
		return out, true
	}
	return nil, false
}

// UnsupportedParams lists the standard params set in config that tool does
// not accept for the capability. A tool with any is not eligible for the
// node: a value is never silently dropped.
func UnsupportedParams(s Stage, tool string, config map[string]any) []string {
	tool = normalizeTool(tool)
	var mapping map[string]string
	for _, impl := range s.Implementations {
		if impl.Tool == tool {
			mapping = impl.Params
		}
	}
	var out []string
	for _, key := range sortedKeys(config) {
		if _, std := s.ParamByName(key); !std {
			continue
		}
		if _, ok := mapping[key]; !ok {
			out = append(out, key)
		}
	}
	return out
}

// ToolConfig is the config a tool receives for a capability node: the
// standard params under the tool's own keys, the node's extras for that
// tool, executor keys, and (pinned steps) plain tool settings. On a pinned
// step a standard param the tool has no mapping for goes through under its
// own name (the tool's own setting, as before capabilities); on a resolved
// step the caller has checked UnsupportedParams, so there is none.
func ToolConfig(s Stage, tool string, config map[string]any, pinned bool) map[string]any {
	if config == nil {
		return nil
	}
	tool = normalizeTool(tool)
	var mapping map[string]string
	for _, impl := range s.Implementations {
		if impl.Tool == tool {
			mapping = impl.Params
		}
	}
	out := map[string]any{}
	for key, v := range config {
		switch {
		case key == ParamsKeyExtras:
			if m, ok := v.(map[string]any); ok {
				for t, settings := range m {
					if normalizeTool(t) != tool {
						continue
					}
					if sm, ok := settings.(map[string]any); ok {
						for k, sv := range sm {
							out[k] = sv
						}
					}
				}
			}
		case executorKeys[key]:
			out[key] = v
		default:
			if _, std := s.ParamByName(key); std {
				if toolKey, ok := mapping[key]; ok {
					out[toolKey] = v
				} else if pinned {
					out[key] = v
				}
				continue
			}
			out[key] = v // a pinned tool's own setting
		}
	}
	return out
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
