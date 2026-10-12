package scan

// Redaction of secret-looking scanner_config values.
//
// DetectConfigSecrets tells the user which values look like credentials;
// RedactConfigSecrets hides exactly those values from callers that may read a
// scan but not edit it (no scans:write). Both use the same classifier, so a
// value listed in scanner_config_warnings is the value that is masked.
//
// Sensors are not affected: the command they claim carries the stored config.

import "encoding/json"

// RedactedSecretValue replaces a masked value in a response.
const RedactedSecretValue = "********"

// RedactConfigSecrets returns a copy of cfg in which every value that
// DetectConfigSecrets would flag is replaced by RedactedSecretValue. The
// structure (keys, list lengths, non-secret values) is kept. Anything nested
// deeper than the detector looks is masked whole, so depth never leaks a
// value. cfg itself is not modified.
func RedactConfigSecrets(cfg map[string]any) map[string]any {
	if cfg == nil {
		return nil
	}
	return redactMap(cfg, 0)
}

// RedactPayloadSecrets applies RedactConfigSecrets to a JSON object (a
// command payload, which embeds scanner_config, config, step_config and the
// run context). A payload that is not a JSON object is replaced by a masked
// string: it cannot be inspected, so it is not shown.
func RedactPayloadSecrets(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return raw
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		var null any
		if json.Unmarshal(raw, &null) == nil && null == nil {
			return raw
		}
		masked, _ := json.Marshal(RedactedSecretValue)
		return masked
	}
	if m == nil {
		return raw
	}
	out, err := json.Marshal(RedactConfigSecrets(m))
	if err != nil {
		masked, _ := json.Marshal(RedactedSecretValue)
		return masked
	}
	return out
}

// RestoreRedactedConfigSecrets returns incoming with every value that equals
// RedactedSecretValue put back to the stored value at the same path, when
// that stored value is one the redaction would have masked. A client that
// saves a config it was shown masked therefore keeps the real secret instead
// of overwriting it with the mask. Other values are taken from incoming as
// they are. incoming is not modified.
func RestoreRedactedConfigSecrets(incoming, stored map[string]any) map[string]any {
	if incoming == nil || stored == nil {
		return incoming
	}
	return restoreMap(incoming, stored, 0)
}

func redactMap(m map[string]any, depth int) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = redactValue(k, v, depth+1)
	}
	return out
}

// redactValue mirrors secretDetector.walk: same key semantics (a list item is
// judged under its list's key) and the same depth accounting.
func redactValue(key string, v any, depth int) any {
	switch val := v.(type) {
	case map[string]any:
		if depth > maxSecretScanDepth {
			return RedactedSecretValue
		}
		return redactMap(val, depth)
	case []any:
		if depth > maxSecretScanDepth {
			return RedactedSecretValue
		}
		out := make([]any, len(val))
		for i, item := range val {
			out[i] = redactValue(key, item, depth+1)
		}
		return out
	case []string:
		out := make([]string, len(val))
		for i, item := range val {
			if _, flagged := secretReason(key, item); flagged {
				out[i] = RedactedSecretValue
			} else {
				out[i] = item
			}
		}
		return out
	case string:
		if _, flagged := secretReason(key, val); flagged {
			return RedactedSecretValue
		}
		return val
	default:
		return v
	}
}

func restoreMap(in, stored map[string]any, depth int) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		sv, ok := stored[k]
		if !ok {
			out[k] = v
			continue
		}
		out[k] = restoreValue(k, v, sv, depth+1)
	}
	return out
}

func restoreValue(key string, in, stored any, depth int) any {
	if s, ok := in.(string); ok && s == RedactedSecretValue {
		if masked, ok := redactValue(key, stored, depth).(string); ok && masked == RedactedSecretValue {
			return stored
		}
		return in
	}
	switch val := in.(type) {
	case map[string]any:
		if sm, ok := stored.(map[string]any); ok {
			return restoreMap(val, sm, depth)
		}
	case []any:
		if sl, ok := stored.([]any); ok {
			out := make([]any, len(val))
			for i, item := range val {
				if i < len(sl) {
					out[i] = restoreValue(key, item, sl[i], depth+1)
				} else {
					out[i] = item
				}
			}
			return out
		}
	}
	return in
}
