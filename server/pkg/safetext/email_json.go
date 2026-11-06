package safetext

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// MaskEmailsJSON masks the e-mail addresses in the string values of a JSON
// document (MaskEmails), at any depth, and reports whether one changed.
// Object keys are names, not text, and are left alone, as are numbers,
// booleans and null. A document without an address is returned as given;
// otherwise the result is re-encoded (numbers keep their digits, object keys
// come out sorted, HTML characters are not escaped), which a jsonb column
// stores as the same value apart from the masked strings. Idempotent.
func MaskEmailsJSON(raw []byte) ([]byte, bool, error) {
	if !bytes.Contains(raw, []byte("@")) && !bytes.Contains(raw, []byte("%40")) {
		return raw, false, nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, false, fmt.Errorf("decode json: %w", err)
	}
	if dec.More() {
		return nil, false, fmt.Errorf("decode json: trailing data")
	}
	v, changed := maskJSONValue(v)
	if !changed {
		return raw, false, nil
	}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, false, fmt.Errorf("encode json: %w", err)
	}
	return bytes.TrimRight(b.Bytes(), "\n"), true, nil
}

// maskJSONValue masks the strings of a decoded JSON value: object values and
// array elements, never object keys.
func maskJSONValue(v any) (any, bool) {
	switch x := v.(type) {
	case string:
		if m := MaskEmails(x); m != x {
			return m, true
		}
	case map[string]any:
		changed := false
		for k, e := range x {
			if m, ok := maskJSONValue(e); ok {
				x[k], changed = m, true
			}
		}
		return x, changed
	case []any:
		changed := false
		for i, e := range x {
			if m, ok := maskJSONValue(e); ok {
				x[i], changed = m, true
			}
		}
		return x, changed
	}
	return v, false
}
