package notification

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// Message is the language-neutral form of a notice's text: a stable code
// that the web renders from its en and vi catalogs, plus the typed values the
// sentence needs (counts, names, capability keys, times). The English title
// and body stay on the notice: older rows, e-mail, chat and webhook
// deliveries read them, and the web falls back to them for a code it does not
// know (docs/architecture/notification-system.md#message-codes).
//
// Params are display values only. The web shows them as text (escaped,
// never markup, never a link target), so a value may carry a name a person
// typed. They never carry secrets: anything in Params reaches every
// recipient of the notice, exactly as the body does.
type Message struct {
	Code   string         `json:"code"`
	Params map[string]any `json:"params,omitempty"`
}

// MaxMessageParamsBytes bounds the stored values of one message (the
// database check allows a little more for jsonb overhead).
const MaxMessageParamsBytes = 12 * 1024

// maxMessageCodeLen matches the message_code column.
const maxMessageCodeLen = 96

// messageCodePattern: dot-separated lower-case segments, e.g. coverage.gap.
var messageCodePattern = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z0-9_]+)*$`)

// Msg builds a message from a code and alternating key, value pairs:
// Msg("coverage.gap", "capability", c, "count", n).
func Msg(code string, kv ...any) *Message {
	m := &Message{Code: code}
	if len(kv) > 0 {
		m.Params = make(map[string]any, len(kv)/2)
		for i := 0; i+1 < len(kv); i += 2 {
			k, ok := kv[i].(string)
			if !ok {
				continue
			}
			m.Params[k] = kv[i+1]
		}
	}
	return m
}

// Lines builds a message whose body is one line per item (a digest): the web
// renders each item from its own code, under the code of the whole.
func Lines(code string, items []*Message, kv ...any) *Message {
	m := Msg(code, kv...)
	if m.Params == nil {
		m.Params = map[string]any{}
	}
	lines := make([]Message, 0, len(items))
	for _, it := range items {
		if it != nil {
			lines = append(lines, *it)
		}
	}
	m.Params["lines"] = lines
	return m
}

// Validate reports whether the message can be stored: a well-formed code and
// values that encode as a JSON object within MaxMessageParamsBytes.
func (m *Message) Validate() error {
	if m == nil {
		return nil
	}
	if len(m.Code) > maxMessageCodeLen || !messageCodePattern.MatchString(m.Code) {
		return fmt.Errorf("notification message code %q is not a dotted lower-case code", m.Code)
	}
	b, err := m.ParamsJSON()
	if err != nil {
		return fmt.Errorf("notification message %s: %w", m.Code, err)
	}
	if len(b) > MaxMessageParamsBytes {
		return fmt.Errorf("notification message %s: values are %d bytes, the limit is %d", m.Code, len(b), MaxMessageParamsBytes)
	}
	return nil
}

// ParamsJSON is the stored form of the values (nil when there are none).
// NUL characters are removed from every string, at any depth: PostgreSQL
// refuses \u0000 in jsonb, and a refused insert would lose the notice.
func (m *Message) ParamsJSON() ([]byte, error) {
	if m == nil || len(m.Params) == 0 {
		return nil, nil
	}
	b, err := json.Marshal(m.Params)
	if err != nil || !bytes.Contains(b, []byte(`\u0000`)) {
		return b, err
	}
	// Decode to plain JSON values and strip NUL from every string; a literal
	// backslash-u0000 typed as text stays (it is encoded as \\u0000).
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, err
	}
	return json.Marshal(stripNUL(v))
}

// stripNUL removes NUL characters from the strings of a decoded JSON value.
func stripNUL(v any) any {
	switch t := v.(type) {
	case string:
		return strings.ReplaceAll(t, "\x00", "")
	case []any:
		for i := range t {
			t[i] = stripNUL(t[i])
		}
		return t
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, x := range t {
			out[strings.ReplaceAll(k, "\x00", "")] = stripNUL(x)
		}
		return out
	default:
		return v
	}
}

// ParseMessage rebuilds a stored message; an empty code means the notice has
// none (it predates message codes). Values that do not decode are dropped,
// the code is kept, so the web still falls back to the English text cleanly.
func ParseMessage(code string, params []byte) *Message {
	if code == "" {
		return nil
	}
	m := &Message{Code: code}
	if len(params) > 0 {
		var p map[string]any
		if json.Unmarshal(params, &p) == nil {
			m.Params = p
		}
	}
	return m
}
