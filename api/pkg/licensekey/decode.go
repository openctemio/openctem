package licensekey

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// maxDepth bounds JSON nesting in a license file.
const maxDepth = 16

// decodeStrict decodes one JSON value into v, refusing unknown fields,
// duplicate object keys (two parsers could pick different values), nesting
// deeper than maxDepth and trailing data.
func decodeStrict(data []byte, v any) error {
	if err := checkShape(data); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing data")
	}
	return nil
}

// checkShape walks the tokens of data once: duplicate keys and depth.
func checkShape(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	type frame struct {
		object bool
		keys   map[string]bool
		expect bool // next string token in an object is a key
	}
	var stack []*frame
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		var top *frame
		if len(stack) > 0 {
			top = stack[len(stack)-1]
		}
		switch t := tok.(type) {
		case json.Delim:
			switch t {
			case '{', '[':
				if top != nil && top.object {
					top.expect = true
				}
				if len(stack) >= maxDepth {
					return fmt.Errorf("nested deeper than %d", maxDepth)
				}
				stack = append(stack, &frame{object: t == '{', keys: map[string]bool{}, expect: t == '{'})
			case '}', ']':
				stack = stack[:len(stack)-1]
				if len(stack) > 0 && stack[len(stack)-1].object {
					stack[len(stack)-1].expect = true
				}
			}
		case string:
			if top != nil && top.object && top.expect {
				if top.keys[t] {
					return fmt.Errorf("duplicate key %q", t)
				}
				top.keys[t] = true
				top.expect = false
				continue
			}
			if top != nil && top.object {
				top.expect = true
			}
		default:
			if top != nil && top.object {
				top.expect = true
			}
		}
	}
}
