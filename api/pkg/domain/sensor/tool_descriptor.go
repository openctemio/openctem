package sensor

// Tool descriptors in the sensor manifest (RFC-055, Tool Contract v1): a
// tool ported to the contract reports its whole tool.yaml (canonical JSON,
// its SHA-256 is the contract's digest) once, in the manifest; heartbeats
// carry the manifest digest only. The platform keeps the descriptor inside
// the sensor's own manifest version (tenant-scoped, per sensor), so a
// descriptor one tenant's sensor reports is never visible to another tenant.
//
// A descriptor is a claim from an untrusted process. It is kept only when it
// hashes to the contract's digest, is a JSON object of the contract's
// format and version, fits MaxToolDescriptorBytes, and holds no control or
// bidirectional-override character in any string (it is shown as text).
// Otherwise it is dropped and the contract is kept without it.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"unicode"
)

// MaxToolDescriptorBytes bounds one descriptor (the SDK's own bound).
const MaxToolDescriptorBytes = 64 << 10

// maxDescriptorDepth bounds the nesting the string walk follows.
const maxDescriptorDepth = 32

// IgnoredInvalidDescriptor is the reason a tool's descriptor was dropped.
const IgnoredInvalidDescriptor = "invalid-descriptor"

// SanitizeToolDescriptor returns the descriptor as it is stored, or nil and
// the reason it is refused.
func SanitizeToolDescriptor(c *ToolContract, raw json.RawMessage) (json.RawMessage, string) {
	if c == nil || len(raw) == 0 {
		return nil, ""
	}
	if len(raw) > MaxToolDescriptorBytes {
		return nil, "descriptor too large"
	}
	sum := sha256.Sum256(raw)
	if "sha256:"+hex.EncodeToString(sum[:]) != c.Digest {
		return nil, "descriptor does not hash to the contract digest"
	}
	var head struct {
		APIVersion string `json:"apiVersion"`
		Version    string `json:"version"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var doc any
	if err := dec.Decode(&doc); err != nil {
		return nil, "descriptor is not JSON"
	}
	obj, ok := doc.(map[string]any)
	if !ok {
		return nil, "descriptor is not a JSON object"
	}
	if err := json.Unmarshal(raw, &head); err != nil || head.APIVersion != c.APIVersion || head.Version != c.Version {
		return nil, "descriptor does not match the contract"
	}
	if !cleanStrings(obj, 0) {
		return nil, "descriptor holds a control character"
	}
	return append(json.RawMessage(nil), raw...), ""
}

// cleanStrings reports whether every string (keys included) is free of
// control and bidirectional-override characters, within the depth bound.
func cleanStrings(v any, depth int) bool {
	if depth > maxDescriptorDepth {
		return false
	}
	switch x := v.(type) {
	case string:
		for _, r := range x {
			if unicode.IsControl(r) || unicode.Is(unicode.Bidi_Control, r) || r == ' ' || r == ' ' {
				return false
			}
		}
	case map[string]any:
		for k, e := range x {
			if !cleanStrings(k, depth+1) || !cleanStrings(e, depth+1) {
				return false
			}
		}
	case []any:
		for _, e := range x {
			if !cleanStrings(e, depth+1) {
				return false
			}
		}
	}
	return true
}

// ToolDescriptor returns the descriptor the manifest's tool named name (case
// insensitive) reported, or nil.
func (m Manifest) ToolDescriptor(name string) json.RawMessage {
	if c := m.ToolContract(name); c != nil {
		return c.Descriptor
	}
	return nil
}
