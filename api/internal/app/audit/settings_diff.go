package audit

import (
	"encoding/json"
	"fmt"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"unicode/utf8"

	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
)

// Configuration changes (organization settings, integrations, policies,
// rules, tokens) are audited with a field-level before/after diff built by
// DiffChanges, so an auditor can see that MFA was turned off or an IP
// allowlist emptied, not just "settings updated".
//
// Redaction: a field whose name marks it as a secret is never recorded; the
// diff carries RedactedChange instead, and only when the value changed.
// Long strings and lists are truncated so one event cannot grow without bound.

// RedactedChange replaces a secret value in a diff.
const RedactedChange = "[changed]"

const (
	maxDiffStringLen = 256
	maxDiffListLen   = 50
	maxDiffFields    = 200
)

// secretFieldMarkers mark a field name as holding a secret.
var secretFieldMarkers = []string{
	"secret", "password", "passwd", "api_key", "apikey", "private_key",
	"access_token", "refresh_token", "credential", "token_hash", "bearer",
	"hec_token", "bot_token", "access_key", "authorization", "cookie", "header",
}

// IsSecretField reports whether a field (last path segment) holds a secret.
// Flags such as "*_configured", "has_*" and "*_enabled" are not secrets.
func IsSecretField(name string) bool {
	k := strings.ToLower(name)
	if strings.HasSuffix(k, "_configured") || strings.HasPrefix(k, "has_") || strings.HasSuffix(k, "_enabled") {
		return false
	}
	for _, m := range secretFieldMarkers {
		if strings.Contains(k, m) {
			return true
		}
	}
	return false
}

// DiffChanges returns the fields that differ between before and after, as
// dotted paths ("security.mfa_required"). Either side may be nil (create or
// delete). Values are anything encoding/json can marshal; structs are compared
// through their JSON form. Returns nil when nothing changed.
func DiffChanges(before, after any) *auditdom.Changes {
	b := flattenForDiff(before)
	a := flattenForDiff(after)

	keys := make([]string, 0, len(b))
	seen := make(map[string]struct{})
	for k := range b {
		keys = append(keys, k)
		seen[k] = struct{}{}
	}
	for k := range a {
		if _, ok := seen[k]; !ok {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)

	changes := auditdom.NewChanges()
	n := 0
	for _, k := range keys {
		bv, bok := b[k]
		av, aok := a[k]
		if bok && aok && reflect.DeepEqual(bv, av) {
			continue
		}
		if n >= maxDiffFields {
			changes.After["_truncated"] = fmt.Sprintf("more than %d fields changed", maxDiffFields)
			break
		}
		n++
		if IsSecretField(lastSegment(k)) {
			if bok {
				changes.Before[k] = RedactedChange
			}
			if aok {
				changes.After[k] = RedactedChange
			}
			continue
		}
		if bok {
			changes.Before[k] = truncateDiffValue(bv)
		}
		if aok {
			changes.After[k] = truncateDiffValue(av)
		}
	}
	if n == 0 {
		return nil
	}
	return changes
}

// ChangedFields lists the dotted paths that a diff touches.
func ChangedFields(c *auditdom.Changes) []string {
	if c == nil {
		return nil
	}
	set := make(map[string]struct{})
	for k := range c.Before {
		set[k] = struct{}{}
	}
	for k := range c.After {
		if k != "_truncated" {
			set[k] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// NewChangeEvent builds a success event that carries the diff of before and
// after, and the list of changed fields in metadata ("changed_fields").
func NewChangeEvent(action auditdom.Action, resourceType auditdom.ResourceType, resourceID string, before, after any) AuditEvent {
	changes := DiffChanges(before, after)
	event := NewSuccessEvent(action, resourceType, resourceID)
	if changes != nil {
		event = event.WithChanges(changes).WithMetadata("changed_fields", ChangedFields(changes))
	}
	return event
}

func lastSegment(path string) string {
	if i := strings.LastIndexByte(path, '.'); i >= 0 {
		return path[i+1:]
	}
	return path
}

// flattenForDiff turns v into dotted-path leaves. Objects are walked; lists
// and scalars are leaves.
func flattenForDiff(v any) map[string]any {
	out := make(map[string]any)
	if v == nil {
		return out
	}
	data, err := json.Marshal(v)
	if err != nil {
		return out
	}
	var generic any
	if err := json.Unmarshal(data, &generic); err != nil {
		return out
	}
	m, ok := generic.(map[string]any)
	if !ok {
		out["value"] = generic
		return out
	}
	flattenInto(out, "", m)
	return out
}

func flattenInto(out map[string]any, prefix string, m map[string]any) {
	for k, v := range m {
		key := k
		if prefix != "" {
			key = prefix + "." + k
		}
		if child, ok := v.(map[string]any); ok && len(child) > 0 && !IsSecretField(k) {
			flattenInto(out, key, child)
			continue
		}
		out[key] = v
	}
}

func truncateDiffValue(v any) any {
	switch val := v.(type) {
	case string:
		val = stripURLPassword(val)
		if len(val) > maxDiffStringLen {
			cut := maxDiffStringLen
			for cut > 0 && !utf8.RuneStart(val[cut]) {
				cut--
			}
			return val[:cut] + "..."
		}
		return val
	case []any:
		if len(val) > maxDiffListLen {
			trimmed := make([]any, 0, maxDiffListLen+1)
			for _, item := range val[:maxDiffListLen] {
				trimmed = append(trimmed, truncateDiffValue(item))
			}
			return append(trimmed, fmt.Sprintf("... %d more", len(val)-maxDiffListLen))
		}
		items := make([]any, 0, len(val))
		for _, item := range val {
			items = append(items, truncateDiffValue(item))
		}
		return items
	case map[string]any:
		// A secret-named object or an empty object kept as a leaf.
		data, _ := json.Marshal(val)
		return truncateDiffValue(string(data))
	default:
		return val
	}
}

// stripURLPassword hides the password of a URL with user info
// (user info with a password before the host), so a credential embedded in a URL is not
// recorded either.
func stripURLPassword(v string) string {
	if !strings.Contains(v, "://") || !strings.Contains(v, "@") {
		return v
	}
	u, err := url.Parse(v)
	if err != nil || u.User == nil {
		return v
	}
	if _, has := u.User.Password(); has {
		u.User = url.UserPassword(u.User.Username(), "xxxxx")
		return u.String()
	}
	return v
}
