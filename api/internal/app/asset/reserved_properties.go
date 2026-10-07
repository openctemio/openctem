package asset

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"

	assetdom "github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// isReservedUserPropertyKey reports whether a key in user-supplied
// properties names a platform-owned property. The key is checked as sent and
// after the camelCase/alias normalization that create applies, so
// "isCrownJewel" cannot slip past as a different spelling. Keys starting
// with "__" are internal markers (for example __promoted_sub_type).
func isReservedUserPropertyKey(k string) bool {
	if strings.HasPrefix(k, "__") {
		return true
	}
	return assetdom.IsReservedPropertyKey(k) ||
		assetdom.IsReservedPropertyKey(assetdom.CanonicalPropertyKey(camelToSnakeCase(k)))
}

// errReservedProperty is the 400 for a platform-owned key in properties.
func errReservedProperty(key string) error {
	return fmt.Errorf("%w: property %q is reserved and cannot be set through properties", shared.ErrValidation, key)
}

// sortedKeys returns the keys of props in a stable order, so the error
// names the same key every time.
func sortedKeys(props map[string]any) []string {
	keys := make([]string, 0, len(props))
	for k := range props {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// RejectReservedProperties refuses user-supplied properties that set a
// platform-owned key (crown jewel, business impact, aliases, discovery
// fields, internal markers). Those are written only by their own endpoints
// or by the platform; a bad type in one of them would also break every
// query that reads it.
func RejectReservedProperties(props map[string]any) error {
	for _, k := range sortedKeys(props) {
		if isReservedUserPropertyKey(k) {
			return errReservedProperty(k)
		}
	}
	return nil
}

// stripUnchangedReservedProperties is RejectReservedProperties for a patch
// over current: a reserved key whose value equals the stored one is an echo
// of what the client read (a full-form or bulk PUT sends the properties back)
// and is dropped from patch; any other reserved key is refused.
func stripUnchangedReservedProperties(patch, current map[string]any) error {
	for _, k := range sortedKeys(patch) {
		if !isReservedUserPropertyKey(k) {
			continue
		}
		stored, ok := current[k]
		if !ok || !sameJSONValue(patch[k], stored) {
			return errReservedProperty(k)
		}
		delete(patch, k)
	}
	return nil
}

// sameJSONValue compares two decoded JSON values, normalizing both through
// encoding/json so numeric and container types compare alike.
func sameJSONValue(a, b any) bool {
	na, errA := normalizeJSON(a)
	nb, errB := normalizeJSON(b)
	if errA != nil || errB != nil {
		return false
	}
	return reflect.DeepEqual(na, nb)
}

func normalizeJSON(v any) (any, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var out any
	err = json.Unmarshal(raw, &out)
	return out, err
}

// rejectMisplacedProperties refuses a key the property schema gives only to
// assets of other classes (a port on a domain; RFC-042 §6.3.9): it describes
// another asset and would be shown, and matched, as this one's.
func rejectMisplacedProperties(t assetdom.AssetType, subType string, props map[string]any) error {
	keys := assetdom.MisplacedPropertyKeys(t, subType, props)
	if len(keys) == 0 {
		return nil
	}
	def, _ := assetdom.LookupProperty(keys[0])
	classes := make([]string, len(def.Classes))
	for i, c := range def.Classes {
		classes[i] = string(c)
	}
	return fmt.Errorf("%w: property %q applies only to %s assets, not to a %s",
		shared.ErrValidation, keys[0], strings.Join(classes, " or "), t)
}
