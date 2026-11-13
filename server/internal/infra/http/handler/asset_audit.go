package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"slices"
	"sort"

	auditapp "github.com/openctemio/openctem/server/internal/app/audit"
	"github.com/openctemio/openctem/server/pkg/domain/asset"
	auditdom "github.com/openctemio/openctem/server/pkg/domain/audit"
	tagdom "github.com/openctemio/openctem/server/pkg/domain/tag"
)

// auditAsset writes one audit event about an asset. Metadata carries field
// names, counts and ids, never field values: properties may hold secrets.
// Tag names are the one exception (assetUpdateAuditMetadata).
func (h *AssetHandler) auditAsset(r *http.Request, action auditdom.Action, assetID, assetName, message string, metadata map[string]any) {
	if h.auditService == nil {
		return
	}
	event := auditapp.NewSuccessEvent(action, auditdom.ResourceTypeAsset, assetID).
		WithMessage(message).
		WithSeverity(auditdom.SeverityForAction(action))
	if assetName != "" {
		event = event.WithResourceName(assetName)
	}
	for k, v := range metadata {
		event = event.WithMetadata(k, v)
	}
	auditapp.RecordOrWarn(r.Context(), h.logger, h.auditService, h.buildAuditContext(r), event)
}

// assetChangedFields names the fields that differ between two versions of an
// asset. A changed property is named "properties.<key>"; its value is never
// part of the result.
func assetChangedFields(before, after *asset.Asset) []string {
	if before == nil || after == nil {
		return []string{}
	}
	changed := []string{}
	add := func(name string, differ bool) {
		if differ {
			changed = append(changed, name)
		}
	}
	add("name", before.Name() != after.Name())
	add("criticality", before.Criticality() != after.Criticality())
	add("scope", before.Scope() != after.Scope())
	add("exposure", before.Exposure() != after.Exposure())
	add("description", before.Description() != after.Description())
	add("owner_ref", before.OwnerRef() != after.OwnerRef())
	add("tags", !sameStrings(before.Tags(), after.Tags()))
	add("impact_confidentiality", before.ImpactConfidentiality() != after.ImpactConfidentiality())
	add("impact_integrity", before.ImpactIntegrity() != after.ImpactIntegrity())
	add("impact_availability", before.ImpactAvailability() != after.ImpactAvailability())
	return append(changed, changedPropertyKeys(before.Properties(), after.Properties())...)
}

// auditKeyChangedFields is the metadata key naming the changed fields.
const auditKeyChangedFields = "changed_fields"

// assetUpdateAuditMetadata is the metadata of an asset.updated entry: the
// changed field names, and for tags the tags added and removed. Tags are
// labels every reader of the asset sees, never secrets; naming them keeps
// who set or removed which tag, which the asset row does not record.
func assetUpdateAuditMetadata(before, after *asset.Asset) map[string]any {
	md := map[string]any{auditKeyChangedFields: assetChangedFields(before, after)}
	if before == nil || after == nil {
		return md
	}
	added, removed := tagdom.Diff(before.Tags(), after.Tags())
	if len(added) > 0 {
		md["tags_added"] = added
	}
	if len(removed) > 0 {
		md["tags_removed"] = removed
	}
	return md
}

func sameStrings(a, b []string) bool {
	x, y := slices.Clone(a), slices.Clone(b)
	sort.Strings(x)
	sort.Strings(y)
	return slices.Equal(x, y)
}

// changedPropertyKeys returns "properties.<key>" for every key added, removed
// or changed between two property maps, sorted.
func changedPropertyKeys(before, after map[string]any) []string {
	keys := map[string]struct{}{}
	for k := range before {
		keys[k] = struct{}{}
	}
	for k := range after {
		keys[k] = struct{}{}
	}
	out := []string{}
	for k := range keys {
		bv, bok := before[k]
		av, aok := after[k]
		if bok != aok || !sameJSON(bv, av) {
			out = append(out, "properties."+k)
		}
	}
	sort.Strings(out)
	return out
}

func sameJSON(a, b any) bool {
	x, errX := json.Marshal(a)
	y, errY := json.Marshal(b)
	return errX == nil && errY == nil && bytes.Equal(x, y)
}

// pickProperties returns the entries of props named by keys.
func pickProperties(props map[string]any, keys ...string) map[string]any {
	out := make(map[string]any, len(keys))
	for _, k := range keys {
		if v, ok := props[k]; ok {
			out[k] = v
		}
	}
	return out
}
