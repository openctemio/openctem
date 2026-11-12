package tool

// Declared tools (RFC-092): a tool that a
// sensor of the organization declares in its signed manifest joins the
// organization's tool catalog. The row is a projection of the tool's
// descriptor: its name, display name, description, the capabilities it
// implements, the target types it consumes and its settings schema. Nothing
// in the platform's code names the tool, so a new tool, or a new version of
// one, needs no platform change.
//
// The projection is data a sensor reported, so it is untrusted:
//
//   - it is scoped to the sensor's organization and never shadows a platform
//     tool of the same name (lookups read the platform tool first);
//   - it never overwrites a tool a member created by hand;
//   - its text is bounded, stripped of control characters and only ever
//     rendered as text;
//   - it grants nothing: the tier, the trust level, the grant, the scope and
//     the sensor-local policy decide what the tool may run, as for every
//     tool.

import (
	"context"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Metadata keys of a declared tool.
const (
	// MetaOrigin is the metadata key naming where a tool row comes from.
	MetaOrigin = "origin"
	// OriginSensorManifest marks a row projected from a sensor's manifest.
	OriginSensorManifest = "sensor_manifest"
	// MetaDescriptorDigest is the digest of the descriptor the row projects.
	MetaDescriptorDigest = "descriptor_digest"
	// MetaVersion is the tool version of that descriptor.
	MetaVersion = "version"
	// MetaCategory and MetaIcon are the descriptor's presentation hints.
	MetaCategory = "category"
	MetaIcon     = "icon"
	// MetaImplements are the capability references ("dast.web@1").
	MetaImplements = "implements"
	// MetaParams maps each implemented capability reference to the
	// standard params the tool takes for it and the config key each one
	// sets ({"scan.ports@1": {"rate": "rate", "ports": "port_list"}}).
	MetaParams = "params"
)

// MaxDeclaredToolsPerTenant bounds how many declared tools one organization
// may hold, so a misbehaving sensor cannot flood its catalog.
const MaxDeclaredToolsPerTenant = 128

// Text bounds of a declared tool (the columns allow more).
const (
	maxDeclaredDisplayName = 100
	maxDeclaredDescription = 1000
	maxDeclaredHint        = 32
	maxDeclaredList        = 32
	maxDeclaredParams      = 64
)

// Declaration is what a sensor's manifest says about one tool, already
// checked by the sensor domain (a valid contract whose descriptor hashes to
// its digest).
type Declaration struct {
	Name        string
	Version     string
	DisplayName string
	Description string
	Category    string
	Icon        string
	// Implements are the capability references the descriptor implements
	// that the capability taxonomy knows ("dast.web@1").
	Implements []string
	// Params maps each reference of Implements to the standard params the
	// tool takes for it and the config key each one sets.
	Params map[string]map[string]string
	// Consumes are the target types the tool takes.
	Consumes []string
	// ConfigSchema is the descriptor's settings schema (nil: none).
	ConfigSchema map[string]any
	// Digest is the descriptor's digest ("sha256:<hex>").
	Digest string
}

// NewDeclaredTool builds the catalog row of a tool a sensor of tenantID
// declares. The caller has validated the name (the sensor domain's tool
// name rule) and the contract.
func NewDeclaredTool(tenantID shared.ID, d Declaration) (*Tool, error) {
	if tenantID.IsZero() {
		return nil, shared.NewDomainError("VALIDATION", "a declared tool belongs to an organization", shared.ErrValidation)
	}
	name := strings.ToLower(strings.TrimSpace(d.Name))
	if name == "" || len(name) > 50 {
		return nil, shared.NewDomainError("VALIDATION", "invalid declared tool name", shared.ErrValidation)
	}
	now := time.Now()
	t := &Tool{
		ID:            shared.NewID(),
		TenantID:      &tenantID,
		Name:          name,
		DefaultConfig: map[string]any{},
		OutputFormats: []string{},
		Tags:          []string{},
		Metadata:      map[string]any{},
		IsActive:      true,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	t.applyDeclaration(d)
	return t, nil
}

// IsDeclared reports whether the row is projected from a sensor's manifest.
func (t *Tool) IsDeclared() bool {
	o, _ := t.Metadata[MetaOrigin].(string)
	return o == OriginSensorManifest
}

// DeclaredDigest is the descriptor digest a declared row projects.
func (t *Tool) DeclaredDigest() string {
	d, _ := t.Metadata[MetaDescriptorDigest].(string)
	return d
}

// RefreshDeclaration applies a newer declaration of the same tool to a
// declared row and reports whether anything changed. A declaration of an
// older version than the row's is ignored (a fleet in the middle of an
// upgrade reports both), as is one for a row a member created. A row
// projected before it kept the param mappings is refreshed once from the
// same descriptor.
func (t *Tool) RefreshDeclaration(d Declaration, newer func(a, b string) bool) bool {
	if !t.IsDeclared() {
		return false
	}
	if _, mapped := t.Metadata[MetaParams]; mapped && d.Digest == t.DeclaredDigest() {
		return false
	}
	if cur, _ := t.Metadata[MetaVersion].(string); cur != "" && d.Version != "" && newer != nil && newer(cur, d.Version) {
		return false
	}
	t.applyDeclaration(d)
	t.UpdatedAt = time.Now()
	return true
}

// applyDeclaration writes the declaration's fields; the row's own state
// (active, the organization's settings) is never touched.
func (t *Tool) applyDeclaration(d Declaration) {
	t.DisplayName = declaredText(d.DisplayName, maxDeclaredDisplayName, true)
	if t.DisplayName == "" {
		t.DisplayName = t.Name
	}
	t.Description = declaredText(d.Description, maxDeclaredDescription, false)
	t.Capabilities = capabilityKeys(d.Implements)
	t.SupportedTargets = declaredWords(d.Consumes)
	t.ConfigSchema = d.ConfigSchema
	if t.ConfigSchema == nil {
		t.ConfigSchema = map[string]any{}
	}
	if t.Metadata == nil {
		t.Metadata = map[string]any{}
	}
	t.Metadata[MetaOrigin] = OriginSensorManifest
	t.Metadata[MetaDescriptorDigest] = d.Digest
	t.Metadata[MetaVersion] = declaredHint(d.Version, 64)
	t.Metadata[MetaCategory] = declaredHint(d.Category, maxDeclaredHint)
	t.Metadata[MetaIcon] = declaredHint(d.Icon, maxDeclaredHint)
	t.Metadata[MetaImplements] = declaredRefs(d.Implements)
	t.Metadata[MetaParams] = declaredParams(d.Implements, d.Params)
	t.CurrentVersion = declaredHint(d.Version, 50)
}

// capabilityKeys are the capability keys ("dast.web") of references
// ("dast.web@1"), in order, without duplicates: the vocabulary the catalog's
// capability matching reads.
func capabilityKeys(refs []string) []string {
	out := []string{}
	for _, r := range refs {
		k, _, _ := strings.Cut(strings.TrimSpace(r), "@")
		if k = declaredHint(k, 64); k != "" && !contains(out, k) && len(out) < maxDeclaredList {
			out = append(out, k)
		}
	}
	return out
}

func declaredRefs(refs []string) []string {
	out := []string{}
	for _, r := range refs {
		if r = declaredHint(r, 64); r != "" && !contains(out, r) && len(out) < maxDeclaredList {
			out = append(out, r)
		}
	}
	return out
}

// declaredParams keeps the param mappings of the implemented capability
// references only, with machine-word names and keys, bounded.
func declaredParams(refs []string, in map[string]map[string]string) map[string]map[string]string {
	out := map[string]map[string]string{}
	for _, ref := range declaredRefs(refs) {
		m := map[string]string{}
		for name, key := range in[ref] {
			name, key = declaredHint(name, 64), declaredHint(key, 64)
			if name == "" || key == "" || strings.ContainsAny(name+key, ".@+") || len(m) >= maxDeclaredParams {
				continue
			}
			m[name] = key
		}
		out[ref] = m
	}
	return out
}

// DeclaredImplements reports whether a declared tool implements the
// capability reference ref ("scan.ports@1"), with the standard params it
// takes for it and the config key each one sets. A row a member created,
// or one that does not implement ref, reports false.
func (t *Tool) DeclaredImplements(ref string) (map[string]string, bool) {
	if t == nil || !t.IsDeclared() || ref == "" {
		return nil, false
	}
	found := false
	switch refs := t.Metadata[MetaImplements].(type) {
	case []string:
		found = contains(refs, ref)
	case []any:
		for _, r := range refs {
			if s, ok := r.(string); ok && s == ref {
				found = true
			}
		}
	}
	if !found {
		return nil, false
	}
	params := map[string]string{}
	switch all := t.Metadata[MetaParams].(type) {
	case map[string]map[string]string:
		for name, key := range all[ref] {
			params[name] = key
		}
	case map[string]any:
		if m, ok := all[ref].(map[string]any); ok {
			for name, key := range m {
				if k, ok := key.(string); ok {
					params[name] = k
				}
			}
		}
	}
	return params, true
}

func declaredWords(in []string) []string {
	out := []string{}
	for _, w := range in {
		if w = declaredHint(w, 64); w != "" && !contains(out, w) && len(out) < maxDeclaredList {
			out = append(out, w)
		}
	}
	return out
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// declaredHint keeps a short machine word: lowercase letters, digits and
// ".@_-", else "".
func declaredHint(s string, maxLen int) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" || len(s) > maxLen {
		return ""
	}
	for _, r := range s {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && !strings.ContainsRune(".@_-+", r) {
			return ""
		}
	}
	return s
}

// declaredText is reported text made safe to store and show as text: valid
// UTF-8, no control or format characters (newlines kept only when
// multiline), runs of spaces collapsed, bounded in runes.
func declaredText(s string, maxRunes int, singleLine bool) string {
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "")
	}
	var b strings.Builder
	space := false
	n := 0
	for _, r := range strings.TrimSpace(s) {
		if n >= maxRunes {
			break
		}
		switch {
		case r == '\n' && !singleLine:
			b.WriteRune(r)
			space = false
		case unicode.IsSpace(r):
			if !space {
				b.WriteRune(' ')
				space = true
			}
		case unicode.IsControl(r) || unicode.Is(unicode.Cf, r):
			continue
		default:
			b.WriteRune(r)
			space = false
		}
		n++
	}
	return strings.TrimSpace(b.String())
}

// DeclaredStore persists declared tools.
type DeclaredStore interface {
	// GetByTenantAndName returns the organization's own tool of that name
	// (shared.ErrNotFound when none).
	GetByTenantAndName(ctx context.Context, tenantID shared.ID, name string) (*Tool, error)
	// CreateDeclared inserts a declared tool; false when it was not inserted
	// (a platform or organization tool has the name, or the limit is
	// reached).
	CreateDeclared(ctx context.Context, t *Tool) (bool, error)
	// UpdateDeclared writes a refreshed declared tool.
	UpdateDeclared(ctx context.Context, t *Tool) error
}

// ErrDeclaredTool refuses editing or deleting a tool a sensor declares: its
// manifest is the source, and the next manifest would bring it back.
// Deactivating it is the organization's switch.
var ErrDeclaredTool = shared.NewDomainError("FORBIDDEN",
	"this tool is declared by a sensor's manifest: change it on the sensor, or deactivate it", shared.ErrForbidden)

// CanEdit checks that the organization may edit or delete the tool: one of
// its own tools that no sensor declares.
func (t *Tool) CanEdit(tenantID shared.ID) error {
	if err := t.CanManage(tenantID); err != nil {
		return err
	}
	if t.IsDeclared() {
		return ErrDeclaredTool
	}
	return nil
}
