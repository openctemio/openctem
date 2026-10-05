package tenant

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Settings sections are the top-level keys of tenants.settings. Each section
// is written on its own with a compare-and-swap (Repository.UpdateSettingsSection),
// so two saves of different sections never overwrite each other and a stale
// save of the same section is refused instead of silently reverting a change
// (for example an IP allowlist or an MFA requirement).
const (
	SectionGeneral        = "general"
	SectionSecurity       = "security"
	SectionBranding       = "branding"
	SectionBranch         = "branch"
	SectionAI             = "ai"
	SectionRiskScoring    = "risk_scoring"
	SectionPentest        = "pentest"
	SectionAssetIdentity  = "asset_identity"
	SectionAssetLifecycle = "asset_lifecycle"
	SectionRetest         = "retest"
)

// settingsSectionTargets maps each section key to the field of s it decodes
// into. Keys not listed here (subscribed_bundles, legacy keys) are not typed
// sections and are never rewritten by a section write.
func settingsSectionTargets(s *Settings) map[string]any {
	return map[string]any{
		SectionGeneral:        &s.General,
		SectionSecurity:       &s.Security,
		SectionBranding:       &s.Branding,
		SectionBranch:         &s.Branch,
		SectionAI:             &s.AI,
		SectionRiskScoring:    &s.RiskScoring,
		SectionPentest:        &s.Pentest,
		SectionAssetIdentity:  &s.AssetIdentity,
		SectionAssetLifecycle: &s.AssetLifecycle,
		SectionRetest:         &s.Retest,
	}
}

// IsSettingsSection reports whether key is a typed settings section.
func IsSettingsSection(key string) bool {
	var s Settings
	_, ok := settingsSectionTargets(&s)[key]
	return ok
}

// ErrSettingsSectionCorrupt is returned when a stored settings section cannot
// be decoded. Readers of security settings treat it as "deny" and writers
// refuse to save over it, so a corrupt section never turns into the permissive
// defaults (empty IP allowlist, MFA off).
var ErrSettingsSectionCorrupt = errors.New("stored settings section is unreadable")

// SettingsConflictError is returned when a settings section changed since the
// caller read it: either the If-Match ETag is stale or a concurrent write won
// the compare-and-swap. It carries the current section so the client can show
// what changed. It matches shared.ErrConflict.
type SettingsConflictError struct {
	Section string
	ETag    string
	Current any
}

func (e *SettingsConflictError) Error() string {
	return fmt.Sprintf("settings section %q was changed by someone else; reload and try again", e.Section)
}

// Unwrap makes errors.Is(err, shared.ErrConflict) true.
func (e *SettingsConflictError) Unwrap() error { return shared.ErrConflict }

// SectionETag is the entity tag of one settings section value: a hash of its
// canonical JSON (encoding/json sorts map keys, so equal content gives an
// equal tag). An absent section has the tag of JSON null.
func SectionETag(v any) string {
	data, err := json.Marshal(v)
	if err != nil {
		data = []byte("null")
	}
	sum := sha256.Sum256(data)
	return `"` + hex.EncodeToString(sum[:12]) + `"`
}

// ETagMatches compares a client If-Match value with a section tag. It accepts
// a weak prefix and a missing pair of quotes, and "*" (any current value).
func ETagMatches(ifMatch, etag string) bool {
	norm := func(s string) string {
		s = strings.TrimSpace(s)
		s = strings.TrimPrefix(s, "W/")
		return strings.Trim(s, `"`)
	}
	for _, candidate := range strings.Split(ifMatch, ",") {
		c := strings.TrimSpace(candidate)
		if c == "*" || norm(c) == norm(etag) {
			return true
		}
	}
	return false
}

// SettingsSectionValue returns the stored (raw) value of a section and
// whether the key is present.
func (t *Tenant) SettingsSectionValue(section string) (any, bool) {
	v, ok := t.settings[section]
	return v, ok
}

// SettingsSectionETag returns the ETag of the stored value of a section.
func (t *Tenant) SettingsSectionETag(section string) string {
	v := t.settings[section]
	return SectionETag(v)
}

// SectionETags returns the ETag of every typed section.
func (t *Tenant) SectionETags() map[string]string {
	var s Settings
	out := make(map[string]string, len(settingsSectionTargets(&s)))
	for key := range settingsSectionTargets(&s) {
		out[key] = t.SettingsSectionETag(key)
	}
	return out
}

// SettingsSectionError returns ErrSettingsSectionCorrupt (wrapped) when the
// stored value of section cannot be decoded into its typed form.
func (t *Tenant) SettingsSectionError(section string) error {
	_, errs := SettingsFromMapChecked(t.settings)
	return errs[section]
}

// SecuritySettingsStrict returns the security section, or an error when it is
// stored but unreadable. Enforcement points (IP allowlist, MFA requirement,
// SSO enforcement) use it so a corrupt section fails closed instead of
// falling back to the permissive defaults.
func (t *Tenant) SecuritySettingsStrict() (SecuritySettings, error) {
	s, errs := SettingsFromMapChecked(t.settings)
	if err := errs[SectionSecurity]; err != nil {
		return SecuritySettings{}, err
	}
	return s.Security, nil
}

// SettingsFromMapChecked decodes the stored settings section by section. A
// section that cannot be decoded gets its default value and is reported in
// the returned map (key -> wrapped ErrSettingsSectionCorrupt); the other
// sections are decoded normally. Before this, one bad key reset every
// section, including security, to defaults.
//
// Decoding otherwise matches the former whole-blob json.Unmarshal: an empty
// blob gives DefaultSettings(); in a non-empty blob an absent section keeps
// its zero value, except risk_scoring, which falls back to the legacy formula.
func SettingsFromMapChecked(m map[string]any) (Settings, map[string]error) {
	if len(m) == 0 {
		return DefaultSettings(), nil
	}
	var settings Settings
	defaults := DefaultSettings()
	defaultTargets := settingsSectionTargets(&defaults)
	var errs map[string]error
	for key, target := range settingsSectionTargets(&settings) {
		raw, ok := m[key]
		if !ok || raw == nil {
			continue
		}
		data, err := json.Marshal(raw)
		if err == nil {
			err = json.Unmarshal(data, target)
		}
		if err != nil {
			// A failed decode may have filled some fields: replace the
			// whole section with its default.
			dst := reflect.ValueOf(target).Elem()
			dst.Set(reflect.ValueOf(defaultTargets[key]).Elem())
			if errs == nil {
				errs = make(map[string]error)
			}
			errs[key] = fmt.Errorf("%w: %s: %v", ErrSettingsSectionCorrupt, key, err)
		}
	}
	if _, ok := m[SectionRiskScoring]; !ok {
		settings.RiskScoring = LegacyRiskScoringSettings()
	}
	if raw, ok := m["subscribed_bundles"]; ok && raw != nil {
		if data, err := json.Marshal(raw); err == nil {
			var bundles []string
			if json.Unmarshal(data, &bundles) == nil {
				settings.SubscribedBundles = bundles
			}
		}
	}
	return settings, errs
}
