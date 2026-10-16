package tenant

// The organization's shared sensor choice (docs/rfcs/RFC-100-shared-sensors.md
// §5, layer 3): its owner may say "never send our scans to shared sensors"
// (data residency, allowlists, policy). The default is to use them when the
// instance offers them.

// SectionSharedSensors is the settings section key.
const SectionSharedSensors = "shared_sensors"

// SharedSensorsSettings is the organization's shared sensor choice.
type SharedSensorsSettings struct {
	// OptOut: never send this organization's scans to shared sensors.
	OptOut bool `json:"opt_out"`
}

// UpdateSharedSensorsSettings replaces the section.
func (t *Tenant) UpdateSharedSensorsSettings(s SharedSensorsSettings) error {
	settings := t.TypedSettings()
	settings.SharedSensors = s
	return t.UpdateSettings(settings)
}
