package tenant

// CredentialSettings is the organization's policy for leaked credentials
// (docs/architecture/credential-leaks.md).
type CredentialSettings struct {
	// StoreSecretValues says whether an imported leaked secret value
	// (password, token, key) is kept, encrypted, so that a holder of
	// findings:credentials:reveal can read it back. Off: only the mask, the
	// credential type and the organization's keyed fingerprint are kept.
	// nil: the platform default applies (credentials.leaked_secret_storage).
	StoreSecretValues *bool `json:"store_secret_values,omitempty"`
}

// EffectiveStoreSecretValues is the organization's choice, or platformDefault
// when it never made one.
func (s CredentialSettings) EffectiveStoreSecretValues(platformDefault bool) bool {
	if s.StoreSecretValues != nil {
		return *s.StoreSecretValues
	}
	return platformDefault
}

// UpdateCredentialSettings replaces the credential settings.
func (t *Tenant) UpdateCredentialSettings(cs CredentialSettings) error {
	settings := t.TypedSettings()
	settings.Credentials = cs
	return t.UpdateSettings(settings)
}
