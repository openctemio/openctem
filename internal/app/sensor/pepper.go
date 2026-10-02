package sensor

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/hex"
	"slices"
)

// sensorKeyPepperInfo separates the derived pepper from any other key
// derived from APP_ENCRYPTION_KEY. Changing it changes every new hash.
const sensorKeyPepperInfo = "openctem/sensor-api-key-pepper/v1"

// DeriveSensorKeyPepper derives the default sensor-key pepper from the
// encryption key: HKDF-SHA256 with a purpose label, hex. "" for "".
func DeriveSensorKeyPepper(encryptionKey string) string {
	if encryptionKey == "" {
		return ""
	}
	derived, err := hkdf.Key(sha256.New, []byte(encryptionKey), nil, sensorKeyPepperInfo, 32)
	if err != nil {
		return "" // unreachable for a 32-byte output from SHA-256
	}
	return hex.EncodeToString(derived)
}

// SensorKeyPeppers returns the pepper sensor API keys are hashed with and
// the earlier peppers whose hashes must keep verifying (RFC-032 Phase 0,
// G9: the pepper used to be APP_ENCRYPTION_KEY itself, so one secret was
// both the encryption key and a MAC key).
//
//   - explicit (SENSOR_KEY_PEPPER) set: it is the pepper.
//   - else, with an encryption key: DeriveSensorKeyPepper, a different key
//     from the encryption key.
//   - else (development without an encryption key): no pepper, plain SHA-256
//     as before.
//
// Legacy peppers, in order: previous (SENSOR_KEY_PEPPER_PREVIOUS, for an
// operator rotating an explicit pepper), the derived pepper when an explicit
// one replaces it, and the encryption key (the pepper before this release),
// so no key issued earlier stops authenticating. Rolling the API back below
// this release makes keys issued after it unknown to the older server (it
// only knows the old pepper); see RFC-032 §10.2.
func SensorKeyPeppers(explicit, encryptionKey string, previous ...string) (pepper string, legacy []string) {
	derived := DeriveSensorKeyPepper(encryptionKey)
	pepper = derived
	if explicit != "" {
		pepper = explicit
	}
	add := func(p string) {
		if p != "" && p != pepper && !slices.Contains(legacy, p) {
			legacy = append(legacy, p)
		}
	}
	for _, p := range previous {
		add(p)
	}
	add(derived)
	add(encryptionKey)
	return pepper, legacy
}
