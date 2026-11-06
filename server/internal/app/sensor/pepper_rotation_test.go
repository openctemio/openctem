package sensor

import (
	"slices"
	"testing"
)

// After APP_ENCRYPTION_KEY rotates, a sensor key hashed with the pepper
// derived from the old key (the default when SENSOR_KEY_PEPPER is unset) or
// with the old key itself must still be among the peppers that verify.
func TestRotatedEncryptionKeyPeppers_KeepOldSensorKeysVerifying(t *testing.T) {
	const oldKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	const newKey = "ab00112233445566778899aabbccddeeff00112233445566778899aabbccddee"

	pepper, legacy := SensorKeyPeppers("", newKey, RotatedEncryptionKeyPeppers([]string{oldKey})...)
	if pepper != DeriveSensorKeyPepper(newKey) {
		t.Fatal("new sensor keys must be hashed with the pepper derived from the new key")
	}
	for _, want := range []string{DeriveSensorKeyPepper(oldKey), oldKey} {
		if !slices.Contains(legacy, want) {
			t.Errorf("legacy peppers miss a pepper of the rotated-out key")
		}
	}

	_, without := SensorKeyPeppers("", newKey)
	if slices.Contains(without, DeriveSensorKeyPepper(oldKey)) {
		t.Fatal("without the previous key its pepper must not verify")
	}
	if got := RotatedEncryptionKeyPeppers([]string{""}); len(got) != 0 {
		t.Fatalf("empty entries are ignored, got %v", got)
	}
}
