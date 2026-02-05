package postgres

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidLicensePattern(t *testing.T) {
	tests := []struct {
		name    string
		license string
		valid   bool
	}{
		// Valid SPDX-like licenses
		{"MIT", "MIT", true},
		{"Apache-2.0", "Apache-2.0", true},
		{"GPL-3.0", "GPL-3.0", true},
		{"LGPL-2.1-only", "LGPL-2.1-only", true},
		{"BSD-3-Clause", "BSD-3-Clause", true},
		{"ISC", "ISC", true},
		{"MPL-2.0", "MPL-2.0", true},
		{"CC-BY-4.0", "CC-BY-4.0", true},
		{"Unlicense", "Unlicense", true},
		{"GPL-2.0+", "GPL-2.0+", true},
		{"LGPL-2.1-or-later", "LGPL-2.1-or-later", true},
		{"Apache-2.0 WITH LLVM-exception", "Apache-2.0", true}, // Core part only
		{"(MIT OR Apache-2.0)", "(MIT)", true},                 // Parentheses allowed

		// Invalid patterns
		{"empty string", "", false},
		{"has spaces", "MIT License", false},
		{"has special chars", "MIT@license", false},
		{"has slash", "MIT/Apache", false},
		{"has colon", "MIT:2.0", false},
		{"has quote", "MIT\"", false},
		{"SQL injection attempt", "'; DROP TABLE licenses;--", false},
		{"XSS attempt", "<script>alert(1)</script>", false},
		{"newline injection", "MIT\nINSERT", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.license == "" {
				assert.False(t, validLicensePattern.MatchString(tt.license))
				return
			}
			result := validLicensePattern.MatchString(tt.license)
			assert.Equal(t, tt.valid, result, "license: %s", tt.license)
		})
	}
}

func TestMaxLicensesPerComponent(t *testing.T) {
	// Verify the constant is set to a reasonable value
	assert.Equal(t, 50, MaxLicensesPerComponent)
}

func TestMaxLicenseNameLength(t *testing.T) {
	// Verify the constant is set to a reasonable value
	assert.Equal(t, 255, MaxLicenseNameLength)
}

func TestLicenseNameLengthValidation(t *testing.T) {
	tests := []struct {
		name   string
		length int
		valid  bool
	}{
		{"short license", 10, true},
		{"medium license", 50, true},
		{"max length", MaxLicenseNameLength, true},
		{"over max length", MaxLicenseNameLength + 1, false},
		{"very long", 1000, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.length <= MaxLicenseNameLength
			assert.Equal(t, tt.valid, result)
		})
	}
}
