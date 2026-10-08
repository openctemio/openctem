package scope

import (
	"errors"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A pattern the caller got wrong is a validation error (HTTP 400), never an
// unclassified error the handlers answer with 500.
func TestValidatePattern_RefusalsAreValidationErrors(t *testing.T) {
	cases := []struct {
		typ     TargetType
		pattern string
	}{
		{TargetTypeDomain, ""},
		{TargetTypeDomain, strings.Repeat("a", 501)},
		{TargetTypeDomain, "exa mple.com"},
		{TargetTypeIPAddress, "300.1.1.1"},
		{TargetTypeCIDR, "10.0.0.0/99"},
		{TargetTypeRepository, "not a repo"},
		{TargetTypeCloudAccount, "123456789012"},
		{TargetTypeCloudAccount, "OCI:tenancy"},
		{TargetTypeURL, "ftp://example.com"},
	}
	for _, c := range cases {
		err := ValidatePattern(c.typ, c.pattern)
		if err == nil {
			t.Fatalf("%s %q: accepted", c.typ, c.pattern)
		}
		if !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("%s %q: %v is not a validation error", c.typ, c.pattern, err)
		}
	}
	if _, err := ParseTargetType("nope"); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("ParseTargetType: %v is not a validation error", err)
	}
	if _, err := ParseExclusionType("nope"); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("ParseExclusionType: %v is not a validation error", err)
	}
}

// A bare 12-digit AWS account id is refused with the accepted form.
func TestValidatePattern_BareAWSAccountIDHint(t *testing.T) {
	err := ValidatePattern(TargetTypeCloudAccount, "123456789012")
	if err == nil || !strings.Contains(err.Error(), "AWS:123456789012") {
		t.Fatalf("got %v, want a hint naming AWS:123456789012", err)
	}
	if err := ValidatePattern(TargetTypeCloudAccount, "AWS:123456789012"); err != nil {
		t.Fatalf("AWS:123456789012 refused: %v", err)
	}
}
