package postgres

import (
	"strings"
	"testing"

	"github.com/openctemio/openctem/server/pkg/domain/attribution"
)

// The liveness query spells the provider-address test out as a constant;
// it must stay the domain's definition.
func TestProviderAddressIDsSQLMatchesDomain(t *testing.T) {
	if !strings.HasSuffix(providerAddressIDsSQL, attribution.ProviderAddressSQL("pa")) {
		t.Fatalf("providerAddressIDsSQL drifted from attribution.ProviderAddressSQL:\n%s", providerAddressIDsSQL)
	}
}
