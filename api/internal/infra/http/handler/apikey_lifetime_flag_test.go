package handler

import (
	"testing"

	apikeydom "github.com/openctemio/openctem/api/pkg/domain/apikey"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestExceedsLifetime(t *testing.T) {
	key := func(days int) *apikeydom.APIKey {
		k := apikeydom.NewAPIKey(shared.NewID(), shared.NewID(), "k", "hash", "oct_abcd")
		exp := k.CreatedAt().AddDate(0, 0, days)
		k.SetExpiresAt(&exp)
		return k
	}
	if !exceedsLifetime(key(365), 90) {
		t.Error("a one-year key under a 90-day maximum must be flagged")
	}
	if exceedsLifetime(key(90), 90) || exceedsLifetime(key(30), 90) {
		t.Error("a key within the maximum must not be flagged")
	}
	if exceedsLifetime(key(365), 0) {
		t.Error("an unknown maximum flags nothing")
	}
	noExpiry := apikeydom.NewAPIKey(shared.NewID(), shared.NewID(), "k", "hash", "oct_abcd")
	if exceedsLifetime(noExpiry, 90) {
		t.Error("a key without an expiry is not flagged here")
	}
}
