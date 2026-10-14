package cirun

import (
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Every provider but Azure Pipelines needs an audience that names the
// tenant: a token minted for one organization is useless to another.
func TestTrustAudienceNamesTheTenant(t *testing.T) {
	tenant := shared.NewID()
	for _, p := range []Provider{ProviderGitHub, ProviderGitLab} {
		c := TrustConfig{TenantID: tenant, Name: "x", Provider: p, Audience: "https://openctem.example.com",
			Rules: Rules{Owners: []string{"acme"}}}
		c.Normalize()
		if err := c.Validate(); err == nil {
			t.Errorf("%s: an audience without the tenant id was accepted", p)
		}
		c.Audience = ""
		c.Normalize()
		if err := c.Validate(); err != nil || c.Audience != DefaultAudience(tenant) {
			t.Errorf("%s: default audience %q refused: %v", p, c.Audience, err)
		}
	}
	if TenantBoundAudience(ProviderAzureDevOps) {
		t.Error("Azure Pipelines has one fixed audience")
	}
}

func TestLegacyAccepted(t *testing.T) {
	now := time.Now()
	until := now.Add(time.Hour)
	c := TrustConfig{Audience: "openctem:tenant:x", LegacyAudience: "old", LegacyAudienceUntil: &until}
	if !c.LegacyAccepted("old", now) || c.LegacyAccepted("old", until) || c.LegacyAccepted("other", now) || c.LegacyAccepted("openctem:tenant:x", now) {
		t.Fatal("LegacyAccepted")
	}
	c.LegacyAudienceUntil = nil
	if c.LegacyAccepted("old", now) {
		t.Fatal("no end date must not accept")
	}
}
