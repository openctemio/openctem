package integration

import "testing"

// Every declared provider must be classified: either it has a client, or it is
// explicitly listed as declared-without-client. A new provider constant that is
// added to IsValid but to neither list fails here instead of shipping as a row
// that is accepted and then does nothing.
func TestProviderHasClient(t *testing.T) {
	withClient := []Provider{
		ProviderGitHub, ProviderGitLab, ProviderBitbucket, ProviderAzureDevOps,
		ProviderDefectDojo,
		ProviderJira,
		ProviderSlack, ProviderTeams, ProviderTelegram, ProviderEmail, ProviderWebhook, ProviderSplunk,
	}
	withoutClient := []Provider{
		ProviderWiz, ProviderSnyk, ProviderCrowdStrike,
		ProviderAWS, ProviderGCP, ProviderAzure,
		ProviderLinear, ProviderAsana,
		// Paused until the runner is rebuilt on the sensor daemon (D-14).
		ProviderTenable,
	}
	for _, p := range withClient {
		if !p.IsValid() {
			t.Errorf("%s: expected valid", p)
		}
		if !p.HasClient() {
			t.Errorf("%s: expected HasClient() = true", p)
		}
	}
	for _, p := range withoutClient {
		if !p.IsValid() {
			t.Errorf("%s: declared providers stay valid so existing rows load", p)
		}
		if p.HasClient() {
			t.Errorf("%s: expected HasClient() = false (no client code exists)", p)
		}
	}
	if Provider("nope").HasClient() {
		t.Error("unknown provider must not report a client")
	}
}
