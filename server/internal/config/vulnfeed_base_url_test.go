package config

import "testing"

// The vulnerability feed is published in openctemio/vulnfeed-bundles (the
// collector code lives in openctemio/vulnfeed); VULNFEED_BASE_URL overrides.
func TestLoad_VulnFeedBaseURL(t *testing.T) {
	t.Setenv("VULNFEED_BASE_URL", "")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if want := "https://github.com/openctemio/vulnfeed-bundles/releases"; cfg.Worker.VulnFeedBaseURL != want {
		t.Errorf("default = %q, want %q", cfg.Worker.VulnFeedBaseURL, want)
	}
	t.Setenv("VULNFEED_BASE_URL", "https://mirror.example/feed")
	if cfg, err = Load(); err != nil || cfg.Worker.VulnFeedBaseURL != "https://mirror.example/feed" {
		t.Errorf("override not kept: %v %v", cfg, err)
	}
}
