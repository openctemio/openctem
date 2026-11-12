package command

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// SECURITY (license): a platform job never runs semgrep, which fetches
// registry rules when the sensor has none (--config auto); opengrep and other
// tools are enqueued as before.
func TestSetPlatformJob_RefusesRegistryRuleTools(t *testing.T) {
	for _, scanner := range []string{"semgrep", " Semgrep "} {
		c := &Command{Payload: json.RawMessage(`{"scanner":"` + scanner + `","targets":["https://github.com/acme/app.git"]}`)}
		err := c.SetPlatformJob(5)
		if !errors.Is(err, ErrRegistryRulesOnPlatform) || !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("%q: err = %v", scanner, err)
		}
		if c.IsPlatformJob || c.QueuedAt != nil {
			t.Fatalf("%q: refused job was enqueued", scanner)
		}
	}
	for _, scanner := range []string{"opengrep", "nuclei", "trivy", ""} {
		c := &Command{Payload: json.RawMessage(`{"scanner":"` + scanner + `"}`)}
		if err := c.SetPlatformJob(5); err != nil || !c.IsPlatformJob || c.QueuePriority != 5 || c.QueuedAt == nil {
			t.Fatalf("%q: err=%v job=%+v", scanner, err, c)
		}
	}
	c := &Command{Payload: json.RawMessage(`not json`)}
	if err := c.SetPlatformJob(1); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("unreadable payload: %v", err)
	}
	if err := (&Command{}).SetPlatformJob(1); err != nil {
		t.Fatalf("empty payload: %v", err)
	}
}
