package config

import (
	"os"
	"strings"
	"testing"
)

type fakeEnv map[string]string

func (f fakeEnv) lookup(k string) (string, bool) { v, ok := f[k]; return v, ok }
func (f fakeEnv) set(k, v string) error          { f[k] = v; return nil }

func TestResolveRenamedEnv_OldNameIsMappedWithWarning(t *testing.T) {
	env := fakeEnv{"AGENT_KEY_TTL": "720h"}
	warnings, err := resolveRenamedEnv(env.lookup, env.set)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if env["SENSOR_KEY_TTL"] != "720h" {
		t.Errorf("SENSOR_KEY_TTL = %q, want the value of AGENT_KEY_TTL", env["SENSOR_KEY_TTL"])
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "AGENT_KEY_TTL") || !strings.Contains(warnings[0], "SENSOR_KEY_TTL") {
		t.Errorf("want one warning naming both variables, got %v", warnings)
	}
}

func TestResolveRenamedEnv_NewNameWins_WhenEqual(t *testing.T) {
	env := fakeEnv{"AGENT_LB_CPU_WEIGHT": "0.5", "SENSOR_LB_CPU_WEIGHT": "0.5"}
	warnings, err := resolveRenamedEnv(env.lookup, env.set)
	if err != nil {
		t.Fatalf("equal values must not fail startup: %v", err)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "remove it") {
		t.Errorf("want a 'remove the old name' warning, got %v", warnings)
	}
}

func TestResolveRenamedEnv_ConflictFailsStartup(t *testing.T) {
	env := fakeEnv{"AGENT_PUBLIC_API_URL": "https://old.example", "SENSOR_PUBLIC_API_URL": "https://new.example"}
	_, err := resolveRenamedEnv(env.lookup, env.set)
	if err == nil {
		t.Fatal("conflicting old/new values must fail startup instead of picking one")
	}
	for _, name := range []string{"AGENT_PUBLIC_API_URL", "SENSOR_PUBLIC_API_URL"} {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("error %q must name %s", err, name)
		}
	}
}

func TestResolveRenamedEnv_NothingSetIsSilent(t *testing.T) {
	env := fakeEnv{"SENSOR_KEY_TTL": "24h"}
	warnings, err := resolveRenamedEnv(env.lookup, env.set)
	if err != nil || len(warnings) != 0 {
		t.Fatalf("new names only: want no warning and no error, got %v / %v", warnings, err)
	}
}

func TestLoad_ReadsDeprecatedEnvName(t *testing.T) {
	t.Setenv("AGENT_LB_CPU_WEIGHT", "0.9")
	// Load copies the value to the new name in the process environment.
	t.Cleanup(func() { _ = os.Unsetenv("SENSOR_LB_CPU_WEIGHT") })
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := cfg.Worker.LoadBalancing.CPUWeight; got != 0.9 {
		t.Errorf("CPUWeight = %v, want 0.9 taken from AGENT_LB_CPU_WEIGHT", got)
	}
	if len(cfg.Deprecations) == 0 {
		t.Error("Load must report the deprecated name so the server logs it")
	}
}
