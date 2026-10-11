package config

import (
	"strings"
	"testing"
)

type fakeEnv map[string]string

func (f fakeEnv) lookup(k string) (string, bool) { v, ok := f[k]; return v, ok }

// A retired AGENT_* name is no longer read. Startup must refuse it rather than
// ignore it: an ignored AGENT_KEY_TTL would silently make sensor keys
// non-expiring.
func TestRejectRetiredEnv_FailsAndNamesReplacement(t *testing.T) {
	err := rejectRetiredEnv(fakeEnv{"AGENT_KEY_TTL": "24h", "AGENT_LB_CPU_WEIGHT": "0.9"}.lookup)
	if err == nil {
		t.Fatal("a retired AGENT_* variable must fail startup")
	}
	for _, want := range []string{"AGENT_KEY_TTL", "SENSOR_KEY_TTL", "AGENT_LB_CPU_WEIGHT", "SENSOR_LB_CPU_WEIGHT"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name %s", err, want)
		}
	}
}

func TestRejectRetiredEnv_EmptyValueStillFails(t *testing.T) {
	if err := rejectRetiredEnv(fakeEnv{"AGENT_PUBLIC_API_URL": ""}.lookup); err == nil {
		t.Fatal("a set-but-empty retired variable must fail startup too")
	}
}

func TestRejectRetiredEnv_NewNamesOnly(t *testing.T) {
	if err := rejectRetiredEnv(fakeEnv{"SENSOR_KEY_TTL": "24h"}.lookup); err != nil {
		t.Fatalf("new names only: %v", err)
	}
}

func TestLoad_RefusesRetiredEnvName(t *testing.T) {
	t.Setenv("AGENT_LB_CPU_WEIGHT", "0.9")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "SENSOR_LB_CPU_WEIGHT") {
		t.Fatalf("Load with AGENT_LB_CPU_WEIGHT set: err = %v, want a refusal naming SENSOR_LB_CPU_WEIGHT", err)
	}
}

// Knobs that switched nothing are refused too, each with what to do instead:
// a deployment file that sets them misleads whoever reads it.
func TestRejectRetiredEnv_DeadKnobsSayRemove(t *testing.T) {
	for _, name := range []string{"APP_DEBUG", "GRPC_PORT", "LOG_SKIP_HEALTH", "AI_MAX_CONCURRENT_JOBS", "AUTH_ALLOW_REGISTRATION"} {
		err := rejectRetiredEnv(fakeEnv{name: "false"}.lookup)
		if err == nil {
			t.Fatalf("%s set: want a refusal", name)
		}
		if !strings.Contains(err.Error(), name) || !strings.Contains(err.Error(), name+" (removed: unset it") {
			t.Errorf("%s: error %q does not name it and say to unset it", name, err)
		}
	}
}
