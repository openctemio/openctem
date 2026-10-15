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

// Cookie names are fixed: an override reached the API but not the web
// console's browser bundle or the gateway, which split the session.
func TestCookieNamesFixed(t *testing.T) {
	for _, name := range []string{"AUTH_ACCESS_TOKEN_COOKIE_NAME", "AUTH_REFRESH_TOKEN_COOKIE_NAME", "AUTH_TENANT_COOKIE_NAME"} {
		if err := rejectRetiredEnv(fakeEnv{name: "x"}.lookup); err == nil || !strings.Contains(err.Error(), name+" (removed:") {
			t.Errorf("%s set: err = %v, want a refusal", name, err)
		}
	}
	t.Setenv("APP_ENV", "development")
	t.Setenv("AUTH_JWT_SECRET", strings.Repeat("a", 64))
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Auth.AccessTokenCookieName != "auth_token" || cfg.Auth.RefreshTokenCookieName != "refresh_token" || cfg.Auth.TenantCookieName != "app_tenant" {
		t.Errorf("cookie names = %q %q %q", cfg.Auth.AccessTokenCookieName, cfg.Auth.RefreshTokenCookieName, cfg.Auth.TenantCookieName)
	}
}

// The platform-wide Jira webhook secret was removed (each organization has
// its own). Startup refuses it, even empty, and says what to do instead.
func TestLoad_RefusesRemovedJiraWebhookSecret(t *testing.T) {
	t.Setenv("JIRA_WEBHOOK_SECRET", "")
	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "JIRA_WEBHOOK_SECRET (removed:") ||
		!strings.Contains(err.Error(), "/api/v1/integrations/{id}/jira-webhook/secret/rotate") {
		t.Fatalf("want JIRA_WEBHOOK_SECRET refused with the per-organization remedy, got %v", err)
	}
}
