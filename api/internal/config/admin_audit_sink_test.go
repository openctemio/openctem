package config

import (
	"strings"
	"testing"
	"time"
)

const sinkTestSecret = "0123456789abcdef0123456789abcdef"

func TestValidateAdminAuditSink(t *testing.T) {
	good := AdminAuditSinkConfig{URL: "https://siem.example.com/audit", Secret: sinkTestSecret, HeadInterval: time.Minute}
	mut := func(f func(c *AdminAuditSinkConfig)) AdminAuditSinkConfig { c := good; f(&c); return c }
	cases := map[string]struct {
		cfg  AdminAuditSinkConfig
		want string
	}{
		"off":          {AdminAuditSinkConfig{}, ""},
		"good":         {good, ""},
		"secret alone": {AdminAuditSinkConfig{Secret: sinkTestSecret}, "ADMIN_AUDIT_SINK is not"},
		"ca alone":     {AdminAuditSinkConfig{SyslogCAFile: "/ca.pem"}, "ADMIN_AUDIT_SINK is not"},
		"short secret": {mut(func(c *AdminAuditSinkConfig) { c.Secret = "0123456789abcdef" }), "at least 32 bytes"},
		"no secret":    {mut(func(c *AdminAuditSinkConfig) { c.Secret = "" }), "at least 32 bytes"},
		"syslog":       {AdminAuditSinkConfig{URL: "syslog+tls://h:6514", HeadInterval: time.Minute}, ""},
		"file":         {AdminAuditSinkConfig{URL: "file:///var/log/a.jsonl", HeadInterval: time.Minute}, ""},
		"no interval":  {mut(func(c *AdminAuditSinkConfig) { c.HeadInterval = 0 }), "HEAD_INTERVAL"},
	}
	for name, tc := range cases {
		err := (&Config{AdminAuditSink: tc.cfg}).validateAdminAuditSink()
		if tc.want == "" && err != nil || tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
			t.Errorf("%s: err=%v want %q", name, err, tc.want)
		}
	}
	if s := good.String(); strings.Contains(s, "siem.example.com") || strings.Contains(s, good.Secret) {
		t.Errorf("String leaks: %s", s)
	}
}

func TestManagedProductionRequiresAdminAuditSink(t *testing.T) {
	sink := AdminAuditSinkConfig{URL: "file:///var/log/a.jsonl", HeadInterval: time.Minute}
	for name, tc := range map[string]struct {
		app     AppConfig
		sink    AdminAuditSinkConfig
		wantErr bool
	}{
		"managed production without sink":  {AppConfig{Env: EnvProduction, ManagedService: true}, AdminAuditSinkConfig{}, true},
		"managed production with sink":     {AppConfig{Env: EnvProduction, ManagedService: true}, sink, false},
		"managed development without sink": {AppConfig{Env: "development", ManagedService: true}, AdminAuditSinkConfig{}, false},
		"self-managed production no sink":  {AppConfig{Env: EnvProduction}, AdminAuditSinkConfig{}, false},
	} {
		err := (&Config{App: tc.app, AdminAuditSink: tc.sink}).validateAdminAuditSink()
		if (err != nil) != tc.wantErr || err != nil && !strings.Contains(err.Error(), "ADMIN_AUDIT_SINK") {
			t.Errorf("%s: err=%v", name, err)
		}
	}
}
