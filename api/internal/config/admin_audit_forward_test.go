package config

import (
	"strings"
	"testing"
	"time"
)

func TestValidateAdminAuditForward(t *testing.T) {
	good := AdminAuditForwardConfig{URL: "https://siem.example.com/audit", Secret: "0123456789abcdef",
		BatchSize: 500, Interval: time.Second, HeadInterval: time.Hour, VerifyInterval: time.Hour, LagAlert: time.Minute}
	mut := func(f func(c *AdminAuditForwardConfig)) AdminAuditForwardConfig { c := good; f(&c); return c }
	cases := map[string]struct {
		cfg  AdminAuditForwardConfig
		want string
	}{
		"off":           {AdminAuditForwardConfig{}, ""},
		"good":          {good, ""},
		"secret alone":  {AdminAuditForwardConfig{Secret: "0123456789abcdef"}, "no sink"},
		"http":          {mut(func(c *AdminAuditForwardConfig) { c.URL = "http://siem.example.com/a" }), "https"},
		"credentials":   {mut(func(c *AdminAuditForwardConfig) { c.URL = "https://u:p@siem.example.com/a" }), "https"},
		"short secret":  {mut(func(c *AdminAuditForwardConfig) { c.Secret = "short" }), "SECRET"},
		"big batch":     {mut(func(c *AdminAuditForwardConfig) { c.BatchSize = 6000 }), "BATCH_SIZE"},
		"bad syslog":    {mut(func(c *AdminAuditForwardConfig) { c.SyslogAddr = "nohost" }), "SYSLOG_ADDR"},
		"zero interval": {mut(func(c *AdminAuditForwardConfig) { c.Interval = 0 }), "INTERVAL"},
	}
	for name, tc := range cases {
		err := (&Config{AdminAuditForward: tc.cfg}).validateAdminAuditForward()
		if tc.want == "" && err != nil || tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
			t.Errorf("%s: err=%v want %q", name, err, tc.want)
		}
	}
	if s := good.String(); strings.Contains(s, "siem.example.com") || strings.Contains(s, good.Secret) {
		t.Errorf("String leaks: %s", s)
	}
}
