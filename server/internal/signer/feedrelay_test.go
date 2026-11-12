package signer

import (
	"crypto/ed25519"
	"testing"

	"github.com/openctemio/openctem/api/pkg/jobsign"
)

const tOrigin = "https://github.com/openctemio/vulnfeed-bundles/releases/latest/download"

// relayStatement is a valid feed relay statement with edits applied.
func relayStatement(edit func(m map[string]any)) []byte {
	return statement(func(m map[string]any) {
		m["tenant_id"] = jobsign.PlatformTenantID
		m["sensor_scope"] = jobsign.SensorScopeInstance
		m["command_type"] = jobsign.CommandTypeFeedRelay
		m["tool"] = ""
		m["targets"] = []string{tOrigin}
		m["lease_epoch"] = 0
		if edit != nil {
			edit(m)
		}
	})
}

// A feed relay statement is signed for an allowlisted origin on a platform
// sensor, with the platform tenant id, and with no scope ledger lookup (the
// ledger is enforcing and empty here).
func TestSign_FeedRelaySigned(t *testing.T) {
	s := newService(t, t.TempDir(), newKey(t), func(c *Config) { c.LedgerMode = jobsign.LedgerEnforce })
	env, ref := s.Sign(relayStatement(nil))
	if ref != nil {
		t.Fatalf("refused: %s %s", ref.reason, ref.detail)
	}
	pub, _ := s.key.Public().(ed25519.PublicKey)
	st, err := jobsign.Verify(env, []ed25519.PublicKey{pub})
	if err != nil {
		t.Fatal(err)
	}
	if st.CommandType != jobsign.CommandTypeFeedRelay || st.TenantID != jobsign.PlatformTenantID ||
		st.SensorScope != jobsign.SensorScopeInstance || st.Seq == 0 {
		t.Fatalf("signed statement %+v", st)
	}
}

// The rules a compromised API cannot relax: the platform tenant id only for
// a feed relay and the reverse, only on a platform sensor, no tool or other
// payload members, and only origins in the signer's own allowlist.
func TestSign_FeedRelayRefused(t *testing.T) {
	s := newService(t, t.TempDir(), newKey(t), func(c *Config) {
		c.FeedOrigins = []string{tOrigin, "https://mirror.example.com/feeds/vulnfeed/"}
	})
	cases := []struct {
		name   string
		raw    []byte
		reason string
	}{
		{"origin not allowlisted", relayStatement(func(m map[string]any) {
			m["targets"] = []string{"https://attacker.example.net/latest/download"}
		}), ReasonFeedRelayOrigin},
		{"one origin of two not allowlisted", relayStatement(func(m map[string]any) {
			m["targets"] = []string{tOrigin, "https://github.com/someone/else/releases/latest/download"}
		}), ReasonFeedRelayOrigin},
		{"internal origin", relayStatement(func(m map[string]any) {
			m["targets"] = []string{"https://10.0.0.5/feed"}
		}), ReasonFeedRelayOrigin},
		{"http origin", relayStatement(func(m map[string]any) {
			m["targets"] = []string{"http://github.com/openctemio/vulnfeed-bundles/releases/latest/download"}
		}), ReasonFeedRelayShape},
		{"origin with query", relayStatement(func(m map[string]any) { m["targets"] = []string{tOrigin + "?x=1"} }), ReasonFeedRelayShape},
		{"origin not canonical", relayStatement(func(m map[string]any) { m["targets"] = []string{tOrigin + "/"} }), ReasonFeedRelayShape},
		{"origin with credentials", relayStatement(func(m map[string]any) {
			m["targets"] = []string{"https://u:p@github.com/openctemio/vulnfeed-bundles/releases/latest/download"}
		}), ReasonFeedRelayShape},
		{"no origin", relayStatement(func(m map[string]any) { m["targets"] = []string{} }), ReasonFeedRelayShape},
		{"organization sensor", relayStatement(func(m map[string]any) { delete(m, "sensor_scope") }), ReasonFeedRelayShape},
		{"organization tenant", relayStatement(func(m map[string]any) { m["tenant_id"] = tTenant }), ReasonPlatformTenant},
		{"names a tool", relayStatement(func(m map[string]any) { m["tool"] = "nuclei" }), ReasonFeedRelayShape},
		{"custom templates", relayStatement(func(m map[string]any) {
			m["templates"] = []string{jobsign.PayloadDigest([]byte("t"))}
		}), ReasonFeedRelayShape},
		{"platform tenant on a scan", statement(func(m map[string]any) {
			m["tenant_id"] = jobsign.PlatformTenantID
			m["sensor_scope"] = jobsign.SensorScopeInstance
		}), ReasonPlatformTenant},
		{"platform tenant on an organization job", statement(func(m map[string]any) {
			m["tenant_id"] = jobsign.PlatformTenantID
		}), ReasonPlatformTenant},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env, ref := s.Sign(tc.raw)
			if ref == nil {
				t.Fatalf("signed: %s", env)
			}
			if ref.reason != tc.reason {
				t.Fatalf("refused with %s (%s), want %s", ref.reason, ref.detail, tc.reason)
			}
		})
	}
	// The configured mirror (written with a trailing slash) is allowed in
	// its canonical spelling.
	if _, ref := s.Sign(relayStatement(func(m map[string]any) {
		m["targets"] = []string{tOrigin, "https://mirror.example.com/feeds/vulnfeed"}
	})); ref != nil {
		t.Fatalf("mirror refused: %s %s", ref.reason, ref.detail)
	}
}

// An empty allowlist ("none") signs no feed relay at all; the defaults are
// the official origins only.
func TestSign_FeedRelayAllowlistConfig(t *testing.T) {
	none := newService(t, t.TempDir(), newKey(t), func(c *Config) { c.FeedOrigins = []string{} })
	if _, ref := none.Sign(relayStatement(nil)); ref == nil || ref.reason != ReasonFeedRelayOrigin {
		t.Fatalf("empty allowlist: %+v", ref)
	}
	if _, err := New(Config{Key: newKey(t), StateDir: t.TempDir(), FeedOrigins: []string{"http://x.example"}}); err == nil {
		t.Fatal("a non-https origin was accepted in the allowlist")
	}
	origins, ok := jobsign.ParseFeedOrigins("")
	if !ok || len(origins) != len(jobsign.DefaultFeedOrigins) {
		t.Fatalf("defaults: %v %v", origins, ok)
	}
	if o, ok := jobsign.ParseFeedOrigins("none"); !ok || len(o) != 0 {
		t.Fatalf("none: %v %v", o, ok)
	}
	if _, ok := jobsign.ParseFeedOrigins("https://ok.example/x,ftp://bad.example"); ok {
		t.Fatal("a bad entry was accepted")
	}
}
