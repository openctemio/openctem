package server

import (
	"context"
	"strings"
	"testing"

	"github.com/openctemio/openctem/server/internal/config"
	"github.com/openctemio/openctem/server/pkg/logger"
)

func samlURLConfig(env, appURL string) *config.Config {
	cfg := &config.Config{}
	cfg.App.Env = env
	cfg.App.URL = appURL
	cfg.Server.Port = 8080
	return cfg
}

// The SAML origin is APP_URL. Without it production has none (the routes
// refuse); any other mode uses localhost.
func TestSAMLPublicURL(t *testing.T) {
	log := logger.NewNop()
	cases := []struct {
		env, appURL, want string
	}{
		{config.EnvProduction, "https://ctem.example.com", "https://ctem.example.com"},
		{"development", "https://ctem.example.com", "https://ctem.example.com"},
		{config.EnvProduction, "", ""},
		{config.EnvProduction, "   ", ""},
		{"development", "", "http://localhost:8080"},
		{"test", "", "http://localhost:8080"},
	}
	for _, c := range cases {
		if got := samlPublicURL(samlURLConfig(c.env, c.appURL), log); got != c.want {
			t.Errorf("env %q APP_URL %q: got %q, want %q", c.env, c.appURL, got, c.want)
		}
	}
}

// The start-up check reads the database only for the one unsafe combination:
// production without APP_URL. A nil database here would panic if it were read.
func TestRequireSAMLPublicURL_SkipsWhenConfiguredOrNotProduction(t *testing.T) {
	ctx := context.Background()
	for _, cfg := range []*config.Config{
		samlURLConfig(config.EnvProduction, "https://ctem.example.com"),
		samlURLConfig("development", ""),
		samlURLConfig("development", "https://ctem.example.com"),
	} {
		if err := requireSAMLPublicURL(ctx, nil, cfg); err != nil {
			t.Errorf("env %q APP_URL %q: %v, want no refusal", cfg.App.Env, cfg.App.URL, err)
		}
	}
	if err := requireSAMLPublicURL(ctx, nil, samlURLConfig(config.EnvProduction, "")); err != nil {
		t.Errorf("no database (bootstrap): %v, want no refusal", err)
	}
	if !strings.Contains(samlPublicURL(samlURLConfig("development", ""), logger.NewNop()), "localhost") {
		t.Error("development falls back to localhost")
	}
}
