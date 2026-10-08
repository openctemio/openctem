package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/config"
)

func TestReportConfigCheck(t *testing.T) {
	var out, errOut bytes.Buffer
	if rc := reportConfigCheck(&out, &errOut, nil, errors.New("AUTH_JWT_SECRET is required")); rc != 1 {
		t.Fatalf("invalid config exit = %d, want 1", rc)
	}
	if !strings.Contains(errOut.String(), "INVALID") || !strings.Contains(errOut.String(), "AUTH_JWT_SECRET") {
		t.Fatalf("stderr = %q, want the load error", errOut.String())
	}

	out.Reset()
	errOut.Reset()
	cfg := &config.Config{}
	cfg.App.Env = config.EnvProduction
	cfg.Auth.Provider = config.AuthProviderLocal
	cfg.Auth.JWTSecret = "must-never-be-printed-by-the-check-0123456789abcdef0123456789abcdef"
	if rc := reportConfigCheck(&out, &errOut, cfg, nil); rc != 0 {
		t.Fatalf("valid config exit = %d, want 0", rc)
	}
	if !strings.Contains(out.String(), "APP_ENV=production") || strings.Contains(out.String(), "note:") {
		t.Fatalf("stdout = %q", out.String())
	}
	if strings.Contains(out.String(), cfg.Auth.JWTSecret) {
		t.Fatal("the check printed a secret")
	}

	out.Reset()
	cfg.App.Env = "development"
	reportConfigCheck(&out, &errOut, cfg, nil)
	if !strings.Contains(out.String(), "skips the production checks") {
		t.Fatalf("development not flagged: %q", out.String())
	}
}
