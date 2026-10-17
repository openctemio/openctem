package main

import (
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func TestAdminAuditSinkForwarder(t *testing.T) {
	repo := postgres.NewAuditLogRepository(nil)
	secret := "0123456789abcdef0123456789abcdef"
	// An unusable destination stops the start-up instead of running without
	// the copy the operator asked for.
	for _, bad := range []config.AdminAuditSinkConfig{
		{URL: "http://collector.example/x", Secret: secret},
		{URL: "syslog+tcp://h:514"},
		{URL: "syslog+udp://h:514"},
		{URL: "https://collector.example/x"},
		{URL: "ftp://x"},
	} {
		if _, err := adminAuditSinkForwarder(bad, repo, logger.NewNop()); err == nil {
			t.Errorf("%q accepted", bad.URL)
		}
	}
	ok := config.AdminAuditSinkConfig{URL: "https://collector.example/x", Secret: secret, HeadInterval: time.Minute}
	if f, err := adminAuditSinkForwarder(ok, repo, logger.NewNop()); err != nil || f.Name() != "admin-audit-sink" || !f.Exclusive() {
		t.Errorf("good config: %v", err)
	}
	if got := redactSinkURL("https://user:secret@collector.example/path?token=x"); got != "https://collector.example" {
		t.Fatalf("redacted: %q", got)
	}
}
