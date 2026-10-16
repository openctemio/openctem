package main

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func TestStartAdminAuditSink(t *testing.T) {
	stop, err := startAdminAuditSink(context.Background(), config.AdminAuditSinkConfig{}, nil, logger.NewNop())
	if err != nil || stop == nil {
		t.Fatalf("off: %v", err)
	}
	stop()
	// An unusable destination stops the start-up instead of running without
	// the copy the operator asked for.
	for _, bad := range []string{"http://collector.example/x", "syslog+tcp://nohostport", "ftp://x"} {
		if _, err := startAdminAuditSink(context.Background(), config.AdminAuditSinkConfig{URL: bad}, nil, logger.NewNop()); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if got := redactSinkURL("https://user:secret@collector.example/path?token=x"); got != "https://collector.example" {
		t.Fatalf("redacted: %q", got)
	}
}
