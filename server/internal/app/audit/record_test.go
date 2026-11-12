package audit_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type failingWriter struct{ err error }

func (w failingWriter) LogEvent(context.Context, auditapp.AuditContext, auditapp.AuditEvent) error {
	return w.err
}

func TestRecordOrWarn_LogsSanitizedFailure(t *testing.T) {
	var buf bytes.Buffer
	cfg := logger.DefaultConfig()
	cfg.Output = &buf
	log := logger.New(cfg)

	ev := auditapp.NewSuccessEvent(auditdom.ActionScopeTargetCreated, auditdom.ResourceTypeScopeTarget, "t-1")
	auditapp.RecordOrWarn(context.Background(), log, failingWriter{err: errors.New("db down\nFORGED line")}, auditapp.AuditContext{}, ev)

	out := buf.String()
	if !strings.Contains(out, "audit event was not recorded") || !strings.Contains(out, "t-1") {
		t.Fatalf("failure not logged: %q", out)
	}
	if strings.Contains(out, "\nFORGED") {
		t.Fatalf("log line forged: %q", out)
	}
}

func TestRecordOrWarn_SuccessIsQuiet(t *testing.T) {
	var buf bytes.Buffer
	cfg := logger.DefaultConfig()
	cfg.Output = &buf
	ev := auditapp.NewSuccessEvent(auditdom.ActionScopeTargetCreated, auditdom.ResourceTypeScopeTarget, "t-1")
	auditapp.RecordOrWarn(context.Background(), logger.New(cfg), failingWriter{}, auditapp.AuditContext{}, ev)
	if buf.Len() != 0 {
		t.Fatalf("unexpected output %q", buf.String())
	}
}
