package unit

import (
	"context"
	"testing"

	auditsvc "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/httpsec"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// An audit row written during a request carries the request id and the
// client address the HTTP middleware put on the context, even when the caller
// built AuditContext without them (most callers do).
func TestLogEvent_FillsRequestIDAndClientIPFromContext(t *testing.T) {
	repo := newMockAuditRepo()
	svc := auditsvc.NewAuditService(repo, logger.NewNop())
	ctx := context.WithValue(context.Background(), logger.ContextKeyRequestID, "req-123")
	ctx = httpsec.WithClientIP(ctx, "203.0.113.7")

	ev := auditsvc.NewSuccessEvent(audit.ActionSettingsUpdated, audit.ResourceTypeSettings, "s-1")
	if err := svc.LogEvent(ctx, auditsvc.AuditContext{TenantID: "019a0000-0000-7000-8000-000000000001"}, ev); err != nil {
		t.Fatal(err)
	}
	got := onlyLog(t, repo)
	if got.RequestID() != "req-123" || got.ActorIP() != "203.0.113.7" {
		t.Fatalf("request_id=%q actor_ip=%q, want req-123 / 203.0.113.7", got.RequestID(), got.ActorIP())
	}
}

// The caller's explicit values win over the context, and background work
// (no request on the context) records neither.
func TestLogEvent_ExplicitValuesWinAndBackgroundRecordsNone(t *testing.T) {
	repo := newMockAuditRepo()
	svc := auditsvc.NewAuditService(repo, logger.NewNop())
	ctx := context.WithValue(context.Background(), logger.ContextKeyRequestID, "req-ctx")
	ctx = httpsec.WithClientIP(ctx, "203.0.113.7")
	ev := auditsvc.NewSuccessEvent(audit.ActionSettingsUpdated, audit.ResourceTypeSettings, "s-1")
	if err := svc.LogEvent(ctx, auditsvc.AuditContext{RequestID: "req-explicit", ActorIP: "198.51.100.9"}, ev); err != nil {
		t.Fatal(err)
	}
	got := onlyLog(t, repo)
	if got.RequestID() != "req-explicit" || got.ActorIP() != "198.51.100.9" {
		t.Fatalf("explicit values overridden: request_id=%q actor_ip=%q", got.RequestID(), got.ActorIP())
	}

	repo = newMockAuditRepo()
	svc = auditsvc.NewAuditService(repo, logger.NewNop())
	if err := svc.LogEvent(context.Background(), auditsvc.AuditContext{}, ev); err != nil {
		t.Fatal(err)
	}
	got = onlyLog(t, repo)
	if got.RequestID() != "" || got.ActorIP() != "" {
		t.Fatalf("background event got request_id=%q actor_ip=%q", got.RequestID(), got.ActorIP())
	}
}

func onlyLog(t *testing.T, repo *mockAuditRepo) *audit.AuditLog {
	t.Helper()
	if len(repo.logs) != 1 {
		t.Fatalf("logs = %d, want 1", len(repo.logs))
	}
	for _, l := range repo.logs {
		return l
	}
	return nil
}
