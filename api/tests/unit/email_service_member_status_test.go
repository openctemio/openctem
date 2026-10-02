package unit

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/openctemio/api/internal/app"
	emaildom "github.com/openctemio/api/pkg/email"
)

// tenantSMTPResolverMock implements app.TenantSMTPResolver for testing
// the per-tenant-SMTP resolution branch inside
// EmailService.getSenderForTenant.
//
// We intentionally only model the three observable fallback branches
// (nil resolver, resolver returns error, resolver returns nil cfg) at
// unit level. The happy-path where a real *emaildom.Config is returned
// causes EmailService to call emaildom.NewSMTPSender(*cfg), which opens
// a network socket — exercised by the integration tier instead.
type tenantSMTPResolverMock struct {
	calls         int
	lastTenantID  string
	returnedCfg   *emaildom.Config
	returnedError error
}

func (m *tenantSMTPResolverMock) GetTenantSMTPConfig(_ context.Context, tenantID string) (*emaildom.Config, error) {
	m.calls++
	m.lastTenantID = tenantID
	return m.returnedCfg, m.returnedError
}

// =============================================================================
// SendMemberSuspendedEmail — happy path
// =============================================================================

func TestEmailService_SendMemberSuspendedEmail_Success(t *testing.T) {
	mock := &emailMockSender{isConfigured: true}
	svc := emailNewService(mock)

	err := svc.SendMemberSuspendedEmail(
		context.Background(),
		"user@example.com",
		"Jane",
		"Acme Corp",
		"Admin Alice",
		"tenant-xyz",
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if mock.sendTemplateCalls != 1 {
		t.Fatalf("expected 1 SendTemplate call, got %d", mock.sendTemplateCalls)
	}
	if mock.lastTo != "user@example.com" {
		t.Errorf("expected to=user@example.com, got %s", mock.lastTo)
	}
	if mock.lastTemplate != emaildom.TemplateMemberSuspended {
		t.Errorf("expected template=%s, got %s", emaildom.TemplateMemberSuspended, mock.lastTemplate)
	}

	data, ok := mock.lastData.(emaildom.MemberStatusChangeData)
	if !ok {
		t.Fatalf("expected MemberStatusChangeData, got %T", mock.lastData)
	}
	if data.UserName != "Jane" {
		t.Errorf("expected UserName=Jane, got %s", data.UserName)
	}
	if data.TeamName != "Acme Corp" {
		t.Errorf("expected TeamName=Acme Corp, got %s", data.TeamName)
	}
	if data.ActorName != "Admin Alice" {
		t.Errorf("expected ActorName=Admin Alice, got %s", data.ActorName)
	}
	if data.AppURL != "https://app.example.com" {
		t.Errorf("expected AppURL=https://app.example.com, got %s", data.AppURL)
	}
	if data.AppName != "OpenCTEM" {
		t.Errorf("expected AppName=OpenCTEM, got %s", data.AppName)
	}
}

// =============================================================================
// SendMemberSuspendedEmail — best-effort contract: MUST NOT return an error
// when the email service is not configured, and MUST NOT attempt to send.
// This protects the suspend flow from being blocked on notification failure.
// =============================================================================

func TestEmailService_SendMemberSuspendedEmail_NotConfigured(t *testing.T) {
	mock := &emailMockSender{isConfigured: false}
	svc := emailNewService(mock)

	err := svc.SendMemberSuspendedEmail(
		context.Background(), "u@e.com", "U", "T", "A", "tenant-xyz",
	)
	if err != nil {
		t.Fatalf("expected nil when sender not configured (best-effort), got: %v", err)
	}
	if mock.sendTemplateCalls != 0 {
		t.Errorf("expected 0 SendTemplate calls when not configured, got %d", mock.sendTemplateCalls)
	}
}

func TestEmailService_SendMemberSuspendedEmail_NilSender(t *testing.T) {
	svc := app.NewEmailService(nil, emailTestConfig(), "OpenCTEM", emailTestLogger())

	err := svc.SendMemberSuspendedEmail(
		context.Background(), "u@e.com", "U", "T", "A", "tenant-xyz",
	)
	if err != nil {
		t.Fatalf("expected nil when sender is nil (best-effort), got: %v", err)
	}
}

// =============================================================================
// SendMemberSuspendedEmail — error wrapping: underlying sender error must be
// preserved through errors.Is so callers can distinguish transport failures.
// =============================================================================

func TestEmailService_SendMemberSuspendedEmail_SenderError(t *testing.T) {
	sendErr := errors.New("smtp connection refused")
	mock := &emailMockSender{isConfigured: true, sendErr: sendErr}
	svc := emailNewService(mock)

	err := svc.SendMemberSuspendedEmail(
		context.Background(), "u@e.com", "U", "T", "A", "tenant-xyz",
	)
	if err == nil {
		t.Fatal("expected error when sender fails")
	}
	if !errors.Is(err, sendErr) {
		t.Errorf("expected wrapped sendErr via errors.Is, got: %v", err)
	}
}

// =============================================================================
// SendMemberReactivatedEmail — same five contract tests, different template.
// =============================================================================

func TestEmailService_SendMemberReactivatedEmail_Success(t *testing.T) {
	mock := &emailMockSender{isConfigured: true}
	svc := emailNewService(mock)

	err := svc.SendMemberReactivatedEmail(
		context.Background(),
		"user@example.com",
		"Bob",
		"Acme Corp",
		"Admin Alice",
		"tenant-xyz",
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if mock.sendTemplateCalls != 1 {
		t.Fatalf("expected 1 SendTemplate call, got %d", mock.sendTemplateCalls)
	}
	if mock.lastTemplate != emaildom.TemplateMemberReactivated {
		t.Errorf("expected template=%s, got %s", emaildom.TemplateMemberReactivated, mock.lastTemplate)
	}

	data, ok := mock.lastData.(emaildom.MemberStatusChangeData)
	if !ok {
		t.Fatalf("expected MemberStatusChangeData, got %T", mock.lastData)
	}
	if data.UserName != "Bob" {
		t.Errorf("expected UserName=Bob, got %s", data.UserName)
	}
	if data.TeamName != "Acme Corp" {
		t.Errorf("expected TeamName=Acme Corp, got %s", data.TeamName)
	}
	if data.ActorName != "Admin Alice" {
		t.Errorf("expected ActorName=Admin Alice, got %s", data.ActorName)
	}
}

func TestEmailService_SendMemberReactivatedEmail_NotConfigured(t *testing.T) {
	mock := &emailMockSender{isConfigured: false}
	svc := emailNewService(mock)

	err := svc.SendMemberReactivatedEmail(
		context.Background(), "u@e.com", "U", "T", "A", "tenant-xyz",
	)
	if err != nil {
		t.Fatalf("expected nil when not configured (best-effort), got: %v", err)
	}
	if mock.sendTemplateCalls != 0 {
		t.Errorf("expected 0 SendTemplate calls when not configured, got %d", mock.sendTemplateCalls)
	}
}

func TestEmailService_SendMemberReactivatedEmail_SenderError(t *testing.T) {
	sendErr := errors.New("dial tcp: i/o timeout")
	mock := &emailMockSender{isConfigured: true, sendErr: sendErr}
	svc := emailNewService(mock)

	err := svc.SendMemberReactivatedEmail(
		context.Background(), "u@e.com", "U", "T", "A", "tenant-xyz",
	)
	if err == nil {
		t.Fatal("expected error when sender fails")
	}
	if !errors.Is(err, sendErr) {
		t.Errorf("expected wrapped sendErr via errors.Is, got: %v", err)
	}
}

// =============================================================================
// ActorName may be empty (the audit context can legitimately lack an actor
// in the bootstrap/automated-reactivate paths). The template must still
// render — the current implementation just leaves ActorName blank in the
// body. This test pins that contract so it isn't broken by a future
// "require actor" refactor.
// =============================================================================

func TestEmailService_SendMemberSuspendedEmail_EmptyActorNameAllowed(t *testing.T) {
	mock := &emailMockSender{isConfigured: true}
	svc := emailNewService(mock)

	err := svc.SendMemberSuspendedEmail(
		context.Background(), "u@e.com", "U", "T",
		"", // actorName empty — automated / system-level suspension
		"tenant-xyz",
	)
	if err != nil {
		t.Fatalf("unexpected error with empty actor name: %v", err)
	}
	if mock.sendTemplateCalls != 1 {
		t.Fatalf("expected 1 SendTemplate call, got %d", mock.sendTemplateCalls)
	}
	data := mock.lastData.(emaildom.MemberStatusChangeData)
	if data.ActorName != "" {
		t.Errorf("expected ActorName to stay empty, got %q", data.ActorName)
	}
}

// =============================================================================
// Per-tenant SMTP resolver is consulted whenever tenantID is non-empty.
// We cover the three fallback branches (resolver nil, resolver errors,
// resolver returns nil cfg) at unit level. The happy-path where a real
// *emaildom.Config is returned builds a live emaildom.SMTPSender and
// attempts a network dial, which is covered at the integration tier.
// =============================================================================

func TestEmailService_MemberStatus_NoResolver_UsesDefaultSender(t *testing.T) {
	mock := &emailMockSender{isConfigured: true}
	svc := emailNewService(mock)
	// Do NOT call SetTenantSMTPResolver — resolver stays nil.

	if err := svc.SendMemberSuspendedEmail(
		context.Background(), "u@e.com", "U", "T", "A", "tenant-xyz",
	); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mock.sendTemplateCalls != 1 {
		t.Errorf("expected default sender to be used when resolver is nil, got 0 calls")
	}
}

func TestEmailService_MemberStatus_ResolverError_FallsBackToDefaultSender(t *testing.T) {
	mock := &emailMockSender{isConfigured: true}
	svc := emailNewService(mock)
	resolver := &tenantSMTPResolverMock{
		returnedError: errors.New("integration store down"),
	}
	svc.SetTenantSMTPResolver(resolver)

	if err := svc.SendMemberReactivatedEmail(
		context.Background(), "u@e.com", "U", "T", "A", "tenant-xyz",
	); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resolver.calls != 1 {
		t.Errorf("expected resolver to be consulted once, got %d calls", resolver.calls)
	}
	if resolver.lastTenantID != "tenant-xyz" {
		t.Errorf("expected resolver to receive tenantID=tenant-xyz, got %q", resolver.lastTenantID)
	}
	if mock.sendTemplateCalls != 1 {
		t.Errorf("expected fallback to default sender on resolver error, got %d calls", mock.sendTemplateCalls)
	}
}

func TestEmailService_MemberStatus_ResolverReturnsNilConfig_FallsBack(t *testing.T) {
	mock := &emailMockSender{isConfigured: true}
	svc := emailNewService(mock)
	resolver := &tenantSMTPResolverMock{
		// Both nil — simulates "tenant has no custom SMTP integration".
		returnedCfg:   nil,
		returnedError: nil,
	}
	svc.SetTenantSMTPResolver(resolver)

	if err := svc.SendMemberSuspendedEmail(
		context.Background(), "u@e.com", "U", "T", "A", "tenant-xyz",
	); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resolver.calls != 1 {
		t.Errorf("expected resolver to be consulted, got %d calls", resolver.calls)
	}
	if mock.sendTemplateCalls != 1 {
		t.Errorf("expected fallback to default sender on nil cfg, got %d calls", mock.sendTemplateCalls)
	}
}

// Empty tenantID short-circuits the resolver entirely — this is the path
// used by system-level notifications that aren't tenant-scoped. Pin the
// short-circuit so it doesn't drift back to hitting the resolver and
// causing a spurious integration lookup.
func TestEmailService_MemberStatus_EmptyTenantID_SkipsResolver(t *testing.T) {
	mock := &emailMockSender{isConfigured: true}
	svc := emailNewService(mock)
	resolver := &tenantSMTPResolverMock{}
	svc.SetTenantSMTPResolver(resolver)

	if err := svc.SendMemberReactivatedEmail(
		context.Background(), "u@e.com", "U", "T", "A",
		"", // empty tenantID
	); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resolver.calls != 0 {
		t.Errorf("expected resolver to be skipped when tenantID is empty, got %d calls", resolver.calls)
	}
}

// =============================================================================
// Template-engine contract: the suspend/reactivate templates must be
// registered and must render with MemberStatusChangeData. Without this,
// a missing or mistyped template const would compile fine but fail at
// send time — a regression class that already bit the team once on the
// Team Invitation template.
// =============================================================================

func TestEmailService_MemberStatus_TemplatesRegisteredAndRender(t *testing.T) {
	engine := emaildom.NewTemplateEngine()

	data := emaildom.MemberStatusChangeData{
		UserName:  "Jane",
		TeamName:  "Acme Corp",
		ActorName: "Admin Alice",
		AppURL:    "https://app.example.com",
		AppName:   "OpenCTEM",
	}

	cases := []struct {
		name           string
		template       emaildom.Template
		wantSubjectHas []string
		wantBodyHas    []string
	}{
		{
			name:           "suspended",
			template:       emaildom.TemplateMemberSuspended,
			wantSubjectHas: []string{"Acme Corp"},
			wantBodyHas:    []string{"Jane", "Acme Corp"},
		},
		{
			name:           "reactivated",
			template:       emaildom.TemplateMemberReactivated,
			wantSubjectHas: []string{"Acme Corp"},
			wantBodyHas:    []string{"Jane", "Acme Corp"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			subject, body, err := engine.Render(tc.template, data)
			if err != nil {
				t.Fatalf("Render(%s): %v", tc.template, err)
			}
			if subject == "" {
				t.Errorf("Render(%s): empty subject", tc.template)
			}
			if body == "" {
				t.Errorf("Render(%s): empty body", tc.template)
			}
			for _, want := range tc.wantSubjectHas {
				if !containsString(subject, want) {
					t.Errorf("Render(%s) subject %q missing %q",
						tc.template, subject, want)
				}
			}
			for _, want := range tc.wantBodyHas {
				if !containsString(body, want) {
					t.Errorf("Render(%s) body missing %q; got first 200 chars: %s",
						tc.template, want, truncateString(body, 200))
				}
			}
		})
	}
}

// When ActorName is empty the template must still render without errors
// (regression: early drafts required ActorName and panicked on nil).
func TestEmailService_MemberStatus_TemplateRender_EmptyActor(t *testing.T) {
	engine := emaildom.NewTemplateEngine()

	data := emaildom.MemberStatusChangeData{
		UserName: "Jane",
		TeamName: "Acme Corp",
		AppURL:   "https://app.example.com",
		AppName:  "OpenCTEM",
		// ActorName intentionally left empty
	}

	for _, tmpl := range []emaildom.Template{
		emaildom.TemplateMemberSuspended,
		emaildom.TemplateMemberReactivated,
	} {
		if _, _, err := engine.Render(tmpl, data); err != nil {
			t.Errorf("Render(%s) with empty ActorName: %v", tmpl, err)
		}
	}
}

// =============================================================================
// Multiple-calls tracking so a regression that accidentally coalesces
// suspend/reactivate sends into a single notification would be caught.
// =============================================================================

func TestEmailService_MemberStatus_SuspendThenReactivate_BothSent(t *testing.T) {
	mock := &emailMockSender{isConfigured: true}
	svc := emailNewService(mock)
	ctx := context.Background()

	if err := svc.SendMemberSuspendedEmail(ctx, "u@e.com", "U", "T", "A", "tenant-xyz"); err != nil {
		t.Fatalf("suspend email failed: %v", err)
	}
	if err := svc.SendMemberReactivatedEmail(ctx, "u@e.com", "U", "T", "A", "tenant-xyz"); err != nil {
		t.Fatalf("reactivate email failed: %v", err)
	}

	if mock.sendTemplateCalls != 2 {
		t.Errorf("expected 2 SendTemplate calls (one per action), got %d", mock.sendTemplateCalls)
	}
	if mock.lastTemplate != emaildom.TemplateMemberReactivated {
		t.Errorf("expected the last call to use reactivated template, got %s", mock.lastTemplate)
	}
}

// =============================================================================
// Shared helpers (small, local — avoid pulling in "strings"/"bytes" just to
// keep this file self-contained and grep-navigable).
// =============================================================================

func containsString(haystack, needle string) bool {
	// Small wrapper so we can swap implementation without touching tests.
	return indexOfString(haystack, needle) >= 0
}

func indexOfString(s, substr string) int {
	// Naive index-of — the payloads here are tiny HTML email bodies so
	// a linear scan is fine; keeps tests free of extra imports.
	n, m := len(s), len(substr)
	if m == 0 {
		return 0
	}
	if m > n {
		return -1
	}
	for i := 0; i+m <= n; i++ {
		if s[i:i+m] == substr {
			return i
		}
	}
	return -1
}

func truncateString(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return fmt.Sprintf("%s...(+%d bytes)", s[:n], len(s)-n)
}
