package unit

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/internal/config"
	"github.com/openctemio/api/pkg/email"
	"github.com/openctemio/api/pkg/logger"
)

// =============================================================================
// Mock Email Sender
// =============================================================================

// emailMockSender implements email.Sender for testing.
type emailMockSender struct {
	isConfigured bool
	sendErr      error

	// Track SendTemplate calls
	sendTemplateCalls    int
	lastTo               string
	lastTemplate         email.Template
	lastData             any
}

func (m *emailMockSender) Send(_ context.Context, _ *email.Message) error {
	return m.sendErr
}

func (m *emailMockSender) SendTemplate(_ context.Context, to string, tmpl email.Template, data any) error {
	m.sendTemplateCalls++
	m.lastTo = to
	m.lastTemplate = tmpl
	m.lastData = data
	return m.sendErr
}

func (m *emailMockSender) IsConfigured() bool {
	return m.isConfigured
}

// =============================================================================
// Helpers
// =============================================================================

func emailTestLogger() *logger.Logger {
	return logger.New(logger.Config{Level: "error"})
}

func emailTestConfig() config.SMTPConfig {
	return config.SMTPConfig{
		Host:    "smtp.example.com",
		Port:    587,
		From:    "noreply@example.com",
		BaseURL: "https://app.example.com",
	}
}

func emailNewService(sender email.Sender) *app.EmailService {
	return app.NewEmailService(sender, emailTestConfig(), "OpenCTEM", emailTestLogger())
}

// =============================================================================
// IsConfigured Tests
// =============================================================================

func TestEmailService_IsConfigured_True(t *testing.T) {
	mock := &emailMockSender{isConfigured: true}
	svc := emailNewService(mock)

	if !svc.IsConfigured() {
		t.Error("expected IsConfigured() to return true when sender is configured")
	}
}

func TestEmailService_IsConfigured_False(t *testing.T) {
	mock := &emailMockSender{isConfigured: false}
	svc := emailNewService(mock)

	if svc.IsConfigured() {
		t.Error("expected IsConfigured() to return false when sender is not configured")
	}
}

func TestEmailService_IsConfigured_NilSender(t *testing.T) {
	svc := app.NewEmailService(nil, emailTestConfig(), "OpenCTEM", emailTestLogger())

	if svc.IsConfigured() {
		t.Error("expected IsConfigured() to return false when sender is nil")
	}
}

// =============================================================================
// SendVerificationEmail Tests
// =============================================================================

func TestEmailService_SendVerificationEmail_Success(t *testing.T) {
	mock := &emailMockSender{isConfigured: true}
	svc := emailNewService(mock)

	err := svc.SendVerificationEmail(context.Background(), "user@example.com", "John", "tok123", 24*time.Hour)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if mock.sendTemplateCalls != 1 {
		t.Fatalf("expected 1 SendTemplate call, got %d", mock.sendTemplateCalls)
	}
	if mock.lastTo != "user@example.com" {
		t.Errorf("expected to=user@example.com, got %s", mock.lastTo)
	}
	if mock.lastTemplate != email.TemplateVerifyEmail {
		t.Errorf("expected template=%s, got %s", email.TemplateVerifyEmail, mock.lastTemplate)
	}

	data, ok := mock.lastData.(email.VerifyEmailData)
	if !ok {
		t.Fatalf("expected VerifyEmailData, got %T", mock.lastData)
	}
	if data.UserName != "John" {
		t.Errorf("expected UserName=John, got %s", data.UserName)
	}
	if data.Email != "user@example.com" {
		t.Errorf("expected Email=user@example.com, got %s", data.Email)
	}
	expectedURL := "https://app.example.com/auth/verify-email?token=tok123"
	if data.VerificationURL != expectedURL {
		t.Errorf("expected VerificationURL=%s, got %s", expectedURL, data.VerificationURL)
	}
	if data.ExpiresIn != "24 hours" {
		t.Errorf("expected ExpiresIn=24 hours, got %s", data.ExpiresIn)
	}
	if data.AppName != "OpenCTEM" {
		t.Errorf("expected AppName=OpenCTEM, got %s", data.AppName)
	}
}

func TestEmailService_SendVerificationEmail_NotConfigured(t *testing.T) {
	mock := &emailMockSender{isConfigured: false}
	svc := emailNewService(mock)

	err := svc.SendVerificationEmail(context.Background(), "user@example.com", "John", "tok123", time.Hour)
	if err != nil {
		t.Fatalf("expected nil error when not configured, got: %v", err)
	}
	if mock.sendTemplateCalls != 0 {
		t.Errorf("expected 0 SendTemplate calls when not configured, got %d", mock.sendTemplateCalls)
	}
}

func TestEmailService_SendVerificationEmail_SenderError(t *testing.T) {
	sendErr := errors.New("smtp connection failed")
	mock := &emailMockSender{isConfigured: true, sendErr: sendErr}
	svc := emailNewService(mock)

	err := svc.SendVerificationEmail(context.Background(), "user@example.com", "John", "tok123", time.Hour)
	if err == nil {
		t.Fatal("expected error when sender fails")
	}
	if !errors.Is(err, sendErr) {
		t.Errorf("expected wrapped sendErr, got: %v", err)
	}
}

// =============================================================================
// SendPasswordResetEmail Tests
// =============================================================================

func TestEmailService_SendPasswordResetEmail_Success(t *testing.T) {
	mock := &emailMockSender{isConfigured: true}
	svc := emailNewService(mock)

	err := svc.SendPasswordResetEmail(context.Background(), "user@example.com", "Jane", "reset-tok", 2*time.Hour, "192.168.1.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if mock.sendTemplateCalls != 1 {
		t.Fatalf("expected 1 SendTemplate call, got %d", mock.sendTemplateCalls)
	}
	if mock.lastTo != "user@example.com" {
		t.Errorf("expected to=user@example.com, got %s", mock.lastTo)
	}
	if mock.lastTemplate != email.TemplatePasswordReset {
		t.Errorf("expected template=%s, got %s", email.TemplatePasswordReset, mock.lastTemplate)
	}

	data, ok := mock.lastData.(email.PasswordResetData)
	if !ok {
		t.Fatalf("expected PasswordResetData, got %T", mock.lastData)
	}
	if data.UserName != "Jane" {
		t.Errorf("expected UserName=Jane, got %s", data.UserName)
	}
	if data.Email != "user@example.com" {
		t.Errorf("expected Email=user@example.com, got %s", data.Email)
	}
	expectedURL := "https://app.example.com/auth/reset-password?token=reset-tok"
	if data.ResetURL != expectedURL {
		t.Errorf("expected ResetURL=%s, got %s", expectedURL, data.ResetURL)
	}
	if data.ExpiresIn != "2 hours" {
		t.Errorf("expected ExpiresIn=2 hours, got %s", data.ExpiresIn)
	}
	if data.AppName != "OpenCTEM" {
		t.Errorf("expected AppName=OpenCTEM, got %s", data.AppName)
	}
	if data.IPAddress != "192.168.1.1" {
		t.Errorf("expected IPAddress=192.168.1.1, got %s", data.IPAddress)
	}
	if data.RequestedAt == "" {
		t.Error("expected RequestedAt to be non-empty")
	}
}

func TestEmailService_SendPasswordResetEmail_NotConfigured(t *testing.T) {
	mock := &emailMockSender{isConfigured: false}
	svc := emailNewService(mock)

	err := svc.SendPasswordResetEmail(context.Background(), "user@example.com", "Jane", "tok", time.Hour, "1.2.3.4")
	if err != nil {
		t.Fatalf("expected nil error when not configured, got: %v", err)
	}
	if mock.sendTemplateCalls != 0 {
		t.Errorf("expected 0 SendTemplate calls when not configured, got %d", mock.sendTemplateCalls)
	}
}

func TestEmailService_SendPasswordResetEmail_SenderError(t *testing.T) {
	sendErr := errors.New("timeout sending email")
	mock := &emailMockSender{isConfigured: true, sendErr: sendErr}
	svc := emailNewService(mock)

	err := svc.SendPasswordResetEmail(context.Background(), "user@example.com", "Jane", "tok", time.Hour, "1.2.3.4")
	if err == nil {
		t.Fatal("expected error when sender fails")
	}
	if !errors.Is(err, sendErr) {
		t.Errorf("expected wrapped sendErr, got: %v", err)
	}
}

// =============================================================================
// SendPasswordChangedEmail Tests
// =============================================================================

func TestEmailService_SendPasswordChangedEmail_Success(t *testing.T) {
	mock := &emailMockSender{isConfigured: true}
	svc := emailNewService(mock)

	err := svc.SendPasswordChangedEmail(context.Background(), "user@example.com", "Alice", "10.0.0.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if mock.sendTemplateCalls != 1 {
		t.Fatalf("expected 1 SendTemplate call, got %d", mock.sendTemplateCalls)
	}
	if mock.lastTo != "user@example.com" {
		t.Errorf("expected to=user@example.com, got %s", mock.lastTo)
	}
	if mock.lastTemplate != email.TemplatePasswordChanged {
		t.Errorf("expected template=%s, got %s", email.TemplatePasswordChanged, mock.lastTemplate)
	}

	data, ok := mock.lastData.(email.PasswordChangedData)
	if !ok {
		t.Fatalf("expected PasswordChangedData, got %T", mock.lastData)
	}
	if data.UserName != "Alice" {
		t.Errorf("expected UserName=Alice, got %s", data.UserName)
	}
	if data.Email != "user@example.com" {
		t.Errorf("expected Email=user@example.com, got %s", data.Email)
	}
	if data.IPAddress != "10.0.0.1" {
		t.Errorf("expected IPAddress=10.0.0.1, got %s", data.IPAddress)
	}
	if data.AppName != "OpenCTEM" {
		t.Errorf("expected AppName=OpenCTEM, got %s", data.AppName)
	}
	expectedSupportURL := "https://app.example.com/support"
	if data.SupportURL != expectedSupportURL {
		t.Errorf("expected SupportURL=%s, got %s", expectedSupportURL, data.SupportURL)
	}
	if data.ChangedAt == "" {
		t.Error("expected ChangedAt to be non-empty")
	}
}

func TestEmailService_SendPasswordChangedEmail_NotConfigured(t *testing.T) {
	mock := &emailMockSender{isConfigured: false}
	svc := emailNewService(mock)

	err := svc.SendPasswordChangedEmail(context.Background(), "user@example.com", "Alice", "10.0.0.1")
	if err != nil {
		t.Fatalf("expected nil error when not configured, got: %v", err)
	}
	if mock.sendTemplateCalls != 0 {
		t.Errorf("expected 0 SendTemplate calls when not configured, got %d", mock.sendTemplateCalls)
	}
}

func TestEmailService_SendPasswordChangedEmail_SenderError(t *testing.T) {
	sendErr := errors.New("auth failed")
	mock := &emailMockSender{isConfigured: true, sendErr: sendErr}
	svc := emailNewService(mock)

	err := svc.SendPasswordChangedEmail(context.Background(), "user@example.com", "Alice", "10.0.0.1")
	if err == nil {
		t.Fatal("expected error when sender fails")
	}
	if !errors.Is(err, sendErr) {
		t.Errorf("expected wrapped sendErr, got: %v", err)
	}
}

// =============================================================================
// SendWelcomeEmail Tests
// =============================================================================

func TestEmailService_SendWelcomeEmail_Success(t *testing.T) {
	mock := &emailMockSender{isConfigured: true}
	svc := emailNewService(mock)

	err := svc.SendWelcomeEmail(context.Background(), "new@example.com", "Bob")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if mock.sendTemplateCalls != 1 {
		t.Fatalf("expected 1 SendTemplate call, got %d", mock.sendTemplateCalls)
	}
	if mock.lastTo != "new@example.com" {
		t.Errorf("expected to=new@example.com, got %s", mock.lastTo)
	}
	if mock.lastTemplate != email.TemplateWelcome {
		t.Errorf("expected template=%s, got %s", email.TemplateWelcome, mock.lastTemplate)
	}

	data, ok := mock.lastData.(email.WelcomeData)
	if !ok {
		t.Fatalf("expected WelcomeData, got %T", mock.lastData)
	}
	if data.UserName != "Bob" {
		t.Errorf("expected UserName=Bob, got %s", data.UserName)
	}
	if data.Email != "new@example.com" {
		t.Errorf("expected Email=new@example.com, got %s", data.Email)
	}
	expectedLoginURL := "https://app.example.com/auth/login"
	if data.LoginURL != expectedLoginURL {
		t.Errorf("expected LoginURL=%s, got %s", expectedLoginURL, data.LoginURL)
	}
	expectedSupportURL := "https://app.example.com/support"
	if data.SupportURL != expectedSupportURL {
		t.Errorf("expected SupportURL=%s, got %s", expectedSupportURL, data.SupportURL)
	}
	if data.AppName != "OpenCTEM" {
		t.Errorf("expected AppName=OpenCTEM, got %s", data.AppName)
	}
}

func TestEmailService_SendWelcomeEmail_NotConfigured(t *testing.T) {
	mock := &emailMockSender{isConfigured: false}
	svc := emailNewService(mock)

	err := svc.SendWelcomeEmail(context.Background(), "new@example.com", "Bob")
	if err != nil {
		t.Fatalf("expected nil error when not configured, got: %v", err)
	}
	if mock.sendTemplateCalls != 0 {
		t.Errorf("expected 0 SendTemplate calls when not configured, got %d", mock.sendTemplateCalls)
	}
}

func TestEmailService_SendWelcomeEmail_SenderError(t *testing.T) {
	sendErr := errors.New("connection refused")
	mock := &emailMockSender{isConfigured: true, sendErr: sendErr}
	svc := emailNewService(mock)

	err := svc.SendWelcomeEmail(context.Background(), "new@example.com", "Bob")
	if err == nil {
		t.Fatal("expected error when sender fails")
	}
	if !errors.Is(err, sendErr) {
		t.Errorf("expected wrapped sendErr, got: %v", err)
	}
}

// =============================================================================
// SendTeamInvitationEmail Tests
// =============================================================================

func TestEmailService_SendTeamInvitationEmail_Success(t *testing.T) {
	mock := &emailMockSender{isConfigured: true}
	svc := emailNewService(mock)

	err := svc.SendTeamInvitationEmail(context.Background(), "invite@example.com", "Admin", "Acme Corp", "inv-tok-456", 7*24*time.Hour)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if mock.sendTemplateCalls != 1 {
		t.Fatalf("expected 1 SendTemplate call, got %d", mock.sendTemplateCalls)
	}
	if mock.lastTo != "invite@example.com" {
		t.Errorf("expected to=invite@example.com, got %s", mock.lastTo)
	}
	if mock.lastTemplate != email.TemplateTeamInvitation {
		t.Errorf("expected template=%s, got %s", email.TemplateTeamInvitation, mock.lastTemplate)
	}

	data, ok := mock.lastData.(email.TeamInvitationData)
	if !ok {
		t.Fatalf("expected TeamInvitationData, got %T", mock.lastData)
	}
	if data.InviterName != "Admin" {
		t.Errorf("expected InviterName=Admin, got %s", data.InviterName)
	}
	if data.TeamName != "Acme Corp" {
		t.Errorf("expected TeamName=Acme Corp, got %s", data.TeamName)
	}
	expectedURL := "https://app.example.com/invitations/inv-tok-456"
	if data.InvitationURL != expectedURL {
		t.Errorf("expected InvitationURL=%s, got %s", expectedURL, data.InvitationURL)
	}
	if data.ExpiresIn != "7 days" {
		t.Errorf("expected ExpiresIn=7 days, got %s", data.ExpiresIn)
	}
	if data.AppName != "OpenCTEM" {
		t.Errorf("expected AppName=OpenCTEM, got %s", data.AppName)
	}
}

func TestEmailService_SendTeamInvitationEmail_NotConfigured(t *testing.T) {
	mock := &emailMockSender{isConfigured: false}
	svc := emailNewService(mock)

	err := svc.SendTeamInvitationEmail(context.Background(), "invite@example.com", "Admin", "Team", "tok", time.Hour)
	if err != nil {
		t.Fatalf("expected nil error when not configured, got: %v", err)
	}
	if mock.sendTemplateCalls != 0 {
		t.Errorf("expected 0 SendTemplate calls when not configured, got %d", mock.sendTemplateCalls)
	}
}

func TestEmailService_SendTeamInvitationEmail_SenderError(t *testing.T) {
	sendErr := errors.New("dns resolution failed")
	mock := &emailMockSender{isConfigured: true, sendErr: sendErr}
	svc := emailNewService(mock)

	err := svc.SendTeamInvitationEmail(context.Background(), "invite@example.com", "Admin", "Team", "tok", time.Hour)
	if err == nil {
		t.Fatal("expected error when sender fails")
	}
	if !errors.Is(err, sendErr) {
		t.Errorf("expected wrapped sendErr, got: %v", err)
	}
}

// =============================================================================
// formatDuration Tests (via SendVerificationEmail template data)
// =============================================================================

func TestEmailService_FormatDuration_Variations(t *testing.T) {
	tests := []struct {
		name     string
		duration time.Duration
		expected string
	}{
		{"1 hour", time.Hour, "1 hour"},
		{"2 hours", 2 * time.Hour, "2 hours"},
		{"24 hours (1 day)", 24 * time.Hour, "24 hours"},
		{"48 hours (2 days)", 48 * time.Hour, "2 days"},
		{"72 hours (3 days)", 72 * time.Hour, "3 days"},
		{"1 minute", time.Minute, "1 minute"},
		{"5 minutes", 5 * time.Minute, "5 minutes"},
		{"30 minutes", 30 * time.Minute, "30 minutes"},
		{"30 seconds", 30 * time.Second, "30s"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mock := &emailMockSender{isConfigured: true}
			svc := emailNewService(mock)

			err := svc.SendVerificationEmail(context.Background(), "user@example.com", "Test", "tok", tc.duration)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			data, ok := mock.lastData.(email.VerifyEmailData)
			if !ok {
				t.Fatalf("expected VerifyEmailData, got %T", mock.lastData)
			}
			if data.ExpiresIn != tc.expected {
				t.Errorf("expected ExpiresIn=%q, got %q", tc.expected, data.ExpiresIn)
			}
		})
	}
}

// =============================================================================
// URL Construction Tests
// =============================================================================

func TestEmailService_URLConstruction_DifferentBaseURLs(t *testing.T) {
	tests := []struct {
		name    string
		baseURL string
	}{
		{"standard", "https://app.example.com"},
		{"with trailing slash removed", "https://myapp.io"},
		{"localhost", "http://localhost:3000"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mock := &emailMockSender{isConfigured: true}
			cfg := config.SMTPConfig{BaseURL: tc.baseURL}
			svc := app.NewEmailService(mock, cfg, "TestApp", emailTestLogger())

			// Test verification URL
			err := svc.SendVerificationEmail(context.Background(), "u@e.com", "U", "t1", time.Hour)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			vData := mock.lastData.(email.VerifyEmailData)
			expectedVerifyURL := fmt.Sprintf("%s/auth/verify-email?token=t1", tc.baseURL)
			if vData.VerificationURL != expectedVerifyURL {
				t.Errorf("expected VerificationURL=%s, got %s", expectedVerifyURL, vData.VerificationURL)
			}

			// Test password reset URL
			err = svc.SendPasswordResetEmail(context.Background(), "u@e.com", "U", "t2", time.Hour, "1.1.1.1")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			rData := mock.lastData.(email.PasswordResetData)
			expectedResetURL := fmt.Sprintf("%s/auth/reset-password?token=t2", tc.baseURL)
			if rData.ResetURL != expectedResetURL {
				t.Errorf("expected ResetURL=%s, got %s", expectedResetURL, rData.ResetURL)
			}

			// Test welcome login URL
			err = svc.SendWelcomeEmail(context.Background(), "u@e.com", "U")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			wData := mock.lastData.(email.WelcomeData)
			expectedLoginURL := fmt.Sprintf("%s/auth/login", tc.baseURL)
			if wData.LoginURL != expectedLoginURL {
				t.Errorf("expected LoginURL=%s, got %s", expectedLoginURL, wData.LoginURL)
			}

			// Test invitation URL
			err = svc.SendTeamInvitationEmail(context.Background(), "u@e.com", "A", "T", "inv1", time.Hour)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			iData := mock.lastData.(email.TeamInvitationData)
			expectedInvURL := fmt.Sprintf("%s/invitations/inv1", tc.baseURL)
			if iData.InvitationURL != expectedInvURL {
				t.Errorf("expected InvitationURL=%s, got %s", expectedInvURL, iData.InvitationURL)
			}

			// Test password changed support URL
			err = svc.SendPasswordChangedEmail(context.Background(), "u@e.com", "U", "1.1.1.1")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			pcData := mock.lastData.(email.PasswordChangedData)
			expectedSupportURL := fmt.Sprintf("%s/support", tc.baseURL)
			if pcData.SupportURL != expectedSupportURL {
				t.Errorf("expected SupportURL=%s, got %s", expectedSupportURL, pcData.SupportURL)
			}
		})
	}
}

// =============================================================================
// AppName Propagation Tests
// =============================================================================

func TestEmailService_AppName_PropagatedToAllTemplates(t *testing.T) {
	mock := &emailMockSender{isConfigured: true}
	customAppName := "MyCustomApp"
	svc := app.NewEmailService(mock, emailTestConfig(), customAppName, emailTestLogger())

	// Verification
	_ = svc.SendVerificationEmail(context.Background(), "u@e.com", "U", "t", time.Hour)
	if d := mock.lastData.(email.VerifyEmailData); d.AppName != customAppName {
		t.Errorf("SendVerificationEmail: expected AppName=%s, got %s", customAppName, d.AppName)
	}

	// Password reset
	_ = svc.SendPasswordResetEmail(context.Background(), "u@e.com", "U", "t", time.Hour, "1.1.1.1")
	if d := mock.lastData.(email.PasswordResetData); d.AppName != customAppName {
		t.Errorf("SendPasswordResetEmail: expected AppName=%s, got %s", customAppName, d.AppName)
	}

	// Password changed
	_ = svc.SendPasswordChangedEmail(context.Background(), "u@e.com", "U", "1.1.1.1")
	if d := mock.lastData.(email.PasswordChangedData); d.AppName != customAppName {
		t.Errorf("SendPasswordChangedEmail: expected AppName=%s, got %s", customAppName, d.AppName)
	}

	// Welcome
	_ = svc.SendWelcomeEmail(context.Background(), "u@e.com", "U")
	if d := mock.lastData.(email.WelcomeData); d.AppName != customAppName {
		t.Errorf("SendWelcomeEmail: expected AppName=%s, got %s", customAppName, d.AppName)
	}

	// Team invitation
	_ = svc.SendTeamInvitationEmail(context.Background(), "u@e.com", "A", "T", "t", time.Hour)
	if d := mock.lastData.(email.TeamInvitationData); d.AppName != customAppName {
		t.Errorf("SendTeamInvitationEmail: expected AppName=%s, got %s", customAppName, d.AppName)
	}
}

// =============================================================================
// Multiple Calls Tracking
// =============================================================================

func TestEmailService_MultipleSendCalls_TrackedCorrectly(t *testing.T) {
	mock := &emailMockSender{isConfigured: true}
	svc := emailNewService(mock)

	_ = svc.SendWelcomeEmail(context.Background(), "a@example.com", "A")
	_ = svc.SendWelcomeEmail(context.Background(), "b@example.com", "B")
	_ = svc.SendWelcomeEmail(context.Background(), "c@example.com", "C")

	if mock.sendTemplateCalls != 3 {
		t.Errorf("expected 3 SendTemplate calls, got %d", mock.sendTemplateCalls)
	}
	// Last call should be the most recent
	if mock.lastTo != "c@example.com" {
		t.Errorf("expected last to=c@example.com, got %s", mock.lastTo)
	}
}

// =============================================================================
// Not Configured Skips All Methods
// =============================================================================

func TestEmailService_NotConfigured_AllMethodsReturnNil(t *testing.T) {
	mock := &emailMockSender{isConfigured: false}
	svc := emailNewService(mock)
	ctx := context.Background()

	if err := svc.SendVerificationEmail(ctx, "u@e.com", "U", "t", time.Hour); err != nil {
		t.Errorf("SendVerificationEmail: expected nil, got %v", err)
	}
	if err := svc.SendPasswordResetEmail(ctx, "u@e.com", "U", "t", time.Hour, "1.1.1.1"); err != nil {
		t.Errorf("SendPasswordResetEmail: expected nil, got %v", err)
	}
	if err := svc.SendPasswordChangedEmail(ctx, "u@e.com", "U", "1.1.1.1"); err != nil {
		t.Errorf("SendPasswordChangedEmail: expected nil, got %v", err)
	}
	if err := svc.SendWelcomeEmail(ctx, "u@e.com", "U"); err != nil {
		t.Errorf("SendWelcomeEmail: expected nil, got %v", err)
	}
	if err := svc.SendTeamInvitationEmail(ctx, "u@e.com", "A", "T", "t", time.Hour); err != nil {
		t.Errorf("SendTeamInvitationEmail: expected nil, got %v", err)
	}

	if mock.sendTemplateCalls != 0 {
		t.Errorf("expected 0 SendTemplate calls when not configured, got %d", mock.sendTemplateCalls)
	}
}
