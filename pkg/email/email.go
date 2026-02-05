// Package email provides email sending functionality using SMTP.
package email

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"time"
)

var (
	// ErrNotConfigured is returned when SMTP is not configured.
	ErrNotConfigured = errors.New("email: SMTP not configured")
	// ErrInvalidRecipient is returned when the recipient email is invalid.
	ErrInvalidRecipient = errors.New("email: invalid recipient email")
	// ErrSendFailed is returned when email sending fails.
	ErrSendFailed = errors.New("email: failed to send email")
)

// Config holds SMTP configuration.
type Config struct {
	Host       string
	Port       int
	User       string
	Password   string
	From       string
	FromName   string
	TLS        bool
	SkipVerify bool
	Timeout    time.Duration
}

// Message represents an email message.
type Message struct {
	To      []string
	Subject string
	Body    string
	IsHTML  bool
	ReplyTo string
	Headers map[string]string
}

// Sender defines the interface for sending emails.
type Sender interface {
	Send(ctx context.Context, msg *Message) error
	SendTemplate(ctx context.Context, to string, template Template, data any) error
	IsConfigured() bool
}

// SMTPSender implements Sender using SMTP.
type SMTPSender struct {
	config    Config
	templates *TemplateEngine
}

// NewSMTPSender creates a new SMTP sender.
func NewSMTPSender(cfg Config) *SMTPSender {
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	return &SMTPSender{
		config:    cfg,
		templates: NewTemplateEngine(),
	}
}

// IsConfigured returns true if SMTP is properly configured.
func (s *SMTPSender) IsConfigured() bool {
	return s.config.Host != "" && s.config.Port > 0 && s.config.From != ""
}

// Send sends an email message.
func (s *SMTPSender) Send(ctx context.Context, msg *Message) error {
	if !s.IsConfigured() {
		return ErrNotConfigured
	}

	if len(msg.To) == 0 {
		return ErrInvalidRecipient
	}

	// Build email content
	content := s.buildMessage(msg)

	// Send email
	if err := s.sendSMTP(ctx, msg.To, content); err != nil {
		return fmt.Errorf("%w: %v", ErrSendFailed, err)
	}

	return nil
}

// SendTemplate sends an email using a predefined template.
func (s *SMTPSender) SendTemplate(ctx context.Context, to string, template Template, data any) error {
	if to == "" {
		return ErrInvalidRecipient
	}

	subject, body, err := s.templates.Render(template, data)
	if err != nil {
		return fmt.Errorf("email: failed to render template: %w", err)
	}

	return s.Send(ctx, &Message{
		To:      []string{to},
		Subject: subject,
		Body:    body,
		IsHTML:  true,
	})
}

// buildMessage builds the email message content.
func (s *SMTPSender) buildMessage(msg *Message) []byte {
	var builder strings.Builder

	// From header
	if s.config.FromName != "" {
		builder.WriteString(fmt.Sprintf("From: %s <%s>\r\n", s.config.FromName, s.config.From))
	} else {
		builder.WriteString(fmt.Sprintf("From: %s\r\n", s.config.From))
	}

	// To header
	builder.WriteString(fmt.Sprintf("To: %s\r\n", strings.Join(msg.To, ", ")))

	// Subject header
	builder.WriteString(fmt.Sprintf("Subject: %s\r\n", msg.Subject))

	// Reply-To header
	if msg.ReplyTo != "" {
		builder.WriteString(fmt.Sprintf("Reply-To: %s\r\n", msg.ReplyTo))
	}

	// Custom headers
	for key, value := range msg.Headers {
		builder.WriteString(fmt.Sprintf("%s: %s\r\n", key, value))
	}

	// MIME headers
	builder.WriteString("MIME-Version: 1.0\r\n")
	if msg.IsHTML {
		builder.WriteString("Content-Type: text/html; charset=UTF-8\r\n")
	} else {
		builder.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	}

	// Empty line before body
	builder.WriteString("\r\n")

	// Body
	builder.WriteString(msg.Body)

	return []byte(builder.String())
}

// sendSMTP sends the email via SMTP.
func (s *SMTPSender) sendSMTP(ctx context.Context, to []string, content []byte) error {
	addr := fmt.Sprintf("%s:%d", s.config.Host, s.config.Port)

	// Create connection with timeout
	dialer := &net.Dialer{Timeout: s.config.Timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}
	defer conn.Close()

	// Create SMTP client
	client, err := smtp.NewClient(conn, s.config.Host)
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}
	defer client.Close()

	// Start TLS if configured
	if s.config.TLS {
		tlsConfig := &tls.Config{
			ServerName:         s.config.Host,
			InsecureSkipVerify: s.config.SkipVerify,
		}
		if err := client.StartTLS(tlsConfig); err != nil {
			return fmt.Errorf("failed to start TLS: %w", err)
		}
	}

	// Authenticate if credentials provided
	if s.config.User != "" && s.config.Password != "" {
		auth := smtp.PlainAuth("", s.config.User, s.config.Password, s.config.Host)
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("authentication failed: %w", err)
		}
	}

	// Set sender
	if err := client.Mail(s.config.From); err != nil {
		return fmt.Errorf("failed to set sender: %w", err)
	}

	// Set recipients
	for _, recipient := range to {
		if err := client.Rcpt(recipient); err != nil {
			return fmt.Errorf("failed to set recipient %s: %w", recipient, err)
		}
	}

	// Send message body
	writer, err := client.Data()
	if err != nil {
		return fmt.Errorf("failed to get data writer: %w", err)
	}

	if _, err := writer.Write(content); err != nil {
		return fmt.Errorf("failed to write message: %w", err)
	}

	if err := writer.Close(); err != nil {
		return fmt.Errorf("failed to close writer: %w", err)
	}

	// Quit
	return client.Quit()
}

// NoOpSender is a sender that does nothing (for development/testing).
type NoOpSender struct{}

// NewNoOpSender creates a new no-op sender.
func NewNoOpSender() *NoOpSender {
	return &NoOpSender{}
}

// IsConfigured always returns true for no-op sender.
func (s *NoOpSender) IsConfigured() bool {
	return true
}

// Send does nothing and returns nil.
func (s *NoOpSender) Send(_ context.Context, _ *Message) error {
	return nil
}

// SendTemplate does nothing and returns nil.
func (s *NoOpSender) SendTemplate(_ context.Context, _ string, _ Template, _ any) error {
	return nil
}

// LoggingSender wraps a sender and logs all email operations.
type LoggingSender struct {
	sender Sender
	logger Logger
}

// Logger is a simple logging interface.
type Logger interface {
	Info(msg string, args ...any)
}

// NewLoggingSender creates a new logging sender.
func NewLoggingSender(sender Sender, logger Logger) *LoggingSender {
	return &LoggingSender{
		sender: sender,
		logger: logger,
	}
}

// IsConfigured returns true if the underlying sender is configured.
func (s *LoggingSender) IsConfigured() bool {
	return s.sender.IsConfigured()
}

// Send logs and sends the email.
func (s *LoggingSender) Send(ctx context.Context, msg *Message) error {
	s.logger.Info("sending email",
		"to", msg.To,
		"subject", msg.Subject,
	)
	err := s.sender.Send(ctx, msg)
	if err != nil {
		s.logger.Info("email send failed",
			"to", msg.To,
			"error", err,
		)
	} else {
		s.logger.Info("email sent successfully",
			"to", msg.To,
		)
	}
	return err
}

// SendTemplate logs and sends a templated email.
func (s *LoggingSender) SendTemplate(ctx context.Context, to string, template Template, data any) error {
	s.logger.Info("sending templated email",
		"to", to,
		"template", template,
	)
	err := s.sender.SendTemplate(ctx, to, template, data)
	if err != nil {
		s.logger.Info("templated email send failed",
			"to", to,
			"template", template,
			"error", err,
		)
	} else {
		s.logger.Info("templated email sent successfully",
			"to", to,
			"template", template,
		)
	}
	return err
}
