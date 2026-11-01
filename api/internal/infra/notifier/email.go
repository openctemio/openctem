package notifier

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"html/template"
	"net"
	"sort"
	"strings"
	"time"

	emailpkg "github.com/openctemio/openctem/api/pkg/email"
)

// EmailClient implements the Client interface for email notifications via SMTP.
type EmailClient struct {
	product    string // brand name in test messages and the footer
	productURL string
	config     EmailConfig
}

// EmailConfig holds the SMTP configuration.
type EmailConfig struct {
	SMTPHost     string   // SMTP server host
	SMTPPort     int      // SMTP server port (25, 465, 587)
	Username     string   // SMTP username
	Password     string   // SMTP password
	FromEmail    string   // Sender email address
	FromName     string   // Sender display name
	ToEmails     []string // Recipient email addresses
	UseTLS       bool     // Use direct TLS (port 465)
	UseSTARTTLS  bool     // Use STARTTLS (port 587)
	ReplyTo      string   // Optional reply-to address
	TemplateName string   // Optional custom template name
}

// NewEmailClient creates a new email notification client.
func NewEmailClient(config Config) (*EmailClient, error) {
	emailConfig := config.Email
	if emailConfig == nil {
		return nil, fmt.Errorf("email config is required")
	}

	if emailConfig.SMTPHost == "" {
		return nil, fmt.Errorf("SMTP host is required")
	}
	if emailConfig.SMTPPort == 0 {
		return nil, fmt.Errorf("SMTP port is required")
	}
	if err := validateRelay(emailConfig); err != nil {
		return nil, err
	}
	if emailConfig.FromEmail == "" {
		return nil, fmt.Errorf("sender email is required")
	}
	if len(emailConfig.ToEmails) == 0 {
		return nil, fmt.Errorf("at least one recipient email is required")
	}

	return &EmailClient{
		product:    config.productName(),
		productURL: config.ProductURL,
		config:     *emailConfig,
	}, nil
}

// Provider returns the provider name.
func (c *EmailClient) Provider() string {
	return string(ProviderEmail)
}

// Send sends a notification email.
func (c *EmailClient) Send(ctx context.Context, msg Message) (*SendResult, error) {
	if err := c.deliver(ctx, msg); err != nil {
		var be buildError
		if errors.As(err, &be) {
			return &SendResult{Success: false, Error: fmt.Sprintf("build email body: %v", be.err)}, nil
		}
		return &SendResult{Success: false, Error: fmt.Sprintf("send email: %v", err)}, nil
	}
	return &SendResult{Success: true}, nil
}

// buildError marks a failure to render the message, as opposed to a transport
// failure.
type buildError struct{ err error }

func (e buildError) Error() string { return e.err.Error() }
func (e buildError) Unwrap() error { return e.err }

// deliver renders the notification and sends it through the shared sender.
func (c *EmailClient) deliver(ctx context.Context, msg Message) error {
	htmlBody, err := c.buildHTMLEmail(msg)
	if err != nil {
		return buildError{err}
	}

	// msg.Title comes from the notification payload, which is
	// attacker-influenceable (finding titles, scanner output, AI
	// summaries). The shared sender strips CR/LF from every header value
	// and encodes the subject (RFC 2047), so a "\r\n" in Title cannot
	// smuggle headers (Bcc, Content-Type). See CodeQL rule
	// go/email-content-injection.
	subject := msg.Title
	if msg.Severity != "" {
		subject = fmt.Sprintf("%s [%s] %s", GetSeverityEmoji(msg.Severity), strings.ToUpper(msg.Severity), msg.Title)
	}

	// The port rule is checked again here: a stored configuration may predate it.
	if err := validateRelay(&c.config); err != nil {
		return err
	}
	// Date, Message-ID, header encoding and the multipart body are the shared
	// sender's job (pkg/email): one SMTP stack.
	return c.sender().Send(ctx, &emailpkg.Message{
		To:       c.config.ToEmails,
		Subject:  subject,
		Body:     htmlBody,
		IsHTML:   true,
		ReplyTo:  c.config.ReplyTo,
		TextBody: c.buildTextEmail(msg),
	})
}

// TestConnection tests the SMTP configuration.
func (c *EmailClient) TestConnection(ctx context.Context) (*SendResult, error) {
	testMsg := Message{
		Title:    c.product + " Test Notification",
		Body:     "This is a test notification to verify your email integration is working correctly.",
		Severity: "low",
	}
	return c.Send(ctx, testMsg)
}

// smtpSessionTimeout bounds one SMTP session of an organization's relay.
var smtpSessionTimeout = 2 * time.Minute

// relayResolver and relayDialer replace the SSRF-guarded resolution and dial
// of the shared sender; tests set them to reach a local relay. They are nil
// in production.
var (
	relayResolver func(ctx context.Context, host string) (net.IP, error)
	relayDialer   func(ctx context.Context, timeout time.Duration, addr string) (net.Conn, error)
)

// validateRelay applies the transport rule for an organization's relay (the
// port always; on a managed service also AUTH and TLS). It runs when the
// client is built and again before every send, because a stored
// configuration may predate the rule.
func validateRelay(c *EmailConfig) error {
	return emailpkg.ValidateTenantRelay(c.SMTPPort, c.UseTLS, c.UseSTARTTLS, c.Username, c.Password)
}

// sender returns the shared SMTP sender for this relay. The shared sender
// resolves the host through the SSRF guard and dials the vetted address, bounds
// the whole session, fails closed when STARTTLS is not available and never
// sends credentials in clear text. The relay's certificate is always verified:
// this client sends a tenant's SMTP password, and a tenant cannot turn
// verification off, so a stored legacy skip_verify flag is ignored. The port
// rule is checked by the caller before every send.
func (c *EmailClient) sender() emailpkg.Sender {
	return emailpkg.NewSMTPSender(emailpkg.Config{
		Host:        c.config.SMTPHost,
		Port:        c.config.SMTPPort,
		User:        c.config.Username,
		Password:    c.config.Password,
		From:        c.config.FromEmail,
		FromName:    c.config.FromName,
		ImplicitTLS: c.config.UseTLS,
		TLS:         c.config.UseSTARTTLS && !c.config.UseTLS,
		SkipVerify:  false,
		// The shared sender allows four dial timeouts per session.
		Timeout:     smtpSessionTimeout / 4,
		ResolveHost: relayResolver,
		Dial:        relayDialer,
	})
}

// buildTextEmail builds the text/plain alternative of the notification.
func (c *EmailClient) buildTextEmail(msg Message) string {
	var b strings.Builder
	if msg.Severity != "" {
		b.WriteString("[" + strings.ToUpper(msg.Severity) + "] ")
	}
	b.WriteString(msg.Title + "\n")
	if msg.Body != "" {
		b.WriteString("\n" + msg.Body + "\n")
	}
	keys := make([]string, 0, len(msg.Fields))
	for k := range msg.Fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) > 0 {
		b.WriteString("\n")
	}
	for _, k := range keys {
		b.WriteString(k + ": " + msg.Fields[k] + "\n")
	}
	if msg.URL != "" {
		b.WriteString("\nView details: " + msg.URL + "\n")
	}
	if msg.FooterText != "" {
		b.WriteString("\n" + msg.FooterText + "\n")
	}
	return b.String()
}

// buildHTMLEmail builds an HTML email from the notification message.
func (c *EmailClient) buildHTMLEmail(msg Message) (string, error) {
	color := msg.Color
	if color == "" {
		color = GetSeverityColor(msg.Severity)
	}

	data := struct {
		Title      string
		Body       string
		Severity   string
		Color      string
		URL        string
		Fields     map[string]string
		FooterText string
		Timestamp  string
		Product    string
		ProductURL string
	}{
		Title:      msg.Title,
		Body:       msg.Body,
		Severity:   strings.ToUpper(msg.Severity),
		Color:      color,
		URL:        msg.URL,
		Fields:     msg.Fields,
		FooterText: msg.FooterText,
		Timestamp:  time.Now().Format("2006-01-02 15:04:05 MST"),
		Product:    c.product,
		ProductURL: c.productURL,
	}

	tmpl, err := template.New("email").Parse(emailHTMLTemplate)
	if err != nil {
		return "", fmt.Errorf("parse template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("execute template: %w", err)
	}

	return buf.String(), nil
}

// emailHTMLTemplate is the HTML template for notification emails.
const emailHTMLTemplate = `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{.Title}}</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 0; background-color: #f5f5f5; }
        .container { max-width: 600px; margin: 20px auto; background: #fff; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .header { background: {{.Color}}; color: #fff; padding: 20px; }
        .header h1 { margin: 0; font-size: 20px; font-weight: 600; }
        .severity-badge { display: inline-block; background: rgba(255,255,255,0.2); padding: 4px 12px; border-radius: 4px; font-size: 12px; font-weight: 600; margin-bottom: 10px; }
        .content { padding: 20px; }
        .body { margin-bottom: 20px; white-space: pre-wrap; }
        .fields { background: #f8f9fa; border-radius: 6px; padding: 15px; margin: 15px 0; }
        .field { margin-bottom: 10px; }
        .field:last-child { margin-bottom: 0; }
        .field-label { font-weight: 600; color: #666; font-size: 12px; text-transform: uppercase; margin-bottom: 2px; }
        .field-value { color: #333; }
        .button { display: inline-block; background: {{.Color}}; color: #fff; padding: 12px 24px; border-radius: 6px; text-decoration: none; font-weight: 500; margin: 15px 0; }
        .button:hover { opacity: 0.9; }
        .footer { background: #f8f9fa; padding: 15px 20px; font-size: 12px; color: #666; border-top: 1px solid #eee; }
        .footer a { color: {{.Color}}; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            {{if .Severity}}<div class="severity-badge">{{.Severity}}</div>{{end}}
            <h1>{{.Title}}</h1>
        </div>
        <div class="content">
            {{if .Body}}<div class="body">{{.Body}}</div>{{end}}
            {{if .Fields}}
            <div class="fields">
                {{range $key, $value := .Fields}}
                <div class="field">
                    <div class="field-label">{{$key}}</div>
                    <div class="field-value">{{$value}}</div>
                </div>
                {{end}}
            </div>
            {{end}}
            {{if .URL}}<a href="{{.URL}}" class="button">View Details</a>{{end}}
        </div>
        <div class="footer">
            {{if .FooterText}}{{.FooterText}}<br>{{end}}
            Sent by {{if .ProductURL}}<a href="{{.ProductURL}}">{{.Product}}</a>{{else}}{{.Product}}{{end}} at {{.Timestamp}}
        </div>
    </div>
</body>
</html>`
